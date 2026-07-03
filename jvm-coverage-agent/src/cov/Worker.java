package cov;

import java.io.DataInputStream;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import fixture.Target;

/**
 * Persistent JVM worker — a warmed, agent-instrumented server. It loops over a small binary control
 * protocol on stdio so the same JVM serves many inputs without restart. The protocol matches the
 * Rust driver (little-endian, length-prefixed replies); the coverage map is delivered out of band
 * through the {@code $COV_MAP_PATH} memory-mapped file, so a reply carries only metadata:
 *
 * <pre>
 *   request  : 'R' u32le(len) bytes[len]           run one input
 *            | 'S'                                  status
 *            | 'Q'                                  quit
 *   reply    : u32le(len) body[len]                every non-quit reply is length-prefixed
 *     run body    : u8 status, u64le iterationId, u32le nonzeroEdges, u32le nClasses, u32le[] ids
 *     status body : u64le usedHeap, u32le threads, u64le openFds        (exactly 20 bytes)
 * </pre>
 *
 * Run status: 0 = OkSnapshot (clean), 5 = FatalJvmError (uncaught Throwable). A hang never replies;
 * the driver enforces the timeout by killing this process and starting a new epoch. Each run resets
 * the map first and dumps it to {@code $COV_MAP_PATH}, so the driver's copied map is attributable to
 * that input.
 */
public final class Worker {
    private static final int STATUS_OK_SNAPSHOT = 0;
    private static final int STATUS_FATAL_JVM_ERROR = 5;

    private Worker() {}

    public static void main(String[] args) throws Exception {
        DataInputStream in = new DataInputStream(new FileInputStream(FileDescriptor.in));
        OutputStream out = new FileOutputStream(FileDescriptor.out);
        long iterationId = 0;
        while (true) {
            int op = in.read();
            if (op < 0 || op == 'Q') {
                break;
            }
            switch (op) {
                case 'R' -> {
                    int len = readU32Le(in);
                    byte[] payload = in.readNBytes(len);
                    iterationId++;
                    Cov.reset();
                    int status;
                    try {
                        Target.run(payload); // may hang (0xFF) -> no reply; driver times out
                        status = STATUS_OK_SNAPSHOT;
                    } catch (Throwable t) {
                        status = STATUS_FATAL_JVM_ERROR;
                    }
                    Cov.dump(); // publish the map at $COV_MAP_PATH for the driver to copy out
                    ByteBuffer body = ByteBuffer.allocate(17).order(ByteOrder.LITTLE_ENDIAN);
                    body.put((byte) status);
                    body.putLong(iterationId);
                    body.putInt(Cov.nonZeroEdges());
                    body.putInt(0); // covered-class ids travel via $COV_CLASSES_PATH, not the reply
                    writeFrame(out, body.array());
                }
                case 'S' -> {
                    System.gc();
                    long usedHeap = Runtime.getRuntime().totalMemory()
                            - Runtime.getRuntime().freeMemory();
                    int threads = ManagementFactory.getThreadMXBean().getThreadCount();
                    ByteBuffer body = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
                    body.putLong(usedHeap);
                    body.putInt(threads);
                    body.putLong(openFileDescriptors());
                    writeFrame(out, body.array());
                }
                default -> {
                    // ignore unknown opcodes
                }
            }
        }
    }

    private static int readU32Le(DataInputStream in) throws IOException {
        byte[] b = new byte[4];
        in.readFully(b);
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static void writeFrame(OutputStream out, byte[] body) throws IOException {
        byte[] len =
                ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(body.length).array();
        out.write(len);
        out.write(body);
        out.flush();
    }

    private static long openFileDescriptors() {
        java.lang.management.OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
        if (os instanceof com.sun.management.UnixOperatingSystemMXBean unix) {
            return unix.getOpenFileDescriptorCount();
        }
        try (Stream<Path> fds = Files.list(Path.of("/proc/self/fd"))) {
            return fds.count();
        } catch (IOException e) {
            return -1;
        }
    }
}
