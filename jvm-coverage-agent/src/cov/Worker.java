package cov;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import fixture.Target;

/**
 * Persistent JVM worker — a warmed, agent-instrumented server. It loops over a tiny binary control
 * protocol on stdio so the same JVM serves many inputs without restart (the Rust-side executor
 * connects to this protocol):
 *
 * <pre>
 *   request  : 'R' u32be(len) bytes[len]        run one input
 *            | 'S'                               status
 *            | 'Q'                               quit
 *   response : (run)    u8 outcome  bytes[MAP_SIZE]        outcome + coverage snapshot
 *            : (status) u64 usedHeap u32 threads u64 fds   bounded-resource snapshot
 * </pre>
 *
 * outcome: 0 = OK, 1 = CRASH (uncaught Throwable). A hang never responds; the driver enforces the
 * timeout by killing this process and starting a new epoch. Each run resets the map first, so the
 * returned coverage is attributable to that input.
 */
public final class Worker {
    private static final int OK = 0;
    private static final int CRASH = 1;

    private Worker() {}

    public static void main(String[] args) throws Exception {
        DataInputStream in = new DataInputStream(new FileInputStream(FileDescriptor.in));
        DataOutputStream out = new DataOutputStream(new FileOutputStream(FileDescriptor.out));
        while (true) {
            int op = in.read();
            if (op < 0 || op == 'Q') {
                break;
            }
            switch (op) {
                case 'R' -> {
                    int len = in.readInt();
                    byte[] payload = in.readNBytes(len);
                    Cov.reset();
                    int outcome;
                    try {
                        Target.run(payload); // may hang (0xFF) -> no response; driver times out
                        outcome = OK;
                    } catch (Throwable t) {
                        outcome = CRASH;
                    }
                    Cov.dump(); // cold-replay provenance
                    out.write(outcome);
                    out.write(Cov.MAP);
                    out.flush();
                }
                case 'S' -> {
                    System.gc();
                    long usedHeap = Runtime.getRuntime().totalMemory()
                            - Runtime.getRuntime().freeMemory();
                    int threads = ManagementFactory.getThreadMXBean().getThreadCount();
                    out.writeLong(usedHeap);
                    out.writeInt(threads);
                    out.writeLong(openFileDescriptors());
                    out.flush();
                }
                default -> {
                    // ignore unknown opcodes
                }
            }
        }
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
