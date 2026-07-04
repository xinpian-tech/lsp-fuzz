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
 * <p>Each run is driven through the per-iteration coverage lifecycle
 * (docs/jvm-coverage-lifecycle.md): {@code reset(generation) → run → quiesce → snapshot →
 * late-watch → detect-late}. The run status is the structured lifecycle outcome the Rust driver
 * decodes: {@code 0 OkSnapshot}, {@code 2 TimeoutQuiescence}, {@code 3 LateCoverage}, {@code 4
 * SnapshotRace}, {@code 5 FatalJvmError}. A hang never replies; the driver enforces the run timeout
 * by killing this process and starting a new epoch. Only {@code OkSnapshot} coverage is attributable
 * — the driver discards the map for every other status.
 */
public final class Worker {
    private static final int STATUS_OK_SNAPSHOT = 0;
    private static final int STATUS_TIMEOUT_RUN = 1;
    private static final int STATUS_TIMEOUT_QUIESCENCE = 2;
    private static final int STATUS_LATE_COVERAGE = 3;
    private static final int STATUS_SNAPSHOT_RACE = 4;
    private static final int STATUS_FATAL_JVM_ERROR = 5;

    // Lifecycle windows (docs/jvm-coverage-lifecycle.md §4). Env-tunable so tests can pick sharp
    // values; the defaults match the spec's presentation-compiler numbers.
    private static final long SETTLE_MS = envMillis("COV_SETTLE_MS", 50);
    private static final long QUIESCE_DEADLINE_MS = envMillis("COV_QUIESCE_DEADLINE_MS", 1000);
    private static final long LATE_WATCH_MS = envMillis("COV_LATE_WATCH_MS", 50);

    private Worker() {}

    public static void main(String[] args) throws Exception {
        DataInputStream in = new DataInputStream(new FileInputStream(FileDescriptor.in));
        OutputStream out = new FileOutputStream(FileDescriptor.out);
        IterationBody body = selectBody();
        long iterationId = 0;
        // Cross-iteration attribution guard: the write count and generation of the last accepted
        // snapshot, so a late write landing after acceptance but before the next reset is caught.
        long acceptedGeneration = -1;
        long acceptedWrites = -1;
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
                    int status;
                    if (acceptedGeneration >= 0
                            && (Cov.hadLateWrite(acceptedGeneration)
                                    || Cov.writes() != acceptedWrites)) {
                        // A background thread from the previous input wrote after we accepted its
                        // snapshot. Refuse to run this input on a contaminated epoch; the driver
                        // discards and restarts (docs §6.4).
                        status = STATUS_LATE_COVERAGE;
                    } else {
                        status = runIteration(body, payload, iterationId);
                        if (status == STATUS_OK_SNAPSHOT) {
                            acceptedGeneration = iterationId;
                            acceptedWrites = Cov.writes();
                        } else {
                            acceptedGeneration = -1;
                            acceptedWrites = -1;
                        }
                    }
                    ByteBuffer replyBody = ByteBuffer.allocate(17).order(ByteOrder.LITTLE_ENDIAN);
                    replyBody.put((byte) status);
                    replyBody.putLong(iterationId);
                    replyBody.putInt(Cov.nonZeroEdges());
                    replyBody.putInt(0); // covered-class ids travel via $COV_CLASSES_PATH
                    writeFrame(out, replyBody.array());
                }
                case 'S' -> {
                    System.gc();
                    long usedHeap = Runtime.getRuntime().totalMemory()
                            - Runtime.getRuntime().freeMemory();
                    int threads = ManagementFactory.getThreadMXBean().getThreadCount();
                    ByteBuffer body2 = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
                    body2.putLong(usedHeap);
                    body2.putInt(threads);
                    body2.putLong(openFileDescriptors());
                    writeFrame(out, body2.array());
                }
                default -> {
                    // ignore unknown opcodes
                }
            }
        }
    }

    /**
     * Select the per-iteration body. {@code COV_ITERATION_BODY=ls} embeds the real in-process
     * language server; anything else uses the planted fixture (the default).
     */
    private static IterationBody selectBody() {
        String kind = System.getenv("COV_ITERATION_BODY");
        if ("ls".equalsIgnoreCase(kind)) {
            return new LsIterationBody();
        }
        return new FixtureBody();
    }

    /** Drive one input through reset → run → quiesce → snapshot → late-watch and classify it. */
    private static int runIteration(IterationBody body, byte[] payload, long generation) {
        Lifecycle.reset();
        Cov.reset(generation);
        try {
            body.run(payload); // may hang (0xFF) -> no reply; may throw
        } catch (RunBudgetExceededException t) {
            // An ordinary run timeout: non-attributable + restart, but NOT a crash objective.
            Cov.dump();
            return STATUS_TIMEOUT_RUN;
        } catch (Throwable t) {
            Cov.dump();
            return STATUS_FATAL_JVM_ERROR;
        }
        if (!quiesce()) {
            Cov.dump();
            return STATUS_TIMEOUT_QUIESCENCE;
        }
        // Snapshot with double validation: the map must not change while the driver copies it.
        long writesBefore = Cov.writes();
        long digestBefore = Cov.digest();
        body.onSnapshotBegin();
        Cov.dump(); // publish the map at $COV_MAP_PATH for the driver to copy out
        long digestAfter = Cov.digest();
        long writesAfter = Cov.writes();
        if (Cov.currentGeneration() != generation
                || digestBefore != digestAfter
                || writesBefore != writesAfter) {
            return STATUS_SNAPSHOT_RACE;
        }
        // Late-watch: any write under this generation after the snapshot closes taints the epoch.
        Cov.markSnapshotClosed(generation);
        body.onLateWatchBegin();
        sleepQuiet(LATE_WATCH_MS);
        if (Cov.hadLateWrite(generation)) {
            return STATUS_LATE_COVERAGE;
        }
        return STATUS_OK_SNAPSHOT;
    }

    /**
     * Wait until the iteration is quiescent — outstanding async work drained and the edge map
     * stable for the settle window — or the deadline expires. Returns {@code false} on timeout.
     */
    private static boolean quiesce() {
        long deadline = System.nanoTime() + QUIESCE_DEADLINE_MS * 1_000_000L;
        while (Lifecycle.outstanding() > 0) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            sleepQuiet(2);
        }
        long settleNanos = SETTLE_MS * 1_000_000L;
        while (true) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            long digestBefore = Cov.digest();
            sleepQuiet(SETTLE_MS);
            boolean idle = Lifecycle.outstanding() == 0
                    && Cov.digest() == digestBefore
                    && (System.nanoTime() - Cov.lastWriteNanos()) >= settleNanos;
            if (idle) {
                return true;
            }
        }
    }

    private static void sleepQuiet(long millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static long envMillis(String name, long fallback) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return fallback;
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
