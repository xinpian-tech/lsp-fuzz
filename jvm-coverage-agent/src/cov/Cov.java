package cov;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runtime coverage map for the ASM instrumentation agent. AFL-shaped: a fixed-size table of 8-bit
 * saturating counters indexed by an edge hash {@code (prev ^ cur)}. See docs/jvm-coverage-agent.md.
 *
 * <p>Also tracks which instrumented classes actually executed, so a harness can confirm coverage
 * reached specific packages (e.g. the presentation compiler) rather than only transport code.
 */
public final class Cov {
    public static final int MAP_SIZE = 1 << 16;
    public static final byte[] MAP = new byte[MAP_SIZE];
    private static int prev = 0;

    // classId -> class name (registered at instrumentation time) and the set of class ids that
    // have executed at least one probe. Concurrent because background compiler threads hit them.
    private static final Map<Integer, String> CLASS_NAMES = new ConcurrentHashMap<>();
    private static final Set<Integer> COVERED_CLASSES = ConcurrentHashMap.newKeySet();

    // Per-iteration attribution state (see docs/jvm-coverage-lifecycle.md). Coverage belongs to one
    // input only if the map was zeroed under a fresh generation, the run reached quiescence, the map
    // did not change during the snapshot, and no write landed after the snapshot closed.
    private static volatile long activeGeneration = 0;
    private static final AtomicLong TOTAL_WRITES = new AtomicLong();
    private static final AtomicLong LAST_WRITE_NANOS = new AtomicLong();
    // Once a snapshot is closed for a generation, any further write under that same generation is a
    // late write; recorded here so the worker can taint the epoch before the next reset.
    private static volatile long snapshotClosedGeneration = -1;
    private static volatile long lateWriteGeneration = -1;

    private Cov() {}

    /**
     * Record a transition into block {@code id}. Racy by design, exactly like AFL. Counters
     * <b>saturate</b> at 0xff — a hot edge must never wrap back to 0 (that would drop coverage and
     * corrupt the identical-input stability gate). Also advances the per-iteration write bookkeeping
     * used for quiescence, snapshot validation, and late-write detection.
     */
    public static void hit(int id) {
        int edge = (prev ^ id) & (MAP_SIZE - 1);
        int value = MAP[edge] & 0xff;
        if (value != 0xff) {
            MAP[edge] = (byte) (value + 1);
        }
        prev = id >>> 1;
        TOTAL_WRITES.incrementAndGet();
        LAST_WRITE_NANOS.set(System.nanoTime());
        if (snapshotClosedGeneration == activeGeneration) {
            lateWriteGeneration = activeGeneration;
        }
    }

    /** Mark that instrumented class {@code classId} executed (one probe per class per method). */
    public static void cls(int classId) {
        COVERED_CLASSES.add(classId);
    }

    /** Called by the agent at instrumentation time to map ids back to class names. */
    public static void registerClass(int classId, String name) {
        CLASS_NAMES.put(classId, name);
    }

    /** Zero all per-iteration state under a stable generation (used by the standalone agent gates). */
    public static void reset() {
        reset(activeGeneration);
    }

    /**
     * Begin a new iteration: zero the edge map, previous-edge state, and covered-class set, install
     * a fresh {@code generation}, and clear the write bookkeeping so this input starts from nothing.
     */
    public static void reset(long generation) {
        Arrays.fill(MAP, (byte) 0);
        prev = 0;
        COVERED_CLASSES.clear();
        activeGeneration = generation;
        snapshotClosedGeneration = -1;
        lateWriteGeneration = -1;
        TOTAL_WRITES.set(0);
        LAST_WRITE_NANOS.set(System.nanoTime());
    }

    /** The generation installed by the most recent {@link #reset(long)}. */
    public static long currentGeneration() {
        return activeGeneration;
    }

    /** Total instrumentation writes since the last reset (monotonic within a generation). */
    public static long writes() {
        return TOTAL_WRITES.get();
    }

    /** Wall-clock nanos of the most recent instrumentation write (or reset). */
    public static long lastWriteNanos() {
        return LAST_WRITE_NANOS.get();
    }

    /** Order-independent digest of the edge map, for detecting mid-snapshot mutation. */
    public static long digest() {
        long h = 1125899906842597L; // FNV-ish seed
        for (byte b : MAP) {
            h = 31 * h + (b & 0xff);
        }
        return h;
    }

    /**
     * Close attribution for {@code generation}: after this, any write under the same generation is a
     * late write and flips {@link #hadLateWrite(long)}.
     */
    public static void markSnapshotClosed(long generation) {
        snapshotClosedGeneration = generation;
    }

    /** Whether a late write landed under {@code generation} after its snapshot was closed. */
    public static boolean hadLateWrite(long generation) {
        return lateWriteGeneration == generation;
    }

    /** Number of edges with a non-zero counter (for bounded-fill / collision diagnostics). */
    public static int nonZeroEdges() {
        int n = 0;
        for (byte b : MAP) {
            if (b != 0) {
                n++;
            }
        }
        return n;
    }

    /** Sorted names of instrumented classes that executed at least one probe. */
    public static List<String> coveredClassNames() {
        List<String> names = new ArrayList<>();
        for (int id : COVERED_CLASSES) {
            String name = CLASS_NAMES.get(id);
            if (name != null) {
                names.add(name);
            }
        }
        names.sort(null);
        return names;
    }

    /** Dump the current map to {@code $COV_MAP_PATH} and covered class names to {@code $COV_CLASSES_PATH}. */
    public static void dump() {
        writeIfSet("COV_MAP_PATH", MAP);
        String classesPath = System.getenv("COV_CLASSES_PATH");
        if (classesPath != null) {
            try {
                Files.write(Path.of(classesPath), coveredClassNames());
            } catch (IOException e) {
                throw new RuntimeException("failed to write covered classes", e);
            }
        }
    }

    private static void writeIfSet(String env, byte[] bytes) {
        String path = System.getenv(env);
        if (path == null) {
            return;
        }
        try {
            Files.write(Path.of(path), bytes);
        } catch (IOException e) {
            throw new RuntimeException("failed to write " + env, e);
        }
    }
}
