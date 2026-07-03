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

    private Cov() {}

    /**
     * Record a transition into block {@code id}. Racy by design, exactly like AFL. Counters
     * <b>saturate</b> at 0xff — a hot edge must never wrap back to 0 (that would drop coverage and
     * corrupt the identical-input stability gate).
     */
    public static void hit(int id) {
        int edge = (prev ^ id) & (MAP_SIZE - 1);
        int value = MAP[edge] & 0xff;
        if (value != 0xff) {
            MAP[edge] = (byte) (value + 1);
        }
        prev = id >>> 1;
    }

    /** Mark that instrumented class {@code classId} executed (one probe per class per method). */
    public static void cls(int classId) {
        COVERED_CLASSES.add(classId);
    }

    /** Called by the agent at instrumentation time to map ids back to class names. */
    public static void registerClass(int classId, String name) {
        CLASS_NAMES.put(classId, name);
    }

    public static void reset() {
        Arrays.fill(MAP, (byte) 0);
        prev = 0;
        COVERED_CLASSES.clear();
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
