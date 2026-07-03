package cov;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Runtime coverage map for the ASM instrumentation agent. AFL-shaped: a fixed-size table of 8-bit
 * saturating counters indexed by an edge hash {@code (prev ^ cur)}. See docs/jvm-coverage-agent.md.
 */
public final class Cov {
    public static final int MAP_SIZE = 1 << 16;
    public static final byte[] MAP = new byte[MAP_SIZE];
    private static int prev = 0;

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

    public static void reset() {
        Arrays.fill(MAP, (byte) 0);
        prev = 0;
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

    /** Dump the current map to {@code $COV_MAP_PATH} (cold-replay provenance). */
    public static void dump() {
        String path = System.getenv("COV_MAP_PATH");
        if (path == null) {
            return;
        }
        try {
            Files.write(Path.of(path), MAP);
        } catch (IOException e) {
            throw new RuntimeException("failed to write coverage map", e);
        }
    }
}
