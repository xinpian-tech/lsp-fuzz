package cov;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Runtime coverage map for the ASM instrumentation agent. AFL-shaped: a fixed-size table of 8-bit
 * saturating counters indexed by an edge hash {@code (prev ^ cur)}. See docs/jvm-coverage-agent.md.
 *
 * <p>This first-slice fixture writes the map to {@code $COV_MAP_PATH} on JVM shutdown; the eventual
 * executor (task7/8) will instead read it from a shared mmap segment per iteration.
 */
public final class Cov {
    public static final int MAP_SIZE = 1 << 16;
    public static final byte[] MAP = new byte[MAP_SIZE];
    private static int prev = 0;

    private Cov() {}

    /** Record a transition into block {@code id}. Racy by design, exactly like AFL. */
    public static void hit(int id) {
        int edge = (prev ^ id) & (MAP_SIZE - 1);
        MAP[edge] = (byte) (MAP[edge] + 1);
        prev = id >>> 1;
    }

    public static void reset() {
        Arrays.fill(MAP, (byte) 0);
        prev = 0;
    }

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
