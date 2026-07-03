package fixture;

/**
 * Trivial fixture exercised by the coverage agent + persistent worker. {@link #run} drives
 * different code paths from the input and has planted outcome cases so the harness can validate
 * classification:
 *
 * <ul>
 *   <li>first byte {@code 0xEE} -> throws (crash / uncaught exception),
 *   <li>first byte {@code 0xFF} -> loops forever (hang / timeout),
 *   <li>otherwise -> branches on input length (distinct lengths take distinct paths).
 * </ul>
 *
 * Package is {@code fixture} (not {@code target}) to avoid the repo's `target/` gitignore rule.
 */
public final class Target {
    private Target() {}

    public static void run(byte[] input) {
        if (input.length > 0) {
            int first = input[0] & 0xff;
            if (first == 0xEE) {
                throw new IllegalStateException("planted crash");
            }
            if (first == 0xFF) {
                hang();
            }
        }
        switch (Math.floorMod(input.length, 3)) {
            case 0 -> pathA(input.length);
            case 1 -> pathB(input.length);
            default -> pathC(input.length);
        }
    }

    @SuppressWarnings("InfiniteLoopStatement")
    private static void hang() {
        while (true) {
            Thread.onSpinWait();
        }
    }

    static void pathA(int n) {
        helper(n);
    }

    static void pathB(int n) {
        if (n > 2) {
            helper(n * 2);
        }
    }

    static void pathC(int n) {
        for (int i = 0; i < 2; i++) {
            helper(i);
        }
    }

    static int helper(int x) {
        return x * 2 + 1;
    }
}
