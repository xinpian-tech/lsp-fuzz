package fixture;

/**
 * Trivial input-branching fixture for the coverage agent: different-length inputs deterministically
 * take different paths, so their coverage maps differ; identical inputs produce identical maps.
 *
 * <p>Package is {@code fixture} (not {@code target}) to avoid the repo's `target/` gitignore rule.
 */
public final class Target {
    private Target() {}

    public static void main(String[] args) throws Exception {
        byte[] input = System.in.readAllBytes();
        switch (Math.floorMod(input.length, 3)) {
            case 0 -> pathA(input.length);
            case 1 -> pathB(input.length);
            default -> pathC(input.length);
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
