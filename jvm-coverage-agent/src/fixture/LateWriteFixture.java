package fixture;

import cov.Cov;

/**
 * Planted background-write target for the coverage lifecycle tests. The lifecycle fixture calls
 * {@link #coverageEdge()} from background threads at controlled phases (during quiescence, after the
 * snapshot, or mid-snapshot) so the worker's attribution and late-write detection can be exercised
 * deterministically.
 *
 * <p>This class lives in the instrumented {@code fixture} package, so under the ASM agent the method
 * body also carries real probes. It additionally records one fixed synthetic edge directly, so the
 * planted write is observable even when the harness runs the worker without the agent (as the Rust
 * lifecycle integration test does) — exactly what an injected instrumentation probe would do.
 */
public final class LateWriteFixture {
    /** A fixed synthetic edge id for the planted late/background write. */
    public static final int LATE_EDGE_ID = 0xBEEF;

    private LateWriteFixture() {}

    /** Record the planted coverage edge (agent-independent, plus real probes under instrumentation). */
    public static void coverageEdge() {
        Cov.hit(LATE_EDGE_ID);
    }
}
