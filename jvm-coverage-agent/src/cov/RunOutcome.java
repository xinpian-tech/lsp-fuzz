package cov;

/**
 * The result of driving one input through the coverage lifecycle: the lifecycle {@code status} (for
 * attribution/restart) plus the fine-grained {@link Evidence} tag and a short normalized message
 * (for the oracle). The worker serializes all three into the run reply.
 */
public final class RunOutcome {
    final int status;
    final int evidence;
    final String message;

    RunOutcome(int status, int evidence, String message) {
        this.status = status;
        this.evidence = evidence;
        this.message = message == null ? "" : message;
    }

    /** A run outcome with only a lifecycle status and no extra evidence. */
    static RunOutcome of(int status) {
        return new RunOutcome(status, Evidence.NONE, "");
    }
}
