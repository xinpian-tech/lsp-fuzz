package cov;

/**
 * Thrown when an input's run budget ({@code COV_RUN_TIMEOUT_MS}) is exhausted before its message
 * sequence completes. This is an ordinary run timeout — a non-attributable, restart-required outcome
 * — NOT a JVM crash, so the worker maps it to the timeout status rather than the fatal one.
 */
public final class RunBudgetExceededException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public RunBudgetExceededException(String message) {
        super(message);
    }
}
