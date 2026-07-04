package cov;

/**
 * Fine-grained outcome evidence tags, mirrored by the Rust {@code OutcomeEvidence} enum. The worker's
 * lifecycle status governs coverage attribution and epoch restart; this evidence names <em>what
 * happened</em> for the oracle, so a single fatal status can resolve to a specific class (OOM vs
 * stack overflow vs an uncaught exception) and a clean snapshot can still carry a JSON-RPC error or a
 * cancellation. The integer values are the wire tags and MUST stay in sync with the Rust side.
 */
public final class Evidence {
    public static final int NONE = 0;
    public static final int NORMAL_SUCCESS = 1;
    public static final int JSON_RPC_ERROR = 2;
    public static final int EXPECTED_CANCELLATION = 3;
    public static final int FOREGROUND_EXCEPTION = 4;
    public static final int BACKGROUND_EXCEPTION = 5;
    public static final int LOGGED_FATAL = 6;
    public static final int JVM_FATAL = 7;
    public static final int OUT_OF_MEMORY = 8;
    public static final int STACK_OVERFLOW = 9;
    public static final int TIMEOUT_OR_DEADLOCK = 10;
    public static final int PROTOCOL_DESYNC = 11;

    private Evidence() {}
}
