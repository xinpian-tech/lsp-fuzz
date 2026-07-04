package cov;

/**
 * The per-iteration work the worker drives through the coverage lifecycle. The default fixture body
 * exercises planted paths; the real target plugs in an in-process {@code ls.core.Main} session that
 * applies a localized {@code LspInput} and issues its LSP message sequence. The worker owns the
 * lifecycle (reset → run → quiesce → snapshot → late-watch); the body only performs the logical run
 * and may react to phase transitions (e.g. flush pending work when the snapshot begins).
 */
public interface IterationBody {
    /** Execute the logical input against the server. May throw to signal a fatal run. */
    void run(byte[] payload) throws Throwable;

    /** Called once the run is logically idle and the worker is about to freeze the snapshot. */
    default void onSnapshotBegin() {}

    /** Called after the snapshot is accepted, at the start of the late-write watch window. */
    default void onLateWatchBegin() {}
}
