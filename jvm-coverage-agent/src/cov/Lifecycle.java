package cov;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks outstanding asynchronous work so the worker can decide when an iteration is quiescent.
 * Any code that issues a request whose completion produces coverage — an lsp4j {@code
 * CompletableFuture}, a presentation-compiler job, a background index task — registers it here so
 * quiescence waits for it before the snapshot (see docs/jvm-coverage-lifecycle.md §4).
 */
public final class Lifecycle {
    private static final AtomicInteger OUTSTANDING = new AtomicInteger();

    private Lifecycle() {}

    /** Register one in-flight async task. Pair with {@link #completeFuture()}. */
    public static void trackFuture() {
        OUTSTANDING.incrementAndGet();
    }

    /** Mark one previously tracked async task complete (or failed/cancelled). */
    public static void completeFuture() {
        OUTSTANDING.decrementAndGet();
    }

    /** Number of async tasks still in flight. Zero is a precondition for quiescence. */
    public static int outstanding() {
        return OUTSTANDING.get();
    }

    /** Reset the counter at the start of an iteration (drops leaked counts from a tainted epoch). */
    public static void reset() {
        OUTSTANDING.set(0);
    }

    /**
     * Wrap {@code future} so its completion decrements the outstanding count. Returns the same
     * future for chaining. Use for every harness-issued LSP request.
     */
    public static <T> CompletableFuture<T> track(CompletableFuture<T> future) {
        trackFuture();
        future.whenComplete((result, error) -> completeFuture());
        return future;
    }

    /**
     * Run background {@code task} under the generation it was scheduled in. If the task wakes after
     * a later input has reset the map, its coverage writes are suppressed rather than misattributed
     * (docs §6.4). Any background work that can outlive its iteration must go through this.
     */
    public static void runInGeneration(long generation, Runnable task) {
        Cov.enterTaskGeneration(generation);
        try {
            task.run();
        } finally {
            Cov.exitTaskGeneration();
        }
    }
}
