package fixture;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * Planted executor-submission target for the fail-closed generation-scoping gate. This class lives in
 * the instrumented {@code fixture} package, so the agent rewrites its {@link ExecutorService#submit}
 * call site to route the task through {@code cov.Cov.capturingRunnable} — exactly the wrapping the
 * agent applies at a real language-server executor boundary. The submitted task parks on {@code gate}
 * and only records {@link LateWriteFixture#coverageEdge()} once released; the harness releases it after
 * a later input has reset the coverage map, so a correct wrapping suppresses the write (the captured
 * generation no longer matches the active one) instead of attributing it to the later input.
 *
 * <p>Unlike the {@code Lifecycle.runInGeneration}-wrapped planted modes, the task here is a plain
 * unwrapped {@link Runnable}: the ONLY thing that captures its generation is the agent's rewrite of the
 * {@code submit} call site. With the rewrite disabled the write leaks into the later input's map, so
 * this reproduces the real detached-executor residual and proves the fix.
 */
public final class ExecutorLateWrite {
    private ExecutorLateWrite() {}

    /** Submit a parked writer to {@code exec}; the agent rewrites this {@code submit} to capture gen. */
    public static Future<?> schedule(ExecutorService exec, CountDownLatch gate) {
        return exec.submit(() -> {
            try {
                gate.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            LateWriteFixture.coverageEdge();
        });
    }
}
