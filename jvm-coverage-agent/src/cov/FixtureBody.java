package cov;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import fixture.LateWriteFixture;
import fixture.Target;

/**
 * Default per-iteration body: exercises the planted lifecycle paths from
 * docs/jvm-coverage-lifecycle.md §10 so the worker's attribution can be validated without the real
 * language server. Control flow and thread scheduling live here in the uninstrumented {@code cov}
 * package; the only instrumented coverage write a planted mode makes is the explicit call to {@link
 * LateWriteFixture#coverageEdge()}, so a mode injects coverage at exactly one lifecycle phase.
 *
 * <p>The first payload byte selects the mode; anything else (including the crash/hang bytes handled
 * by {@link Target}) runs as an ordinary input.
 */
public final class FixtureBody implements IterationBody {
    private static final int MODE_QUIESCE_WAIT = 0xE0;
    private static final int MODE_QUIESCE_TIMEOUT = 0xE1;
    private static final int MODE_LATE_AFTER_SNAPSHOT = 0xE2;
    private static final int MODE_SNAPSHOT_RACE = 0xE3;
    private static final int MODE_POST_RESET_STALE = 0xE4;
    private static final int MODE_RELEASE_STALE = 0xE5;
    private static final int MODE_RUN_BUDGET_TIMEOUT = 0xE6;
    // Planted outcome-oracle classes: each maps to a specific Evidence tag or thrown error.
    private static final int MODE_OUT_OF_MEMORY = 0xE7;
    private static final int MODE_STACK_OVERFLOW = 0xE8;
    private static final int MODE_FOREGROUND_EXCEPTION = 0xE9;
    private static final int MODE_BACKGROUND_EXCEPTION = 0xEA;
    private static final int MODE_LOGGED_FATAL = 0xEB;
    private static final int MODE_JSON_RPC_ERROR = 0xEC;
    private static final int MODE_EXPECTED_CANCELLATION = 0xED;
    // 0xEE and 0xFF are reserved by Target (crash / hang); use 0xEF for the planted hard JVM fatal.
    private static final int MODE_JVM_FATAL = 0xEF;

    private static final long BACKGROUND_DELAY_MS = 30;
    private static final long NEVER_COMPLETES_MS = 60_000;
    private static final long COORDINATION_TIMEOUT_MS = 5_000;

    // Per-iteration coordination, reset at the start of every run().
    private int activeMode;
    private CountDownLatch snapshotRelease;
    private CountDownLatch snapshotDone;
    private CountDownLatch lateRelease;
    private CountDownLatch lateDone;
    // A background thread scheduled under a prior generation, released by a later input to prove a
    // post-reset stale write is suppressed rather than attributed to the current input.
    private Thread pendingStale;
    private CountDownLatch staleGate;
    // Fine-grained evidence a clean-snapshot mode reports to the worker (defaults to normal success).
    private int evidenceTag = Evidence.NORMAL_SUCCESS;
    private String evidenceMessage = "";
    private final Findings findings = new Findings();

    @Override
    public void run(byte[] payload) {
        snapshotRelease = new CountDownLatch(1);
        snapshotDone = new CountDownLatch(1);
        lateRelease = new CountDownLatch(1);
        lateDone = new CountDownLatch(1);
        evidenceTag = Evidence.NORMAL_SUCCESS;
        evidenceMessage = "";
        findings.reset();
        int mode = payload.length > 0 ? (payload[0] & 0xff) : -1;
        activeMode = mode;
        // The generation this input runs under; background work captures it so a write that lands
        // after a later reset is recognised as stale.
        long generation = Cov.currentGeneration();
        switch (mode) {
            case MODE_QUIESCE_WAIT -> {
                // A tracked async task that writes coverage before it completes. Quiescence must
                // wait for it, so the late edge lands inside the attributed snapshot.
                Lifecycle.trackFuture();
                daemon(() -> {
                    sleepQuiet(BACKGROUND_DELAY_MS);
                    Lifecycle.runInGeneration(generation, LateWriteFixture::coverageEdge);
                    Lifecycle.completeFuture();
                });
            }
            case MODE_QUIESCE_TIMEOUT -> {
                // A tracked async task that never completes within the quiescence deadline.
                Lifecycle.trackFuture();
                daemon(() -> sleepQuiet(NEVER_COMPLETES_MS));
            }
            case MODE_LATE_AFTER_SNAPSHOT -> {
                // Untracked task that writes coverage only once the snapshot has been accepted and
                // the late-watch window opens — a late write that must taint the epoch.
                daemon(() -> {
                    awaitQuiet(lateRelease);
                    Lifecycle.runInGeneration(generation, LateWriteFixture::coverageEdge);
                    lateDone.countDown();
                });
            }
            case MODE_SNAPSHOT_RACE -> {
                // Untracked task that writes coverage in the middle of the snapshot copy, so the
                // before/after digests differ.
                daemon(() -> {
                    awaitQuiet(snapshotRelease);
                    Lifecycle.runInGeneration(generation, LateWriteFixture::coverageEdge);
                    snapshotDone.countDown();
                });
            }
            case MODE_POST_RESET_STALE -> {
                // Schedule a background thread that captures THIS generation but parks until a later
                // input releases it — by then the map has been reset for that later generation.
                staleGate = new CountDownLatch(1);
                CountDownLatch gate = staleGate;
                pendingStale = daemon(() -> {
                    awaitQuiet(gate);
                    Lifecycle.runInGeneration(generation, LateWriteFixture::coverageEdge);
                });
            }
            case MODE_RELEASE_STALE -> {
                // Release the previously parked stale thread now that we are a fresh generation; its
                // write must be suppressed (captured generation != active), not attributed here.
                if (staleGate != null) {
                    staleGate.countDown();
                    joinQuiet(pendingStale);
                    pendingStale = null;
                    staleGate = null;
                }
            }
            case MODE_RUN_BUDGET_TIMEOUT ->
                // Planted run-budget timeout: the worker must class this as TimeoutRun, not a crash.
                throw new RunBudgetExceededException("planted run-budget timeout");
            case MODE_OUT_OF_MEMORY ->
                // Planted OOM: thrown (not actually allocated) so the worker classes it distinctly.
                throw new OutOfMemoryError("planted out-of-memory");
            case MODE_STACK_OVERFLOW -> throw new StackOverflowError("planted stack overflow");
            case MODE_FOREGROUND_EXCEPTION ->
                throw new RuntimeException("planted foreground exception");
            case MODE_BACKGROUND_EXCEPTION -> {
                // A background thread failed but the foreground run completed cleanly: an OkSnapshot
                // carrying background-exception evidence.
                evidenceTag = Evidence.BACKGROUND_EXCEPTION;
                evidenceMessage = "planted background exception";
            }
            case MODE_LOGGED_FATAL -> {
                // The server logged a fatal-level event without crashing.
                evidenceTag = Evidence.LOGGED_FATAL;
                evidenceMessage = "planted logged fatal";
            }
            case MODE_JSON_RPC_ERROR -> {
                // A request returned a JSON-RPC error response: an OkSnapshot that is a finding.
                evidenceTag = Evidence.JSON_RPC_ERROR;
                evidenceMessage = "textDocument/hover";
                findings.recordJsonRpcError("textDocument/hover", -32603, "planted internal error");
            }
            case MODE_EXPECTED_CANCELLATION -> {
                // A request was cancelled as expected: not a finding.
                evidenceTag = Evidence.EXPECTED_CANCELLATION;
                evidenceMessage = "textDocument/hover";
            }
            case MODE_JVM_FATAL -> {
                // A hard JVM fatal the worker can still observe: flag the class, then throw so the
                // worker classes it FatalJvmError with JVM-fatal evidence (a true SIGSEGV would give
                // no reply and the driver would time out instead).
                evidenceTag = Evidence.JVM_FATAL;
                evidenceMessage = "planted jvm fatal";
                throw new Error("planted jvm fatal");
            }
            default -> Target.run(payload);
        }
        // A clean (non-throwing) run publishes its findings — empty for every mode except the planted
        // JSON-RPC error — so a later read reflects exactly this input (no stale finding lingers).
        findings.publish();
    }

    @Override
    public int evidenceTag() {
        return evidenceTag;
    }

    @Override
    public String evidenceMessage() {
        return evidenceMessage;
    }

    @Override
    public void onSnapshotBegin() {
        // Release the snapshot racer and block until its single write lands, so the write is
        // guaranteed to fall between the worker's before/after digests.
        if (activeMode == MODE_SNAPSHOT_RACE) {
            snapshotRelease.countDown();
            awaitQuiet(snapshotDone);
        }
    }

    @Override
    public void onLateWatchBegin() {
        // Release the late writer and block until it writes, so the late write is recorded before
        // the worker checks for it.
        if (activeMode == MODE_LATE_AFTER_SNAPSHOT) {
            lateRelease.countDown();
            awaitQuiet(lateDone);
        }
    }

    private static Thread daemon(Runnable task) {
        Thread t = new Thread(task, "lsp-fuzz-fixture");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void joinQuiet(Thread t) {
        if (t == null) {
            return;
        }
        try {
            t.join(COORDINATION_TIMEOUT_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void awaitQuiet(CountDownLatch latch) {
        try {
            latch.await(COORDINATION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleepQuiet(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
