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

    private static final long BACKGROUND_DELAY_MS = 30;
    private static final long NEVER_COMPLETES_MS = 60_000;
    private static final long COORDINATION_TIMEOUT_MS = 5_000;

    // Per-iteration coordination, reset at the start of every run().
    private int activeMode;
    private CountDownLatch snapshotRelease;
    private CountDownLatch snapshotDone;
    private CountDownLatch lateRelease;
    private CountDownLatch lateDone;

    @Override
    public void run(byte[] payload) {
        snapshotRelease = new CountDownLatch(1);
        snapshotDone = new CountDownLatch(1);
        lateRelease = new CountDownLatch(1);
        lateDone = new CountDownLatch(1);
        int mode = payload.length > 0 ? (payload[0] & 0xff) : -1;
        activeMode = mode;
        switch (mode) {
            case MODE_QUIESCE_WAIT -> {
                // A tracked async task that writes coverage before it completes. Quiescence must
                // wait for it, so the late edge lands inside the attributed snapshot.
                Lifecycle.trackFuture();
                daemon(() -> {
                    sleepQuiet(BACKGROUND_DELAY_MS);
                    LateWriteFixture.coverageEdge();
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
                    LateWriteFixture.coverageEdge();
                    lateDone.countDown();
                });
            }
            case MODE_SNAPSHOT_RACE -> {
                // Untracked task that writes coverage in the middle of the snapshot copy, so the
                // before/after digests differ.
                daemon(() -> {
                    awaitQuiet(snapshotRelease);
                    LateWriteFixture.coverageEdge();
                    snapshotDone.countDown();
                });
            }
            default -> Target.run(payload);
        }
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

    private static void daemon(Runnable task) {
        Thread t = new Thread(task, "lsp-fuzz-fixture");
        t.setDaemon(true);
        t.start();
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
