# Per-iteration coverage lifecycle (plan task7 / AC-3.1)

Design spec for how the Option-B JVM worker attributes coverage to a single fuzzer iteration:
`reset → run → quiesce → copy → detect-late`, the restart rules, and the planted late-write tests
that enforce it. This is the contract that **task8** (Rust `Executor`/`Observer`/`Feedback`) and
**task9** (in-process LS harness / worker) implement; no executor code lands with this spec.

> Routing / provenance: task7 is an `analyze` task. This spec was produced via
> `/humanize:ask-codex` (gpt-5.5, high effort) and reconciled against the existing implementation.
> It maps onto the code already in the repo:
>
> - The Java worker/agent it extends is `jvm-coverage-agent/src/cov/` — `cov.Worker` (the `R`/`S`/`Q`
>   control protocol with proven 1000-identical-input stability, timeout-kill + epoch restart,
>   256 KiB transport, cold replay) and `cov.Cov` (the `2^16` 8-bit **saturating** AFL edge map in an
>   mmap file + the covered-class set). The planted-late-write fixture extends the existing
>   `jvm-coverage-agent/src/fixture/` target used by `cov.Harness`.
> - The Régime-2 index path is live-BSP on the frozen zaozi backdrop (see `docs/zaozi-backdrop.md`);
>   the LS must run on its exact pinned JDK (`BL-20260703-ls-needs-its-exact-pinned-jdk`), and the
>   SemanticDB reader it exercises is `ls.semanticdb.*`.
> - The DEC-3 determinism flags (`-XX:-UseCompactObjectHeaders`/`-Xshare:off`) vs the SQLite index
>   path remain the open AC-2/AC-2.1 follow-up; the reach path currently uses production-like flags.

## 1. Purpose

Define the exact lifecycle for attributing JVM bytecode coverage to one `LspInput` when fuzzing `scala3-bsp-smantic-ls` through a persistent JVM worker.

The executor must ensure:

1. Coverage from input `N` is copied only after the language server is logically idle.
2. Late coverage from background JVM threads is detected.
3. Late writes never contaminate input `N+1`.
4. Bad worker epochs are killed and replaced without stopping the LibAFL fuzzing loop.

This applies to both:

- **Regime 1:** presentation compiler only, no BSP.
- **Regime 2:** live BSP/index paths on a frozen `zaozi` backdrop.

---

## 2. State Machine

Per input, the Rust JVM executor drives one worker epoch through these states.

### 2.1 States

1. **`IdleClean`**
   - Worker is alive.
   - No input is currently running.
   - Coverage map is zeroed.
   - Worker generation is stable.
   - LS is either freshly initialized or reset to the selected regime baseline.

2. **`Resetting`**
   - Worker clears coverage state and logical LS iteration state.
   - A new `iteration_id` / generation is installed.

3. **`RunningInput`**
   - Rust sends `R<u32 len><bytes>`.
   - Java worker executes the serialized input against the LS.

4. **`LogicalReturned`**
   - Worker has finished the direct LSP message sequence.
   - Responses for synchronous request paths have returned or failed.
   - Background tasks may still be running.

5. **`Quiescing`**
   - Worker waits until the LS appears idle:
     - outstanding LSP futures == 0
     - tracked background task count == 0 where available
     - coverage map stops changing for the settle window

6. **`Snapshotting`**
   - Worker freezes attribution for this iteration.
   - Rust copies the 64 KiB AFL-style edge map from mmap.
   - Worker also reports covered-class delta for this iteration.

7. **`LateWatch`**
   - Worker keeps watching the map after the snapshot for a short late-write window.
   - Any new write after the snapshot marks the epoch suspicious.

8. **`DoneStable`**
   - Input result is returned to LibAFL.
   - Snapshot is accepted as the coverage for this input.

9. **`RestartRequired`**
   - Worker epoch is tainted.
   - Rust kills/restarts the JVM worker before the next input.

10. **`Dead`**
   - Worker process exited or was killed.
   - Rust launches a new worker epoch.

### 2.2 Transitions

```text
IdleClean
  -> Resetting
  -> RunningInput
  -> LogicalReturned
  -> Quiescing
  -> Snapshotting
  -> LateWatch
  -> DoneStable
  -> IdleClean
```

Failure transitions:

```text
RunningInput timeout/OOM/SOE/worker death -> RestartRequired -> Dead -> IdleClean

Quiescing deadline exceeded -> RestartRequired -> Dead -> IdleClean

Snapshot changed during copy -> RestartRequired -> Dead -> IdleClean

LateWatch sees post-copy write past allowed window -> RestartRequired -> Dead -> IdleClean

Instability detected by Rust feedback -> RestartRequired -> Dead -> IdleClean
```

---

## 3. Reset Semantics

There are two independent reset domains:

1. **Coverage reset**
2. **Language-server logical reset**

They must both happen before every input, but they do different things.

### 3.1 Coverage Reset

For every input, before executing any LSP messages, Java worker must clear:

1. Edge coverage mmap:
   - all `2^16` 8-bit counters set to `0`

2. Previous-edge state:
   - all thread-local or global `prev_loc` values set to `0`
   - any per-thread coverage cache cleared
   - new JVM threads must initialize `prev_loc = 0`

3. Covered-class set:
   - clear the per-input covered-class set
   - retain only global metadata needed by the agent, not the iteration result

4. Coverage generation:
   - increment `coverage_generation`
   - mark the new generation as active
   - reset `late_write_detected = false`
   - reset `last_coverage_write_nanos = now`

The coverage agent must expose at least:

```text
resetCoverage(iteration_id)
snapshotWriteGeneration()
lateWriteDetectedSince(snapshot_generation)
```

### 3.2 LS Logical Reset: Regime 1

Regime 1 targets presentation-compiler paths without BSP.

Per input, reset:

1. Open documents:
   - close all documents opened by the previous input
   - clear dirty buffers
   - reset virtual `lsp-fuzz://` to localized `file://` mapping

2. Workspace files:
   - replace the temporary workspace tree with the new input workspace
   - no real paths should be embedded into the stored corpus

3. Presentation compiler session:
   - clear per-document compiler state where the LS exposes this
   - force source buffers to be reloaded from the current input
   - invalidate diagnostics and semanticdb-like caches tied to previous documents

4. Request tracking:
   - outstanding request/future counter reset to `0`
   - failed/cancelled futures drained

Do not require a full LS process restart between stable Regime 1 inputs unless quiescence or attribution fails.

### 3.3 LS Logical Reset: Regime 2

Regime 2 targets live BSP/index behavior on a frozen `zaozi` backdrop.

Per worker epoch, initialize once:

1. Start LS with exact pinned JDK.
2. Initialize BSP connection.
3. Load frozen `zaozi` workspace.
4. Warm/index baseline until stable.
5. Record baseline quiescent state.

Per input, reset:

1. Input overlay:
   - apply fuzzed files as an overlay over the frozen baseline
   - remove overlay files from the previous input

2. Dirty buffers:
   - close/reopen documents changed by the input
   - clear stale diagnostics/request state

3. Index-facing state:
   - invalidate only input overlay paths
   - preserve frozen backdrop index caches
   - do not rebuild the entire `zaozi` baseline per input

4. BSP activity:
   - keep BSP session alive
   - drain BSP client futures/messages caused by the input
   - reset counters for index/reference/rename/workspace-symbol activity

5. Coverage:
   - still fully reset per input

If BSP/index background activity cannot be bounded to the current input, the worker epoch is tainted and must restart.

---

## 4. Quiescence Detection

Quiescence is detected inside the Java worker, not inferred only by Rust.

The worker may return to Rust only after either:

1. quiescence succeeds, or
2. a deadline/error forces restart.

### 4.1 Required Idle Conditions

The worker considers an iteration quiescent when all are true:

1. **Outstanding LSP futures == 0**
   - every request future submitted by the harness is completed, failed, or cancelled
   - includes lsp4j `CompletableFuture` responses

2. **Tracked background activity == 0**
   - presentation compiler jobs known to the harness are idle
   - BSP client request/response futures are idle
   - index jobs known through hooks/wrappers are idle

3. **No new coverage edges for settle window**
   - edge map digest is unchanged for the full settle window
   - covered-class set size is unchanged for the same window
   - `last_coverage_write_nanos` is older than the settle window

### 4.2 Settle Window

Default:

```text
settle_window = 50 ms
```

For Regime 2, because BSP/index activity is noisier:

```text
settle_window = 100 ms
```

The settle window starts only after outstanding futures and tracked task counters reach zero.

### 4.3 Quiescence Deadline

Default hard deadline per input:

```text
Regime 1: 1 second after logical LSP sequence return
Regime 2: 3 seconds after logical LSP sequence return
```

The deadline is independent of the AFL execution timeout. It is the maximum time spent waiting for background completion after the direct input has returned.

If the deadline expires:

```text
result = TimeoutQuiescence
epoch = tainted
action = kill + restart JVM worker
```

The input is reported to LibAFL as a timeout/crash-class execution result according to existing policy, but its coverage must not be merged.

---

## 5. Snapshot and Attribution

### 5.1 Copy Step

After quiescence succeeds, Java enters `Snapshotting`.

The snapshot protocol is:

1. Java records:

```text
snapshot_generation = coverage_generation
snapshot_write_count = total_coverage_writes
snapshot_digest_before = digest(edge_map)
snapshot_classes_before = covered_class_set_digest
```

2. Java marks the worker as `snapshot_in_progress`.

3. Rust copies exactly `65536` bytes from the mmap edge map into the LibAFL observer-owned buffer.

4. Rust asks Java for post-copy status, or Java includes post-copy validation in the run response.

5. Java records:

```text
snapshot_digest_after = digest(edge_map)
snapshot_classes_after = covered_class_set_digest
snapshot_write_count_after = total_coverage_writes
```

The snapshot is accepted only if:

```text
snapshot_generation unchanged
snapshot_digest_before == snapshot_digest_after
snapshot_classes_before == snapshot_classes_after
snapshot_write_count_before == snapshot_write_count_after
```

If any differ, the snapshot is not attributable.

### 5.2 Why This Attributes Coverage Correctly

Coverage belongs to the current iteration only if:

1. map was zeroed after the previous iteration,
2. current input ran under a fresh generation,
3. worker reached quiescence,
4. map did not change during Rust copy,
5. no late write was observed before starting the next input.

Only then may the Rust observer expose the copied map to LibAFL feedback.

---

## 6. Late-Coverage Detection

Late coverage is any coverage write after the accepted snapshot point.

The design must prevent this from bleeding into the next input.

### 6.1 Required Mechanism

Use both:

1. **Generation counter**
2. **Double-snapshot validation**

The coverage agent maintains:

```text
volatile long active_generation
AtomicLong total_coverage_writes
AtomicLong last_coverage_write_nanos
AtomicLong late_write_generation
```

Each instrumentation write does:

```text
if coverage_enabled:
    increment edge map counter saturating at 255
    total_coverage_writes++
    last_coverage_write_nanos = now
    if snapshot_closed_for_generation == active_generation:
        late_write_generation = active_generation
```

The important rule:

```text
Rust must never start input N+1 while input N has an unresolved late-write window.
```

### 6.2 LateWatch Window

After snapshot validation succeeds, Java waits:

```text
late_watch_window = settle_window
```

If no coverage write occurs during this window, the iteration is accepted.

If a write occurs during this window:

```text
result = LateCoverage
epoch = tainted
coverage = discard
action = restart before next input
```

### 6.3 Late Write After LateWatch

A write after LateWatch but before the next reset still taints the epoch if detected by generation state.

Before every reset, Java must check:

```text
late_write_generation == previous_generation
or total_coverage_writes changed since accepted snapshot
```

If true:

```text
do not run next input
return EpochTaintedLateWrite
Rust kills + restarts worker
```

This prevents a delayed background thread from writing after Rust has already accepted the prior input.

### 6.4 No Bleed Into Next Input

Before starting input `N+1`, Java must prove:

```text
previous_generation closed cleanly
no write count change since previous accepted snapshot
late_write_generation != previous_generation
```

Only then may it execute:

```text
resetCoverage(generation = previous_generation + 1)
```

If a background thread from input `N` writes after the reset for input `N+1`, it will increment the fresh map. That is contamination, so the generation guard must detect old-generation activity before reset, and the worker must restart if the guard cannot prove cleanliness.

For stronger protection, instrumented background tasks should capture the current iteration id when scheduled. On execution, if their captured id differs from `active_generation`, they must either:

1. avoid coverage writes, or
2. mark `late_write_generation = captured_generation`.

---

## 7. Restart Rules

The Rust executor owns worker liveness. Java reports structured statuses; Rust decides whether to continue, discard coverage, or restart.

### 7.1 Restart Immediately

Kill and restart JVM worker epoch on:

1. input execution timeout
2. quiescence deadline exceeded
3. JVM OOM
4. `StackOverflowError`
5. uncaught fatal exception from LS/harness
6. worker protocol desync
7. mmap unreadable or wrong size
8. edge map changes during snapshot copy
9. late coverage detected after snapshot
10. late write detected before next reset
11. instability during calibration
12. LS/BSP session enters unrecoverable state
13. pinned JDK mismatch
14. FFM SQLite binding/load error

### 7.2 Timeout Handling

On timeout:

1. Rust kills worker process group.
2. Rust records timeout result for the input.
3. Rust does not merge coverage from that input.
4. Rust starts a fresh worker epoch.
5. Fuzzer loop continues.

### 7.3 OOM and StackOverflow

Java worker must classify:

```text
OutOfMemoryError -> FatalJvmError.OOM
StackOverflowError -> FatalJvmError.StackOverflow
```

Rust behavior:

```text
discard coverage
mark execution as crash/interesting according to policy
restart worker epoch
continue fuzzing
```

### 7.4 Instability

If calibration of identical input shows nondeterministic coverage after the proven worker stability baseline:

```text
discard unstable coverage
increment instability metric
restart epoch
optionally mark input as flaky
continue fuzzing
```

If instability persists across fresh epochs, the executor may downgrade the target regime or disable that input path, but must not poison the corpus with unattributable coverage.

---

## 8. Rust-Side Extension Points

### 8.1 `JvmLspExecutor`

New LibAFL executor, separate from AFL forkserver executor.

Responsibilities:

1. launch JVM worker with exact pinned JDK
2. set env vars:
   - coverage mmap path
   - worker control socket/pipe paths
   - regime
   - timeout/quiescence settings
3. serialize `LspInput`
4. send `R<u32 len><bytes>`
5. wait for worker result
6. copy mmap map only after Java reports `SnapshotReady`
7. restart worker epochs on taint/failure
8. bypass `check_binary` and ELF/AFL signature checks

### 8.2 `JvmCoverageObserver`

LibAFL observer backed by a private Rust-owned copy of the Java mmap map.

It must not expose the live mmap directly to feedback.

Fields:

```text
copied_map: [u8; 65536]
iteration_id: u64
worker_epoch: u64
covered_classes: Vec<ClassId>
snapshot_digest: u64
```

### 8.3 `CoveredClassObserver`

Tracks the per-input covered-class set reported by Java.

Used for:

1. diagnostics
2. optional feedback
3. instability detection
4. class-level corpus analysis

### 8.4 `JvmCoverageFeedback`

AFL-style edge novelty feedback over the copied map.

Rules:

1. consume only accepted snapshots
2. ignore discarded timeout/late/tainted executions
3. never read the live mmap

### 8.5 `JvmWorkerHealthFeedback`

Optional feedback/monitoring based on `S` status:

```text
heap_used
thread_count
fd_count
worker_epoch
restart_count
late_write_count
quiescence_timeout_count
```

Used to detect leaks and regime instability.

---

## 9. Java Worker Extension Points

### 9.1 Worker Protocol

Existing protocol:

```text
R<u32 len><bytes>  run
S                  status
Q                  quit
```

Extend `R` response with structured result:

```text
RunResult {
  iteration_id
  worker_epoch
  status
  snapshot_ready
  edge_digest
  covered_class_digest
  covered_classes
  logical_run_nanos
  quiesce_nanos
  late_watch_nanos
  failure_kind
}
```

Statuses:

```text
OkSnapshot
TimeoutRun
TimeoutQuiescence
LateCoverage
SnapshotRace
FatalJvmError
ProtocolError
EpochTainted
```

### 9.2 Coverage Agent API

Required Java API:

```text
Coverage.reset(iterationId)
Coverage.beginIteration(iterationId)
Coverage.beginSnapshot()
Coverage.endSnapshotAndValidate()
Coverage.watchForLateWrites(duration)
Coverage.checkCleanBeforeNextReset()
Coverage.copyClassSet()
Coverage.status()
```

### 9.3 Future Tracking

Wrap all harness-issued LSP requests:

```text
outstandingFutures.increment()
future.whenComplete((result, error) -> outstandingFutures.decrement())
```

Also track:

1. BSP client requests
2. presentation compiler submitted jobs where observable
3. index jobs where observable
4. diagnostics futures
5. workspace/symbol, references, rename futures

### 9.4 Background Task Attribution

Where the worker controls scheduling, capture iteration id:

```text
long scheduledGeneration = Coverage.currentGeneration()
executor.submit(() -> {
  Coverage.enterTaskGeneration(scheduledGeneration)
  try { task.run() }
  finally { Coverage.exitTaskGeneration() }
})
```

If a task runs after its generation has closed, it must mark late coverage.

---

## 10. Planted Late-Write Tests

Add a Java fixture mode to the worker.

The fixture simulates an LS request that logically returns, then schedules a delayed background task that writes coverage.

### 10.1 Fixture Behavior

Test command:

```text
R input_with_late_write(delay_ms)
```

Worker does:

1. handle logical input normally
2. complete all direct futures
3. schedule background task:
   - sleep `delay_ms`
   - execute instrumented method `LateWriteFixture.coverageEdge()`
4. return through normal lifecycle

### 10.2 Positive Assertion: Quiesce Waits

Case:

```text
delay_ms < quiescence_deadline
delay_ms <= settle_window start boundary
```

Expected:

1. quiescence observes map change
2. settle window restarts
3. final snapshot includes the late edge
4. result is `OkSnapshot`
5. no restart required

### 10.3 Positive Assertion: Restart on Late Past Deadline

Case:

```text
delay_ms > quiescence_deadline
```

Expected:

1. worker reaches quiescence deadline or LateWatch detects write
2. result is `TimeoutQuiescence` or `LateCoverage`
3. Rust discards coverage
4. Rust kills and restarts worker epoch
5. fuzzer loop continues

### 10.4 Negative Assertion: No Merge Into Next Map

Case:

```text
input N schedules delayed write after snapshot
input N+1 is immediately attempted
```

Expected:

1. worker refuses to start `N+1` if previous generation has a late write
2. Rust restarts worker before running `N+1`
3. copied map for `N+1` does not contain `LateWriteFixture.coverageEdge`
4. LibAFL feedback for `N+1` sees no novelty from `N`

This test must assert against the Rust observer’s copied map, not the live mmap.

### 10.5 Snapshot Race Test

Fixture writes repeatedly during snapshot.

Expected:

1. `snapshot_digest_before != snapshot_digest_after` or write count changes
2. result is `SnapshotRace`
3. Rust discards coverage
4. worker restarts

---

## 11. Invariants

The implementation must preserve these invariants:

1. LibAFL feedback only sees Rust-copied maps.
2. Live mmap is never directly used for novelty feedback.
3. Every accepted map has exactly one `iteration_id`.
4. Every input starts from a zeroed coverage map.
5. Previous-edge state is reset per input.
6. Covered-class set is reset per input.
7. No input starts after unresolved late coverage.
8. Any attribution ambiguity causes epoch restart, not corpus pollution.
9. JVM worker restarts are normal executor events, not fuzzer failures.
10. The LS always runs under the exact pinned JDK required by the target.
