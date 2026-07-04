//! `LibAFL` executor for JVM language-server targets (the non-fork-server path).
//!
//! Where the native path uses an AFL fork server, a JVM target is driven through a persistent
//! worker (see [`super::jvm`]). This executor plugs that worker into `LibAFL`: each `run_target`
//! serializes the input, runs it through the worker, copies the attributable coverage into an owned
//! map observer (never the live mmap), restarts the worker epoch when the run tainted it, and
//! reports the mapped [`ExitKind`]. It performs no ELF/AFL-signature inspection, so it is
//! independent of the native binary checks.

use std::{borrow::Cow, fmt, marker::PhantomData, path::PathBuf};

use libafl::{
    HasTargetBytesConverter,
    executors::{Executor, ExitKind, HasObservers},
    inputs::ToTargetBytes,
    observers::{Observer, StdMapObserver},
    state::HasExecutions,
};
use libafl_bolts::{AsSliceMut, Named, tuples::RefIndexable};
use serde::{Deserialize, Serialize};

use super::jvm::{JvmWorker, LifecycleOutcome, MAP_SIZE, WorkerError, WorkerTransport};
use super::outcome::OutcomeClass;
use crate::findings::{FindingSet, findings_from_jvm_side_channel};

/// The coverage observer for JVM targets: an owned AFL edge map the executor fills from the copied
/// worker snapshot each iteration. Reuses `LibAFL`'s map observer so it composes with the standard
/// map feedback (e.g. `MaxMapFeedback`).
pub type JvmCoverageObserver = StdMapObserver<'static, u8, false>;

/// Build a fresh, zeroed [`JvmCoverageObserver`] of the agent's map size.
#[must_use]
pub fn jvm_coverage_observer(name: &'static str) -> JvmCoverageObserver {
    StdMapObserver::owned(name, vec![0u8; MAP_SIZE])
}

/// The oracle observer for JVM targets: records the per-run [`OutcomeClass`] and any JSON-RPC error
/// findings the worker published to its `$COV_FINDINGS_PATH` side channel. This makes the outcome
/// classification durable at the `LibAFL` observer layer (rather than discarded once `run_target`
/// maps it to an `ExitKind`), so a feedback / provenance-export path can consume it per input.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JvmOutcomeObserver {
    /// The worker's findings side-channel file, shared with the worker via `$COV_FINDINGS_PATH`. Not
    /// serialized: it is a runtime path, meaningful only for the live executor.
    #[serde(skip)]
    findings_path: Option<PathBuf>,
    /// The class of the most recent run (`None` before the first run / after a reset).
    last_outcome: Option<OutcomeClass>,
    /// The deduplicated JSON-RPC error findings of the most recent run.
    findings: FindingSet,
}

impl JvmOutcomeObserver {
    /// Create the observer; `findings_path` is the shared `$COV_FINDINGS_PATH` the worker writes and
    /// this observer reads after each run (pass `None` to disable finding capture).
    #[must_use]
    pub fn new(findings_path: Option<PathBuf>) -> Self {
        Self {
            findings_path,
            last_outcome: None,
            findings: FindingSet::new(),
        }
    }

    /// The class of the most recent run.
    #[must_use]
    pub fn last_outcome(&self) -> Option<OutcomeClass> {
        self.last_outcome
    }

    /// The deduplicated findings of the most recent run.
    #[must_use]
    pub fn findings(&self) -> &FindingSet {
        &self.findings
    }

    /// Clear the previous run's outcome and remove any stale side-channel file, so a later read
    /// reflects only the run about to happen (a run that publishes nothing leaves no file).
    fn reset_before_run(&mut self) {
        self.last_outcome = None;
        self.findings = FindingSet::new();
        if let Some(path) = &self.findings_path {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Record the run's class and read its published JSON-RPC error findings (absent file → none).
    fn record_after_run(&mut self, outcome_class: OutcomeClass) {
        self.last_outcome = Some(outcome_class);
        self.findings = match &self.findings_path {
            Some(path) => std::fs::read_to_string(path)
                .map(|contents| findings_from_jvm_side_channel(&contents))
                .unwrap_or_default(),
            None => FindingSet::new(),
        };
    }
}

impl Named for JvmOutcomeObserver {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("jvm-outcome");
        &NAME
    }
}

impl<I, S> Observer<I, S> for JvmOutcomeObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl::Error> {
        self.reset_before_run();
        Ok(())
    }
}

/// A `LibAFL` [`Executor`] that drives a persistent JVM coverage worker.
pub struct JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    worker: JvmWorker<T>,
    respawn: Box<dyn FnMut() -> Result<T, WorkerError>>,
    observers: (JvmCoverageObserver, (JvmOutcomeObserver, ())),
    _phantom: PhantomData<(I, S)>,
}

impl<T, I, S> fmt::Debug for JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JvmLspExecutor")
            .field("epoch", &self.worker.epoch())
            .finish_non_exhaustive()
    }
}

impl<T, I, S> JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    /// Create an executor over `worker`; `respawn` spawns a fresh transport for epoch restarts and
    /// may fail (e.g. the JVM cannot be re-launched), in which case `run_target` reports an error
    /// rather than continuing on a dead epoch.
    pub fn new(
        worker: JvmWorker<T>,
        respawn: impl FnMut() -> Result<T, WorkerError> + 'static,
    ) -> Self {
        Self::with_observers(
            worker,
            respawn,
            jvm_coverage_observer("jvm-edges"),
            JvmOutcomeObserver::new(None),
        )
    }

    /// Like [`JvmLspExecutor::new`] but adopts a caller-provided coverage observer, so the caller can
    /// build the map feedback from the same observer (by name) before the executor takes ownership.
    /// The outcome observer captures no findings (no side-channel path).
    pub fn with_observer(
        worker: JvmWorker<T>,
        respawn: impl FnMut() -> Result<T, WorkerError> + 'static,
        observer: JvmCoverageObserver,
    ) -> Self {
        Self::with_observers(worker, respawn, observer, JvmOutcomeObserver::new(None))
    }

    /// Like [`JvmLspExecutor::with_observer`] but also adopts a caller-provided outcome observer, so
    /// the outcome observer can be wired to the worker's `$COV_FINDINGS_PATH` side channel.
    pub fn with_observers(
        worker: JvmWorker<T>,
        respawn: impl FnMut() -> Result<T, WorkerError> + 'static,
        coverage: JvmCoverageObserver,
        outcome: JvmOutcomeObserver,
    ) -> Self {
        JvmLspExecutor {
            worker,
            respawn: Box::new(respawn),
            observers: (coverage, (outcome, ())),
            _phantom: PhantomData,
        }
    }

    /// The coverage observer (for building feedback that reads the copied map).
    #[must_use]
    pub fn coverage_observer(&self) -> &JvmCoverageObserver {
        &self.observers.0
    }

    /// The outcome observer (records the per-run [`OutcomeClass`] and JSON-RPC error findings).
    #[must_use]
    pub fn outcome_observer(&self) -> &JvmOutcomeObserver {
        &self.observers.1.0
    }

    /// Restart the worker epoch when the last run tainted it. Propagates a spawn failure so the
    /// caller never continues on a dead epoch.
    fn restart_if_needed(&mut self, restart_required: bool) -> Result<(), WorkerError> {
        if restart_required {
            let fresh = (self.respawn)()?;
            self.worker.restart_epoch(fresh);
        }
        Ok(())
    }

    /// Reset the outcome side channel, run `bytes` capturing coverage into the observer's owned map,
    /// then record the run's outcome class + published findings. Split out of `run_target` so the
    /// reset→run→record ordering is unit-testable without a full fuzzer/state: the reset MUST precede
    /// the run so a run that dies before publishing its findings file cannot inherit the previous
    /// run's findings.
    fn run_and_record(&mut self, bytes: &[u8]) -> LifecycleOutcome {
        // Clear the outcome observer + remove any stale side-channel file BEFORE the run. This is the
        // `pre_exec` hook a stock LibAFL executor would run for us; this custom executor drives it.
        self.observers.1.0.reset_before_run();
        // Capture the attributable coverage directly into the observer's owned map (zeroed on any
        // non-attributable outcome). worker and observers are disjoint fields.
        let outcome = {
            let map: &mut [u8] = self.observers.0.as_slice_mut();
            let map: &mut [u8; MAP_SIZE] = map
                .try_into()
                .expect("jvm coverage observer map is MAP_SIZE");
            self.worker.run_capturing(bytes, map)
        };
        // Persist the oracle classification + any JSON-RPC error findings at the observer layer so a
        // feedback / provenance-export path can consume them (the coverage map already lives in
        // observer 0). The worker published its findings before replying, so this read is ready.
        self.observers.1.0.record_after_run(outcome.outcome_class);
        outcome
    }
}

impl<T, I, S> HasObservers for JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    type Observers = (JvmCoverageObserver, (JvmOutcomeObserver, ()));

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<EM, I, S, Z, T> Executor<EM, I, S, Z> for JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
    S: HasExecutions,
    Z: HasTargetBytesConverter,
    Z::Converter: ToTargetBytes<I>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, libafl::Error> {
        let bytes = fuzzer.target_bytes_converter_mut().to_target_bytes(input);
        let outcome = self.run_and_record(&bytes);
        self.restart_if_needed(outcome.restart_required)
            .map_err(|err| {
                libafl::Error::unknown(format!("failed to restart JVM worker epoch: {err}"))
            })?;
        *state.executions_mut() += 1;
        Ok(outcome.exit_kind)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use libafl_bolts::AsSlice;

    use super::*;
    use crate::execution::jvm::Request;

    /// Minimal transport for executor tests: every request errors (its replies are irrelevant here;
    /// the executor's restart path is what these tests exercise).
    #[derive(Debug)]
    struct DeadTransport;
    impl WorkerTransport for DeadTransport {
        fn request(
            &mut self,
            _request: &Request,
            _deadline: Duration,
        ) -> Result<Vec<u8>, WorkerError> {
            Err(WorkerError::Protocol)
        }
        fn kill(&mut self) {}
    }

    /// The coverage observer is exactly `MAP_SIZE` bytes and is the buffer `run_target` writes the
    /// copied worker snapshot into; the standard `MaxMapFeedback` reads novelty from it.
    #[test]
    fn coverage_observer_is_map_sized_and_writable() {
        let mut observer = jvm_coverage_observer("jvm-edges-test");
        {
            let map = observer.as_slice_mut();
            assert_eq!(map.len(), MAP_SIZE);
            map[0] = 1;
            map[MAP_SIZE - 1] = 2;
        }
        let map = observer.as_slice();
        assert_eq!(map[0], 1);
        assert_eq!(map[MAP_SIZE - 1], 2);
    }

    /// The outcome observer captures the per-run class and reads the worker's published JSON-RPC
    /// findings; a reset removes the stale side-channel file so a later run cannot inherit it.
    #[test]
    fn outcome_observer_records_class_and_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.tsv");
        std::fs::write(&path, "textDocument/hover\t-32603\tboom\n").unwrap();

        let mut observer = JvmOutcomeObserver::new(Some(path.clone()));
        observer.record_after_run(OutcomeClass::JsonRpcError);
        assert_eq!(observer.last_outcome(), Some(OutcomeClass::JsonRpcError));
        assert_eq!(observer.findings().len(), 1);

        // A reset clears state and removes the file so a later run starts clean.
        observer.reset_before_run();
        assert_eq!(observer.last_outcome(), None);
        assert!(observer.findings().is_empty());
        assert!(!path.exists());

        // A run that publishes nothing records the class with no findings (attributable or not).
        observer.record_after_run(OutcomeClass::NormalSuccess);
        assert_eq!(observer.last_outcome(), Some(OutcomeClass::NormalSuccess));
        assert!(observer.findings().is_empty());
    }

    /// Without a side-channel path the observer still records the class (no findings).
    #[test]
    fn outcome_observer_without_path_captures_class_only() {
        let mut observer = JvmOutcomeObserver::new(None);
        observer.record_after_run(OutcomeClass::JvmFatal);
        assert_eq!(observer.last_outcome(), Some(OutcomeClass::JvmFatal));
        assert!(observer.findings().is_empty());
    }

    /// A run that dies before the worker publishes its findings file must NOT inherit the previous
    /// run's side channel: `run_and_record` (driven by `run_target`) resets the outcome observer and
    /// removes the stale file BEFORE running. Regression for the missing pre-exec reset — without the
    /// `reset_before_run` call this reads the stale `boom` finding and attributes it to this run.
    #[test]
    fn a_run_does_not_inherit_the_previous_runs_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.tsv");
        // A prior run's published findings still on disk.
        std::fs::write(&path, "textDocument/hover\t-32603\tboom\n").unwrap();

        let worker = JvmWorker::new(DeadTransport, "/nonexistent/map", Duration::from_secs(1));
        let mut executor: JvmLspExecutor<DeadTransport, (), ()> = JvmLspExecutor::with_observers(
            worker,
            || Err(WorkerError::Protocol),
            jvm_coverage_observer("jvm-edges-test"),
            JvmOutcomeObserver::new(Some(path.clone())),
        );

        // DeadTransport makes the run a protocol failure that publishes nothing (no Java body writes
        // the file). The reset before the run must clear the stale findings + remove the stale file.
        let _ = executor.run_and_record(b"any input");
        assert!(
            executor.observers.1.0.findings().is_empty(),
            "a non-publishing run must not inherit the previous run's findings"
        );
        assert!(
            !path.exists(),
            "the stale side-channel file must be removed before the run"
        );
    }

    /// A required epoch restart whose respawn fails must surface as an error, not a panic, and not a
    /// silent continue on a dead epoch.
    #[test]
    fn restart_failure_is_reported_not_panicked() {
        let worker = JvmWorker::new(DeadTransport, "/nonexistent/map", Duration::from_secs(1));
        let mut executor: JvmLspExecutor<DeadTransport, (), ()> =
            JvmLspExecutor::new(worker, || Err(WorkerError::Protocol));
        assert!(
            executor.restart_if_needed(true).is_err(),
            "a failed respawn on a required restart must be an error"
        );
        // No restart needed → Ok even if respawn would fail.
        assert!(executor.restart_if_needed(false).is_ok());
    }
}
