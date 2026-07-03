//! `LibAFL` executor for JVM language-server targets (the non-fork-server path).
//!
//! Where the native path uses an AFL fork server, a JVM target is driven through a persistent
//! worker (see [`super::jvm`]). This executor plugs that worker into `LibAFL`: each `run_target`
//! serializes the input, runs it through the worker, copies the attributable coverage into an owned
//! map observer (never the live mmap), restarts the worker epoch when the run tainted it, and
//! reports the mapped [`ExitKind`]. It performs no ELF/AFL-signature inspection, so it is
//! independent of the native binary checks.

use std::{fmt, marker::PhantomData};

use libafl::{
    HasTargetBytesConverter,
    executors::{Executor, ExitKind, HasObservers},
    inputs::ToTargetBytes,
    observers::StdMapObserver,
    state::HasExecutions,
};
use libafl_bolts::{AsSliceMut, tuples::RefIndexable};

use super::jvm::{JvmWorker, MAP_SIZE, WorkerTransport};

/// The coverage observer for JVM targets: an owned AFL edge map the executor fills from the copied
/// worker snapshot each iteration. Reuses `LibAFL`'s map observer so it composes with the standard
/// map feedback (e.g. `MaxMapFeedback`).
pub type JvmCoverageObserver = StdMapObserver<'static, u8, false>;

/// Build a fresh, zeroed [`JvmCoverageObserver`] of the agent's map size.
#[must_use]
pub fn jvm_coverage_observer(name: &'static str) -> JvmCoverageObserver {
    StdMapObserver::owned(name, vec![0u8; MAP_SIZE])
}

/// A `LibAFL` [`Executor`] that drives a persistent JVM coverage worker.
pub struct JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    worker: JvmWorker<T>,
    respawn: Box<dyn FnMut() -> T>,
    observers: (JvmCoverageObserver, ()),
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
    /// Create an executor over `worker`; `respawn` produces a fresh transport for epoch restarts.
    pub fn new(worker: JvmWorker<T>, respawn: impl FnMut() -> T + 'static) -> Self {
        JvmLspExecutor {
            worker,
            respawn: Box::new(respawn),
            observers: (jvm_coverage_observer("jvm-edges"), ()),
            _phantom: PhantomData,
        }
    }

    /// The coverage observer (for building feedback that reads the copied map).
    #[must_use]
    pub fn coverage_observer(&self) -> &JvmCoverageObserver {
        &self.observers.0
    }
}

impl<T, I, S> HasObservers for JvmLspExecutor<T, I, S>
where
    T: WorkerTransport + fmt::Debug,
{
    type Observers = (JvmCoverageObserver, ());

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
        // Run the input and capture the attributable coverage directly into the observer's owned
        // map (zeroed on any non-attributable outcome). worker and observers are disjoint fields.
        let outcome = {
            let map: &mut [u8] = self.observers.0.as_slice_mut();
            let map: &mut [u8; MAP_SIZE] = map
                .try_into()
                .expect("jvm coverage observer map is MAP_SIZE");
            self.worker.run_capturing(&bytes, map)
        };
        if outcome.restart_required {
            let fresh = (self.respawn)();
            self.worker.restart_epoch(fresh);
        }
        *state.executions_mut() += 1;
        Ok(outcome.exit_kind)
    }
}

#[cfg(test)]
mod tests {
    use libafl_bolts::AsSlice;

    use super::*;

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
}
