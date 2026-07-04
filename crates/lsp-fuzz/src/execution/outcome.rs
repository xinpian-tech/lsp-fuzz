//! Outcome classification for a single JVM LSP iteration.
//!
//! Every run of an input against the in-process language server resolves to exactly one
//! [`OutcomeClass`]. The classes cover the full space the oracle needs to reason about — from a
//! plain successful response through the various ways the server can misbehave (a JSON-RPC error, an
//! uncaught exception on a foreground or background thread, a logged fatal, a hard JVM fatal, memory
//! exhaustion, a hang, or a protocol desync). [`classify_outcome`] resolves a run from the worker's
//! lifecycle status **and** its fine-grained outcome evidence: the status is authoritative for the
//! attribution-driven classes (timeout, instability, protocol desync) while the evidence names the
//! specific class for a clean snapshot or a fatal error. [`classify_run`] is the evidence-`None`
//! shorthand for callers that have only a status (a transport or copy-out failure).

use serde::{Deserialize, Serialize};

use super::jvm::{OutcomeEvidence, WorkerStatus};

/// The classification of a single iteration's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutcomeClass {
    /// The request(s) completed and the server returned a normal result. Not a finding.
    NormalSuccess,
    /// The server returned a JSON-RPC error response. A finding.
    JsonRpcError,
    /// The server cancelled a request as expected (e.g. a `$/cancelRequest` was honoured). Not a
    /// finding — this is protocol-conformant behaviour.
    ExpectedCancellation,
    /// An exception escaped on a request-handling (foreground) thread. A finding.
    ForegroundException,
    /// An exception escaped on a background/worker thread. A finding.
    BackgroundException,
    /// The server logged a fatal-level event without crashing the process. A finding.
    LoggedFatal,
    /// The JVM died (uncaught fatal error, hard exit). A finding.
    JvmFatal,
    /// The JVM ran out of memory or overflowed the stack. A finding.
    OutOfMemoryOrStackOverflow,
    /// The run exceeded its time budget or the server failed to quiesce (a hang/deadlock). A
    /// finding.
    TimeoutOrDeadlock,
    /// The worker and the fuzzer disagreed on the control protocol. A harness/transport fault, not a
    /// server defect — not a finding.
    ProtocolDesync,
    /// Coverage arrived late or a snapshot raced the run. Non-attributable and forces a restart, but
    /// it is a harness-observed instability rather than a server defect — not a finding.
    Instability,
}

impl OutcomeClass {
    /// Whether an outcome of this class should be recorded as a finding.
    ///
    /// Successful, cancelled, harness-instability, and protocol-desync outcomes are not server
    /// defects and are excluded; everything that points at a server-side problem is a finding.
    #[must_use]
    pub const fn is_finding(self) -> bool {
        matches!(
            self,
            OutcomeClass::JsonRpcError
                | OutcomeClass::ForegroundException
                | OutcomeClass::BackgroundException
                | OutcomeClass::LoggedFatal
                | OutcomeClass::JvmFatal
                | OutcomeClass::OutOfMemoryOrStackOverflow
                | OutcomeClass::TimeoutOrDeadlock
        )
    }
}

/// Classify a run from the worker's coverage-lifecycle status alone (evidence unknown). A shorthand
/// for [`classify_outcome`] with [`OutcomeEvidence::None`], used where only the status is available
/// (a transport failure, a copy-out failure).
#[must_use]
pub const fn classify_run(status: WorkerStatus) -> OutcomeClass {
    classify_outcome(status, OutcomeEvidence::None)
}

/// Classify a run from the worker's lifecycle status **and** its fine-grained outcome evidence.
///
/// The status is authoritative for the attribution-driven classes: any timeout is
/// [`OutcomeClass::TimeoutOrDeadlock`], a late/racy snapshot is [`OutcomeClass::Instability`], and a
/// protocol error is [`OutcomeClass::ProtocolDesync`] — the evidence cannot override these. For a
/// clean snapshot or a fatal JVM error, the evidence names the specific class (so a `FatalJvmError`
/// resolves to OOM / stack overflow / foreground / background / logged-fatal / hard fatal, and a
/// clean snapshot can still carry a JSON-RPC error or an expected cancellation). Evidence-`None` on a
/// `FatalJvmError` is a generic [`OutcomeClass::JvmFatal`]; on a clean snapshot it is a plain success.
#[must_use]
pub const fn classify_outcome(status: WorkerStatus, evidence: OutcomeEvidence) -> OutcomeClass {
    match status {
        WorkerStatus::TimeoutRun | WorkerStatus::TimeoutQuiescence => {
            return OutcomeClass::TimeoutOrDeadlock;
        }
        WorkerStatus::LateCoverage | WorkerStatus::SnapshotRace => {
            return OutcomeClass::Instability;
        }
        WorkerStatus::ProtocolError => return OutcomeClass::ProtocolDesync,
        WorkerStatus::OkSnapshot | WorkerStatus::FatalJvmError => {}
    }
    match evidence {
        OutcomeEvidence::None => match status {
            WorkerStatus::FatalJvmError => OutcomeClass::JvmFatal,
            _ => OutcomeClass::NormalSuccess,
        },
        OutcomeEvidence::NormalSuccess => OutcomeClass::NormalSuccess,
        OutcomeEvidence::JsonRpcError => OutcomeClass::JsonRpcError,
        OutcomeEvidence::ExpectedCancellation => OutcomeClass::ExpectedCancellation,
        OutcomeEvidence::ForegroundException => OutcomeClass::ForegroundException,
        OutcomeEvidence::BackgroundException => OutcomeClass::BackgroundException,
        OutcomeEvidence::LoggedFatal => OutcomeClass::LoggedFatal,
        OutcomeEvidence::JvmFatal => OutcomeClass::JvmFatal,
        OutcomeEvidence::OutOfMemory | OutcomeEvidence::StackOverflow => {
            OutcomeClass::OutOfMemoryOrStackOverflow
        }
        OutcomeEvidence::TimeoutOrDeadlock => OutcomeClass::TimeoutOrDeadlock,
        OutcomeEvidence::ProtocolDesync => OutcomeClass::ProtocolDesync,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_every_worker_status() {
        assert_eq!(
            classify_run(WorkerStatus::OkSnapshot),
            OutcomeClass::NormalSuccess
        );
        assert_eq!(
            classify_run(WorkerStatus::TimeoutRun),
            OutcomeClass::TimeoutOrDeadlock
        );
        assert_eq!(
            classify_run(WorkerStatus::TimeoutQuiescence),
            OutcomeClass::TimeoutOrDeadlock
        );
        assert_eq!(
            classify_run(WorkerStatus::FatalJvmError),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            classify_run(WorkerStatus::ProtocolError),
            OutcomeClass::ProtocolDesync
        );
        assert_eq!(
            classify_run(WorkerStatus::LateCoverage),
            OutcomeClass::Instability
        );
        assert_eq!(
            classify_run(WorkerStatus::SnapshotRace),
            OutcomeClass::Instability
        );
    }

    #[test]
    fn classify_outcome_combines_status_and_evidence() {
        use OutcomeEvidence as Ev;
        use WorkerStatus as St;

        // Status-authoritative classes ignore the evidence.
        for ev in [Ev::None, Ev::NormalSuccess, Ev::JsonRpcError, Ev::JvmFatal] {
            assert_eq!(
                classify_outcome(St::TimeoutRun, ev),
                OutcomeClass::TimeoutOrDeadlock
            );
            assert_eq!(
                classify_outcome(St::TimeoutQuiescence, ev),
                OutcomeClass::TimeoutOrDeadlock
            );
            assert_eq!(
                classify_outcome(St::LateCoverage, ev),
                OutcomeClass::Instability
            );
            assert_eq!(
                classify_outcome(St::SnapshotRace, ev),
                OutcomeClass::Instability
            );
            assert_eq!(
                classify_outcome(St::ProtocolError, ev),
                OutcomeClass::ProtocolDesync
            );
        }

        // A clean snapshot: evidence names the class.
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::None),
            OutcomeClass::NormalSuccess
        );
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::NormalSuccess),
            OutcomeClass::NormalSuccess
        );
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::JsonRpcError),
            OutcomeClass::JsonRpcError
        );
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::ExpectedCancellation),
            OutcomeClass::ExpectedCancellation
        );
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::BackgroundException),
            OutcomeClass::BackgroundException
        );
        assert_eq!(
            classify_outcome(St::OkSnapshot, Ev::LoggedFatal),
            OutcomeClass::LoggedFatal
        );

        // A fatal JVM error: evidence splits the fatal sub-classes.
        assert_eq!(
            classify_outcome(St::FatalJvmError, Ev::None),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            classify_outcome(St::FatalJvmError, Ev::JvmFatal),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            classify_outcome(St::FatalJvmError, Ev::OutOfMemory),
            OutcomeClass::OutOfMemoryOrStackOverflow
        );
        assert_eq!(
            classify_outcome(St::FatalJvmError, Ev::StackOverflow),
            OutcomeClass::OutOfMemoryOrStackOverflow
        );
        assert_eq!(
            classify_outcome(St::FatalJvmError, Ev::ForegroundException),
            OutcomeClass::ForegroundException
        );
    }

    #[test]
    fn only_server_defect_classes_are_findings() {
        // Findings.
        assert!(OutcomeClass::JsonRpcError.is_finding());
        assert!(OutcomeClass::ForegroundException.is_finding());
        assert!(OutcomeClass::BackgroundException.is_finding());
        assert!(OutcomeClass::LoggedFatal.is_finding());
        assert!(OutcomeClass::JvmFatal.is_finding());
        assert!(OutcomeClass::OutOfMemoryOrStackOverflow.is_finding());
        assert!(OutcomeClass::TimeoutOrDeadlock.is_finding());
        // Not findings.
        assert!(!OutcomeClass::NormalSuccess.is_finding());
        assert!(!OutcomeClass::ExpectedCancellation.is_finding());
        assert!(!OutcomeClass::ProtocolDesync.is_finding());
        assert!(!OutcomeClass::Instability.is_finding());
    }
}
