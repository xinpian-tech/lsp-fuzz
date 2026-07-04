//! Outcome classification for a single JVM LSP iteration.
//!
//! Every run of an input against the in-process language server resolves to exactly one
//! [`OutcomeClass`]. The classes cover the full space the oracle needs to reason about — from a
//! plain successful response through the various ways the server can misbehave (a JSON-RPC error, an
//! uncaught exception on a foreground or background thread, a logged fatal, a hard JVM fatal, memory
//! exhaustion, a hang, or a protocol desync). Only a subset of these are observable from the
//! worker's coverage-lifecycle status alone; the rest require richer evidence that the worker does
//! not yet report, so [`classify_run`] maps what the worker *can* observe today and the remaining
//! classes are populated from other signals (e.g. JSON-RPC error responses on the native path).

use serde::{Deserialize, Serialize};

use super::jvm::WorkerStatus;

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

/// Classify a run from the worker's coverage-lifecycle status.
///
/// This only covers what the worker reports today. `FatalJvmError` folds every hard failure into
/// [`OutcomeClass::JvmFatal`] until the worker carries the richer evidence needed to distinguish
/// OOM / stack overflow / foreground / background / logged-fatal sub-classes; the JSON-RPC error and
/// cancellation classes come from response matching, not from the worker status.
#[must_use]
pub const fn classify_run(status: WorkerStatus) -> OutcomeClass {
    match status {
        WorkerStatus::OkSnapshot => OutcomeClass::NormalSuccess,
        WorkerStatus::TimeoutRun | WorkerStatus::TimeoutQuiescence => {
            OutcomeClass::TimeoutOrDeadlock
        }
        WorkerStatus::FatalJvmError => OutcomeClass::JvmFatal,
        WorkerStatus::ProtocolError => OutcomeClass::ProtocolDesync,
        WorkerStatus::LateCoverage | WorkerStatus::SnapshotRace => OutcomeClass::Instability,
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
