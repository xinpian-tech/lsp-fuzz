//! Client for the persistent JVM coverage worker used to fuzz JVM language servers.
//!
//! JVM language servers cannot be instrumented with compile-time AFL instrumentation, so coverage
//! comes from a bytecode agent that writes an AFL-shaped edge map into a memory-mapped file. A
//! persistent worker process hosts the server in-process and speaks a small control protocol; this
//! module is the driver side of that protocol.
//!
//! The driver owns the per-iteration coverage lifecycle: it runs one input, waits for the worker's
//! structured result, and decides whether the copied coverage map is attributable to that input or
//! whether the worker epoch is tainted and must be restarted. Coverage is accepted only for a clean
//! snapshot; a timeout, a late background write, a snapshot race, or a fatal JVM error discards the
//! map and forces a fresh epoch, so a straggler write from one input can never be credited to the
//! next. This driver never inspects ELF or AFL signatures — the map is a plain shared byte slice —
//! so it is independent of the fork-server binary checks.
//!
//! The transport is abstracted so the protocol and lifecycle logic are exercised by an in-memory
//! mock in unit tests; the subprocess transport wires the same logic to a real worker process.

use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use libafl::executors::ExitKind;

/// AFL edge-map size (2^16), matching the bytecode agent.
pub const MAP_SIZE: usize = 1 << 16;

/// A request sent to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Run one serialized input.
    Run(Vec<u8>),
    /// Ask for a worker health/status snapshot.
    Status,
    /// Ask the worker to quit.
    Quit,
}

impl Request {
    /// Encode the request on the wire: `R<u32-le len><bytes>`, `S`, or `Q`.
    ///
    /// # Panics
    ///
    /// Panics if a run input is larger than `u32::MAX` bytes, which the fuzzer never produces.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::Run(bytes) => {
                let len = u32::try_from(bytes.len()).expect("run input length fits in u32");
                let mut out = Vec::with_capacity(5 + bytes.len());
                out.push(b'R');
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(bytes);
                out
            }
            Request::Status => vec![b'S'],
            Request::Quit => vec![b'Q'],
        }
    }
}

/// The worker's classification of a single run. Mirrors the statuses in the coverage-lifecycle
/// design: only [`WorkerStatus::OkSnapshot`] yields attributable coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
    /// The run reached quiescence and the coverage snapshot validated cleanly.
    OkSnapshot,
    /// The input's direct message sequence did not complete within the run timeout.
    TimeoutRun,
    /// Background work never settled within the quiescence deadline.
    TimeoutQuiescence,
    /// A background thread wrote coverage after the snapshot was taken.
    LateCoverage,
    /// The map changed while it was being copied, so the snapshot is not attributable.
    SnapshotRace,
    /// A fatal JVM condition (OOM, `StackOverflowError`, SIGSEGV, ...).
    FatalJvmError,
    /// The control protocol desynchronized or a reply was malformed.
    ProtocolError,
}

impl WorkerStatus {
    fn from_tag(tag: u8) -> Option<WorkerStatus> {
        Some(match tag {
            0 => WorkerStatus::OkSnapshot,
            1 => WorkerStatus::TimeoutRun,
            2 => WorkerStatus::TimeoutQuiescence,
            3 => WorkerStatus::LateCoverage,
            4 => WorkerStatus::SnapshotRace,
            5 => WorkerStatus::FatalJvmError,
            6 => WorkerStatus::ProtocolError,
            _ => return None,
        })
    }

    /// The wire tag for this status (inverse of [`WorkerStatus::from_tag`]).
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            WorkerStatus::OkSnapshot => 0,
            WorkerStatus::TimeoutRun => 1,
            WorkerStatus::TimeoutQuiescence => 2,
            WorkerStatus::LateCoverage => 3,
            WorkerStatus::SnapshotRace => 4,
            WorkerStatus::FatalJvmError => 5,
            WorkerStatus::ProtocolError => 6,
        }
    }
}

/// The worker's structured reply to a [`Request::Run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub status: WorkerStatus,
    /// Monotonic per-input id assigned by the worker; distinguishes generations for late-write
    /// attribution.
    pub iteration_id: u64,
    /// Non-zero edge count observed on the worker side (a cheap consistency cross-check for the
    /// map the driver copies out).
    pub nonzero_edges: u32,
    /// Class ids reached during the run (for reach oracles); may be empty.
    pub covered_classes: Vec<u32>,
}

impl RunResult {
    /// Encode a run reply: `<status:u8><iteration_id:u64-le><nonzero_edges:u32-le><n:u32-le><class ids:u32-le...>`.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` classes were covered, which cannot happen for a `2^16` map.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = u32::try_from(self.covered_classes.len()).expect("class count fits in u32");
        let mut out = Vec::with_capacity(17 + self.covered_classes.len() * 4);
        out.push(self.status.tag());
        out.extend_from_slice(&self.iteration_id.to_le_bytes());
        out.extend_from_slice(&self.nonzero_edges.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for c in &self.covered_classes {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Decode a run reply produced by [`RunResult::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Protocol`] if the bytes are truncated or carry an unknown status tag.
    pub fn decode(bytes: &[u8]) -> Result<RunResult, WorkerError> {
        let mut cursor = bytes;
        let mut u8v = || -> Result<u8, WorkerError> {
            let (h, t) = cursor.split_first().ok_or(WorkerError::Protocol)?;
            cursor = t;
            Ok(*h)
        };
        let status = WorkerStatus::from_tag(u8v()?).ok_or(WorkerError::Protocol)?;
        let take = |cursor: &mut &[u8], n: usize| -> Result<Vec<u8>, WorkerError> {
            if cursor.len() < n {
                return Err(WorkerError::Protocol);
            }
            let (h, t) = cursor.split_at(n);
            *cursor = t;
            Ok(h.to_vec())
        };
        let iteration_id = u64::from_le_bytes(
            take(&mut cursor, 8)?
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        );
        let nonzero_edges = u32::from_le_bytes(
            take(&mut cursor, 4)?
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        );
        let count = u32::from_le_bytes(
            take(&mut cursor, 4)?
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ) as usize;
        let mut covered_classes = Vec::with_capacity(count);
        for _ in 0..count {
            covered_classes.push(u32::from_le_bytes(
                take(&mut cursor, 4)?
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            ));
        }
        Ok(RunResult {
            status,
            iteration_id,
            nonzero_edges,
            covered_classes,
        })
    }
}

/// The driver's decision after a run: how `LibAFL` should treat it and whether the epoch survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleOutcome {
    pub exit_kind: ExitKind,
    /// Whether the copied coverage map is attributable to this input and may be fed to the
    /// coverage feedback. False whenever attribution is ambiguous.
    pub coverage_attributable: bool,
    /// Whether the worker epoch is tainted and must be killed + restarted before the next input.
    pub restart_required: bool,
    /// Whether the run was flagged unstable (e.g. a late write): recorded for feedback down-weighting.
    pub instability: bool,
}

/// Map a worker run status to the driver's lifecycle decision.
///
/// Only a clean snapshot yields attributable coverage. Every ambiguous or failing status discards
/// the coverage and requires an epoch restart, so late/racy writes are never merged into the next
/// input's map.
#[must_use]
pub fn decide(status: WorkerStatus) -> LifecycleOutcome {
    match status {
        WorkerStatus::OkSnapshot => LifecycleOutcome {
            exit_kind: ExitKind::Ok,
            coverage_attributable: true,
            restart_required: false,
            instability: false,
        },
        // A stalled run, a stalled quiescence, and a desynced protocol are all "no attributable
        // result, restart the epoch" — the executor treats them as a timeout-class execution.
        WorkerStatus::TimeoutRun
        | WorkerStatus::TimeoutQuiescence
        | WorkerStatus::ProtocolError => LifecycleOutcome {
            exit_kind: ExitKind::Timeout,
            coverage_attributable: false,
            restart_required: true,
            instability: false,
        },
        WorkerStatus::LateCoverage | WorkerStatus::SnapshotRace => LifecycleOutcome {
            exit_kind: ExitKind::Ok,
            coverage_attributable: false,
            restart_required: true,
            instability: true,
        },
        WorkerStatus::FatalJvmError => LifecycleOutcome {
            exit_kind: ExitKind::Crash,
            coverage_attributable: false,
            restart_required: true,
            instability: false,
        },
    }
}

/// Errors from driving the worker.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("worker I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("worker control protocol error")]
    Protocol,
    /// The worker did not reply within the deadline; the caller should restart the epoch.
    #[error("worker timed out")]
    Timeout,
}

/// A transport carries one request to the worker and returns its raw reply bytes, bounded by a
/// deadline. Abstracted so the protocol and lifecycle logic can be unit-tested against a mock.
pub trait WorkerTransport {
    /// Send `request` and read the raw reply bytes, failing with [`WorkerError::Timeout`] if the
    /// worker does not answer within `deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Timeout`] on deadline expiry, [`WorkerError::Io`] on transport I/O
    /// failure, or [`WorkerError::Protocol`] on a malformed exchange.
    fn request(&mut self, request: &Request, deadline: Duration) -> Result<Vec<u8>, WorkerError>;

    /// Kill the underlying worker (used before spawning a fresh epoch).
    fn kill(&mut self);
}

/// A persistent JVM coverage worker: a control transport plus the memory-mapped coverage map.
#[derive(Debug)]
pub struct JvmWorker<T: WorkerTransport + std::fmt::Debug> {
    transport: T,
    map_path: PathBuf,
    run_deadline: Duration,
    /// Incremented every epoch restart; surfaced for health feedback / diagnostics.
    epoch: u64,
}

impl<T: WorkerTransport + std::fmt::Debug> JvmWorker<T> {
    #[must_use]
    pub fn new(transport: T, map_path: impl Into<PathBuf>, run_deadline: Duration) -> Self {
        JvmWorker {
            transport,
            map_path: map_path.into(),
            run_deadline,
            epoch: 0,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Run one input and return its lifecycle decision. A transport timeout maps to a
    /// restart-required `Timeout` outcome rather than propagating, so the fuzzer loop is never
    /// stalled by a hung worker.
    pub fn run(&mut self, input: &[u8]) -> LifecycleOutcome {
        match self
            .transport
            .request(&Request::Run(input.to_vec()), self.run_deadline)
            .and_then(|reply| RunResult::decode(&reply))
        {
            Ok(result) => decide(result.status),
            Err(WorkerError::Timeout) => decide(WorkerStatus::TimeoutRun),
            Err(_) => decide(WorkerStatus::ProtocolError),
        }
    }

    /// Copy the coverage map out of the shared mmap file. The caller invokes this only when the
    /// preceding [`JvmWorker::run`] returned `coverage_attributable`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Protocol`] if the mapped file is not exactly [`MAP_SIZE`] bytes, or an
    /// I/O error if it cannot be read.
    pub fn copy_map(&self) -> Result<Box<[u8; MAP_SIZE]>, WorkerError> {
        read_map(&self.map_path)
    }

    /// Kill and re-spawn the worker epoch. The transport handles process teardown; `respawn`
    /// installs the fresh transport.
    pub fn restart_epoch(&mut self, respawn: impl FnOnce() -> T) {
        self.transport.kill();
        self.transport = respawn();
        self.epoch += 1;
    }
}

/// A transport backed by a real worker subprocess speaking the control protocol over stdin/stdout.
#[derive(Debug)]
pub struct SubprocessTransport {
    child: Child,
}

impl SubprocessTransport {
    /// Spawn the worker process. The worker is expected to read framed requests from stdin and
    /// write framed replies to stdout.
    ///
    /// # Errors
    ///
    /// Returns any error from spawning the process.
    pub fn spawn(mut command: Command) -> Result<SubprocessTransport, WorkerError> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        Ok(SubprocessTransport { child })
    }
}

impl WorkerTransport for SubprocessTransport {
    fn request(&mut self, request: &Request, _deadline: Duration) -> Result<Vec<u8>, WorkerError> {
        // Deadline enforcement for the blocking pipe is the executor's responsibility (a watchdog
        // that kills the child on timeout); this transport performs the framed exchange. Reading a
        // run reply requires the length-prefixed reply framing the worker emits.
        let stdin = self.child.stdin.as_mut().ok_or(WorkerError::Protocol)?;
        stdin.write_all(&request.encode())?;
        stdin.flush()?;
        if matches!(request, Request::Quit) {
            return Ok(Vec::new());
        }
        let stdout = self.child.stdout.as_mut().ok_or(WorkerError::Protocol)?;
        let mut len_buf = [0u8; 4];
        stdout.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut reply = vec![0u8; len];
        stdout.read_exact(&mut reply)?;
        Ok(reply)
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read exactly [`MAP_SIZE`] bytes from `path` as a coverage map. Standalone helper used by
/// cold-replay tooling that does not hold a live [`JvmWorker`]. Returns a boxed array so the
/// `2^16`-byte map is never placed on the stack.
///
/// # Errors
///
/// Returns [`WorkerError::Protocol`] if the file is not exactly [`MAP_SIZE`] bytes.
pub fn read_map(path: &Path) -> Result<Box<[u8; MAP_SIZE]>, WorkerError> {
    let mut file = std::fs::File::open(path)?;
    let mut map = vec![0u8; MAP_SIZE].into_boxed_slice();
    file.read_exact(&mut map)
        .map_err(|_| WorkerError::Protocol)?;
    // Reject a map larger than expected (wrong agent / stale file): the contract is exact size.
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(WorkerError::Protocol);
    }
    map.try_into().map_err(|_| WorkerError::Protocol)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// In-memory transport: replays a scripted queue of replies (or a timeout) per request.
    #[derive(Debug)]
    struct MockTransport {
        replies: VecDeque<Result<Vec<u8>, WorkerError>>,
        killed: usize,
    }

    impl MockTransport {
        fn new(replies: Vec<Result<Vec<u8>, WorkerError>>) -> Self {
            MockTransport {
                replies: replies.into(),
                killed: 0,
            }
        }
    }

    impl WorkerTransport for MockTransport {
        fn request(
            &mut self,
            _request: &Request,
            _deadline: Duration,
        ) -> Result<Vec<u8>, WorkerError> {
            self.replies
                .pop_front()
                .unwrap_or(Err(WorkerError::Protocol))
        }

        fn kill(&mut self) {
            self.killed += 1;
        }
    }

    #[test]
    fn request_encoding() {
        assert_eq!(Request::Status.encode(), vec![b'S']);
        assert_eq!(Request::Quit.encode(), vec![b'Q']);
        let run = Request::Run(vec![1, 2, 3]).encode();
        assert_eq!(&run[..1], b"R");
        assert_eq!(&run[1..5], &3u32.to_le_bytes());
        assert_eq!(&run[5..], &[1, 2, 3]);
    }

    #[test]
    fn run_result_round_trip() {
        let original = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 42,
            nonzero_edges: 931,
            covered_classes: vec![1, 1000, 3662],
        };
        let decoded = RunResult::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_truncated_and_unknown_status() {
        assert!(matches!(RunResult::decode(&[]), Err(WorkerError::Protocol)));
        assert!(matches!(
            RunResult::decode(&[99, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(WorkerError::Protocol)
        ));
        // valid status tag but truncated body
        assert!(matches!(
            RunResult::decode(&[0, 1, 2]),
            Err(WorkerError::Protocol)
        ));
    }

    #[test]
    fn decide_accepts_only_clean_snapshot() {
        let ok = decide(WorkerStatus::OkSnapshot);
        assert_eq!(ok.exit_kind, ExitKind::Ok);
        assert!(ok.coverage_attributable);
        assert!(!ok.restart_required);

        for status in [WorkerStatus::TimeoutRun, WorkerStatus::TimeoutQuiescence] {
            let o = decide(status);
            assert_eq!(o.exit_kind, ExitKind::Timeout);
            assert!(!o.coverage_attributable);
            assert!(o.restart_required);
        }

        for status in [WorkerStatus::LateCoverage, WorkerStatus::SnapshotRace] {
            let o = decide(status);
            assert!(
                !o.coverage_attributable,
                "late/racy coverage must be discarded"
            );
            assert!(o.restart_required);
            assert!(o.instability);
        }

        let fatal = decide(WorkerStatus::FatalJvmError);
        assert_eq!(fatal.exit_kind, ExitKind::Crash);
        assert!(!fatal.coverage_attributable);
        assert!(fatal.restart_required);
    }

    #[test]
    fn run_clean_snapshot_is_attributable() {
        let reply = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 1,
            nonzero_edges: 10,
            covered_classes: vec![],
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(reply)]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        let outcome = worker.run(b"input");
        assert!(outcome.coverage_attributable);
        assert!(!outcome.restart_required);
    }

    #[test]
    fn run_late_coverage_restarts_and_discards() {
        let reply = RunResult {
            status: WorkerStatus::LateCoverage,
            iteration_id: 7,
            nonzero_edges: 5,
            covered_classes: vec![],
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(reply)]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        let outcome = worker.run(b"input");
        assert!(!outcome.coverage_attributable);
        assert!(outcome.restart_required);
        assert!(outcome.instability);
    }

    #[test]
    fn run_transport_timeout_is_timeout_and_restart() {
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Err(WorkerError::Timeout)]),
            "/nonexistent/map",
            Duration::from_millis(1),
        );
        let outcome = worker.run(b"input");
        assert_eq!(outcome.exit_kind, ExitKind::Timeout);
        assert!(outcome.restart_required);
        assert!(!outcome.coverage_attributable);
    }

    #[test]
    fn restart_epoch_kills_and_respawns() {
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        assert_eq!(worker.epoch(), 0);
        worker.restart_epoch(|| MockTransport::new(vec![]));
        assert_eq!(worker.epoch(), 1);
    }

    #[test]
    fn copy_map_requires_exact_size() {
        use std::io::Write as _;
        // exact size → ok
        let mut exact = tempfile::NamedTempFile::new().unwrap();
        exact.write_all(&vec![7u8; MAP_SIZE]).unwrap();
        exact.flush().unwrap();
        let worker = JvmWorker::new(
            MockTransport::new(vec![]),
            exact.path(),
            Duration::from_secs(1),
        );
        let map = worker.copy_map().unwrap();
        assert_eq!(map.len(), MAP_SIZE);
        assert!(map.iter().all(|&b| b == 7));

        // too short → protocol error
        let mut short = tempfile::NamedTempFile::new().unwrap();
        short.write_all(&[0u8; 10]).unwrap();
        short.flush().unwrap();
        assert!(matches!(read_map(short.path()), Err(WorkerError::Protocol)));

        // too long → protocol error
        let mut long = tempfile::NamedTempFile::new().unwrap();
        long.write_all(&vec![0u8; MAP_SIZE + 1]).unwrap();
        long.flush().unwrap();
        assert!(matches!(read_map(long.path()), Err(WorkerError::Protocol)));
    }
}
