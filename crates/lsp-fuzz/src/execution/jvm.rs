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
    sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel},
    thread::JoinHandle,
    time::Duration,
};

use libafl::executors::ExitKind;

use super::outcome::{OutcomeClass, classify_outcome, classify_run};

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

/// The worker's fine-grained outcome evidence, orthogonal to the lifecycle [`WorkerStatus`]. The
/// status governs coverage attribution and epoch restart; the evidence names *what happened* for the
/// oracle, letting a single `FatalJvmError` status resolve to a specific class (OOM vs stack overflow
/// vs an uncaught exception) and letting a clean snapshot still carry a JSON-RPC error or a
/// cancellation. Mirrors the `cov.Evidence` tags on the Java side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeEvidence {
    /// No specific evidence; the class is derived from the status alone.
    None,
    /// The run completed normally.
    NormalSuccess,
    /// A request returned a JSON-RPC error response.
    JsonRpcError,
    /// A request was cancelled as expected.
    ExpectedCancellation,
    /// An exception escaped on a request-handling (foreground) thread.
    ForegroundException,
    /// An exception escaped on a background/worker thread.
    BackgroundException,
    /// The server logged a fatal-level event without crashing the process.
    LoggedFatal,
    /// A hard JVM fatal (SIGSEGV, forced exit, ...).
    JvmFatal,
    /// The JVM ran out of memory.
    OutOfMemory,
    /// The JVM overflowed the stack.
    StackOverflow,
    /// A run timeout / deadlock.
    TimeoutOrDeadlock,
    /// The control protocol desynchronized.
    ProtocolDesync,
}

impl OutcomeEvidence {
    fn from_tag(tag: u8) -> Option<OutcomeEvidence> {
        Some(match tag {
            0 => OutcomeEvidence::None,
            1 => OutcomeEvidence::NormalSuccess,
            2 => OutcomeEvidence::JsonRpcError,
            3 => OutcomeEvidence::ExpectedCancellation,
            4 => OutcomeEvidence::ForegroundException,
            5 => OutcomeEvidence::BackgroundException,
            6 => OutcomeEvidence::LoggedFatal,
            7 => OutcomeEvidence::JvmFatal,
            8 => OutcomeEvidence::OutOfMemory,
            9 => OutcomeEvidence::StackOverflow,
            10 => OutcomeEvidence::TimeoutOrDeadlock,
            11 => OutcomeEvidence::ProtocolDesync,
            _ => return None,
        })
    }

    /// The wire tag for this evidence (inverse of [`OutcomeEvidence::from_tag`]).
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            OutcomeEvidence::None => 0,
            OutcomeEvidence::NormalSuccess => 1,
            OutcomeEvidence::JsonRpcError => 2,
            OutcomeEvidence::ExpectedCancellation => 3,
            OutcomeEvidence::ForegroundException => 4,
            OutcomeEvidence::BackgroundException => 5,
            OutcomeEvidence::LoggedFatal => 6,
            OutcomeEvidence::JvmFatal => 7,
            OutcomeEvidence::OutOfMemory => 8,
            OutcomeEvidence::StackOverflow => 9,
            OutcomeEvidence::TimeoutOrDeadlock => 10,
            OutcomeEvidence::ProtocolDesync => 11,
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
    /// Fine-grained outcome evidence for the oracle (orthogonal to [`RunResult::status`]).
    pub evidence: OutcomeEvidence,
    /// A short, worker-normalized message for the evidence (e.g. an exception class); may be empty.
    pub message: String,
}

impl RunResult {
    /// Encode a run reply:
    /// `<status:u8><iteration_id:u64-le><nonzero_edges:u32-le><n:u32-le><class ids:u32-le...>`
    /// `<evidence:u8><msg_len:u32-le><msg bytes>`.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` classes were covered (impossible for a `2^16` map) or the
    /// message is longer than `u32::MAX` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = u32::try_from(self.covered_classes.len()).expect("class count fits in u32");
        let msg = self.message.as_bytes();
        let msg_len = u32::try_from(msg.len()).expect("message length fits in u32");
        let mut out = Vec::with_capacity(22 + self.covered_classes.len() * 4 + msg.len());
        out.push(self.status.tag());
        out.extend_from_slice(&self.iteration_id.to_le_bytes());
        out.extend_from_slice(&self.nonzero_edges.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for c in &self.covered_classes {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.push(self.evidence.tag());
        out.extend_from_slice(&msg_len.to_le_bytes());
        out.extend_from_slice(msg);
        out
    }

    /// Decode a run reply produced by [`RunResult::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Protocol`] if the bytes are truncated or carry an unknown status or
    /// evidence tag.
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
        let evidence =
            OutcomeEvidence::from_tag(*take(&mut cursor, 1)?.first().ok_or(WorkerError::Protocol)?)
                .ok_or(WorkerError::Protocol)?;
        let msg_len = u32::from_le_bytes(
            take(&mut cursor, 4)?
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ) as usize;
        let message =
            String::from_utf8(take(&mut cursor, msg_len)?).map_err(|_| WorkerError::Protocol)?;
        // Fail closed on a reply that is longer than the declared payload.
        if !cursor.is_empty() {
            return Err(WorkerError::Protocol);
        }
        Ok(RunResult {
            status,
            iteration_id,
            nonzero_edges,
            covered_classes,
            evidence,
            message,
        })
    }
}

/// The worker's reply to a [`Request::Status`]: a resource snapshot used for leak / bounded-resource
/// health checks (mirrors the worker's `S` reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerHealth {
    pub used_heap: u64,
    pub threads: u32,
    pub open_fds: u64,
}

impl WorkerHealth {
    /// Encode as `<used_heap:u64-le><threads:u32-le><open_fds:u64-le>`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(&self.used_heap.to_le_bytes());
        out.extend_from_slice(&self.threads.to_le_bytes());
        out.extend_from_slice(&self.open_fds.to_le_bytes());
        out
    }

    /// Decode a health reply produced by [`WorkerHealth::encode`]. Fails closed on the wrong length.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Protocol`] if `bytes` is not exactly 20 bytes.
    pub fn decode(bytes: &[u8]) -> Result<WorkerHealth, WorkerError> {
        if bytes.len() != 20 {
            return Err(WorkerError::Protocol);
        }
        let field = |range: std::ops::Range<usize>| -> Result<[u8; 8], WorkerError> {
            let mut buf = [0u8; 8];
            let slice = &bytes[range];
            buf[..slice.len()].copy_from_slice(slice);
            Ok(buf)
        };
        let used_heap = u64::from_le_bytes(field(0..8)?);
        let threads =
            u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| WorkerError::Protocol)?);
        let open_fds = u64::from_le_bytes(field(12..20)?);
        Ok(WorkerHealth {
            used_heap,
            threads,
            open_fds,
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
    /// The oracle's classification of this run. [`decide`] fills it from the status alone
    /// (evidence-`None`); [`JvmWorker::run`] refines it with the reply's outcome evidence.
    pub outcome_class: OutcomeClass,
}

/// Map a worker run status to the driver's lifecycle decision.
///
/// Only a clean snapshot yields attributable coverage. Every ambiguous or failing status discards
/// the coverage and requires an epoch restart, so late/racy writes are never merged into the next
/// input's map.
#[must_use]
pub fn decide(status: WorkerStatus) -> LifecycleOutcome {
    let outcome_class = classify_run(status);
    match status {
        WorkerStatus::OkSnapshot => LifecycleOutcome {
            exit_kind: ExitKind::Ok,
            coverage_attributable: true,
            restart_required: false,
            instability: false,
            outcome_class,
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
            outcome_class,
        },
        WorkerStatus::LateCoverage | WorkerStatus::SnapshotRace => LifecycleOutcome {
            exit_kind: ExitKind::Ok,
            coverage_attributable: false,
            restart_required: true,
            instability: true,
            outcome_class,
        },
        WorkerStatus::FatalJvmError => LifecycleOutcome {
            exit_kind: ExitKind::Crash,
            coverage_attributable: false,
            restart_required: true,
            instability: false,
            outcome_class,
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
            Ok(result) => {
                // Attribution/restart come from the lifecycle status; refine the oracle class with
                // the reply's fine-grained evidence.
                let mut outcome = decide(result.status);
                outcome.outcome_class = classify_outcome(result.status, result.evidence);
                outcome
            }
            Err(WorkerError::Timeout) => decide(WorkerStatus::TimeoutRun),
            Err(_) => decide(WorkerStatus::ProtocolError),
        }
    }

    /// Run one input and capture its coverage into `map`. This is the executor's per-iteration
    /// core: the map is filled with the copied coverage **only** when the outcome is
    /// `coverage_attributable`; otherwise (timeout, late write, snapshot race, fatal, protocol
    /// error) it is zeroed, so discarded coverage is never surfaced to feedback and a straggler
    /// write is never credited to this input. Returns the lifecycle outcome; the caller restarts the
    /// epoch when `restart_required`.
    pub fn run_capturing(&mut self, input: &[u8], map: &mut [u8; MAP_SIZE]) -> LifecycleOutcome {
        let outcome = self.run(input);
        if outcome.coverage_attributable {
            // The worker reported a clean snapshot but if the map is missing / wrong-size /
            // unreadable the coverage is NOT trustworthy: treat it as a protocol failure — discard
            // the buffer and require an epoch restart, never surface all-zero coverage as an
            // attributable run.
            let Ok(copied) = self.copy_map() else {
                map.fill(0);
                return decide(WorkerStatus::ProtocolError);
            };
            map.copy_from_slice(&copied[..]);
            return outcome;
        }
        map.fill(0);
        outcome
    }

    /// Request a worker health snapshot (used heap / live threads / open fds) for leak and
    /// bounded-resource monitoring.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Timeout`] if the worker does not answer within the run deadline, or
    /// [`WorkerError::Protocol`]/[`WorkerError::Io`] on a malformed or failed exchange.
    pub fn status(&mut self) -> Result<WorkerHealth, WorkerError> {
        let reply = self
            .transport
            .request(&Request::Status, self.run_deadline)?;
        WorkerHealth::decode(&reply)
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

    /// Kill the current worker and adopt a freshly-spawned transport as the next epoch.
    pub fn restart_epoch(&mut self, new_transport: T) {
        self.transport.kill();
        self.transport = new_transport;
        self.epoch += 1;
    }
}

/// A transport backed by a real worker subprocess speaking the control protocol over stdin/stdout.
///
/// Both directions are offloaded to dedicated threads so [`WorkerTransport::request`] itself never
/// blocks on the pipe: a **writer thread** owns stdin and drains a request channel, and a **reader
/// thread** owns stdout and pushes each complete length-prefixed reply frame onto a reply channel.
/// `request` only does a non-blocking channel send plus a `recv_timeout`, so the deadline bounds the
/// whole exchange — even a worker that never drains stdin (a request larger than the pipe buffer)
/// cannot stall the caller. On a deadline miss the caller restarts the epoch via
/// [`WorkerTransport::kill`], which kills the child (unblocking the writer) and joins both threads.
#[derive(Debug)]
pub struct SubprocessTransport {
    child: Child,
    to_writer: Option<Sender<Vec<u8>>>,
    replies: Receiver<io::Result<Vec<u8>>>,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
}

impl SubprocessTransport {
    /// Spawn the worker process. The worker reads framed requests from stdin and writes framed
    /// replies (`<u32-le len><bytes>`) to stdout.
    ///
    /// # Errors
    ///
    /// Returns any error from spawning the process.
    pub fn spawn(mut command: Command) -> Result<SubprocessTransport, WorkerError> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or(WorkerError::Protocol)?;
        let mut stdout = child.stdout.take().ok_or(WorkerError::Protocol)?;

        // Writer thread: drains the request channel and writes to stdin. If the worker never reads
        // stdin, `write_all` blocks HERE (not in `request`); killing the child closes the pipe and
        // ends this thread. Exits when the request channel's sender is dropped (`kill`).
        let (to_writer, from_main) = channel::<Vec<u8>>();
        let writer = std::thread::spawn(move || {
            while let Ok(bytes) = from_main.recv() {
                if stdin.write_all(&bytes).is_err() || stdin.flush().is_err() {
                    return;
                }
            }
        });

        // Reader thread: reads one framed reply at a time and forwards it. When the child dies or
        // stdout closes, `read_exact` errors and the loop forwards that error then exits; a hung
        // worker simply never sends, and the caller's `recv_timeout` fires instead.
        let (to_main, replies) = channel();
        let reader = std::thread::spawn(move || {
            loop {
                let mut len_buf = [0u8; 4];
                if let Err(err) = stdout.read_exact(&mut len_buf) {
                    let _ = to_main.send(Err(err));
                    return;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut reply = vec![0u8; len];
                if let Err(err) = stdout.read_exact(&mut reply) {
                    let _ = to_main.send(Err(err));
                    return;
                }
                if to_main.send(Ok(reply)).is_err() {
                    return; // receiver dropped: transport gone
                }
            }
        });

        Ok(SubprocessTransport {
            child,
            to_writer: Some(to_writer),
            replies,
            writer: Some(writer),
            reader: Some(reader),
        })
    }
}

impl WorkerTransport for SubprocessTransport {
    fn request(&mut self, request: &Request, deadline: Duration) -> Result<Vec<u8>, WorkerError> {
        // Drop any reply left over from a previous request (e.g. one that arrived after a timeout)
        // so this request's reply is the one recv'd below. After a timeout the caller restarts the
        // epoch anyway, so this is belt-and-suspenders.
        while self.replies.try_recv().is_ok() {}
        // Non-blocking hand-off to the writer thread: this never blocks on the pipe, so the deadline
        // below bounds the whole exchange regardless of a non-draining worker.
        self.to_writer
            .as_ref()
            .ok_or(WorkerError::Protocol)?
            .send(request.encode())
            .map_err(|_| WorkerError::Protocol)?;
        if matches!(request, Request::Quit) {
            return Ok(Vec::new());
        }
        match self.replies.recv_timeout(deadline) {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(err)) => Err(WorkerError::Io(err)),
            Err(RecvTimeoutError::Timeout) => Err(WorkerError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(WorkerError::Protocol),
        }
    }

    fn kill(&mut self) {
        // Drop the request sender so the writer's `recv` ends; kill+wait the child so a writer
        // blocked in `write_all` (non-draining worker) unblocks and the reader hits EOF; then join.
        self.to_writer = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for SubprocessTransport {
    fn drop(&mut self) {
        // Reap the worker process and I/O threads if the caller did not restart the epoch.
        self.kill();
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
            evidence: OutcomeEvidence::ForegroundException,
            message: "java.lang.NullPointerException".to_string(),
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
    fn decode_rejects_unknown_evidence_tag() {
        // A well-formed reply body through the class ids, then an unknown evidence tag (99).
        let mut wire = Vec::new();
        wire.push(WorkerStatus::OkSnapshot.tag());
        wire.extend_from_slice(&0u64.to_le_bytes()); // iteration_id
        wire.extend_from_slice(&0u32.to_le_bytes()); // nonzero_edges
        wire.extend_from_slice(&0u32.to_le_bytes()); // class count
        wire.push(99); // unknown evidence tag
        wire.extend_from_slice(&0u32.to_le_bytes()); // msg len 0
        assert!(matches!(
            RunResult::decode(&wire),
            Err(WorkerError::Protocol)
        ));
    }

    #[test]
    fn decode_rejects_message_length_overrun() {
        // Declares a 4-byte message but supplies none.
        let mut wire = Vec::new();
        wire.push(WorkerStatus::OkSnapshot.tag());
        wire.extend_from_slice(&0u64.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.extend_from_slice(&0u32.to_le_bytes());
        wire.push(OutcomeEvidence::NormalSuccess.tag());
        wire.extend_from_slice(&4u32.to_le_bytes()); // claims 4 message bytes, none follow
        assert!(matches!(
            RunResult::decode(&wire),
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

    /// A run-budget timeout (the Java worker returns status tag 1 for `RunBudgetExceededException`)
    /// must decode to `TimeoutRun` and be a timeout-class restart — never a crash objective.
    #[test]
    fn run_budget_timeout_tag_is_timeout_not_crash() {
        assert_eq!(WorkerStatus::from_tag(1), Some(WorkerStatus::TimeoutRun));
        let reply = RunResult {
            status: WorkerStatus::TimeoutRun,
            iteration_id: 7,
            nonzero_edges: 0,
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
        };
        let decoded = RunResult::decode(&reply.encode()).unwrap();
        assert_eq!(decoded.status, WorkerStatus::TimeoutRun);
        let outcome = decide(decoded.status);
        assert_eq!(outcome.exit_kind, ExitKind::Timeout);
        assert!(!outcome.coverage_attributable);
        assert!(outcome.restart_required);
        assert_ne!(
            outcome.exit_kind,
            decide(WorkerStatus::FatalJvmError).exit_kind
        );
    }

    #[test]
    fn run_clean_snapshot_is_attributable() {
        let reply = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 1,
            nonzero_edges: 10,
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
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
            evidence: OutcomeEvidence::None,
            message: String::new(),
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
    fn run_refines_outcome_class_from_evidence() {
        use crate::execution::outcome::OutcomeClass;

        // A fatal JVM error carrying OOM evidence classifies as OOM/StackOverflow, not generic fatal.
        let oom = RunResult {
            status: WorkerStatus::FatalJvmError,
            iteration_id: 1,
            nonzero_edges: 0,
            covered_classes: vec![],
            evidence: OutcomeEvidence::OutOfMemory,
            message: "java.lang.OutOfMemoryError".to_string(),
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(oom)]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        let outcome = worker.run(b"input");
        assert_eq!(outcome.exit_kind, ExitKind::Crash);
        assert_eq!(
            outcome.outcome_class,
            OutcomeClass::OutOfMemoryOrStackOverflow
        );

        // A clean snapshot carrying JSON-RPC-error evidence stays Ok/attributable but classifies as
        // a JSON-RPC error (a finding).
        let err = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 2,
            nonzero_edges: 10,
            covered_classes: vec![],
            evidence: OutcomeEvidence::JsonRpcError,
            message: "method not found".to_string(),
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(err)]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        let outcome = worker.run(b"input");
        assert!(outcome.coverage_attributable);
        assert_eq!(outcome.outcome_class, OutcomeClass::JsonRpcError);
        assert!(outcome.outcome_class.is_finding());
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
        worker.restart_epoch(MockTransport::new(vec![]));
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

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut wire = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 1,
            nonzero_edges: 0,
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
        }
        .encode();
        wire.push(0xAB); // one byte past the declared payload
        assert!(matches!(
            RunResult::decode(&wire),
            Err(WorkerError::Protocol)
        ));
    }

    #[test]
    fn worker_health_round_trip_and_truncation() {
        let health = WorkerHealth {
            used_heap: 123_456_789,
            threads: 6,
            open_fds: 42,
        };
        assert_eq!(WorkerHealth::decode(&health.encode()).unwrap(), health);
        assert!(matches!(
            WorkerHealth::decode(&[0u8; 19]),
            Err(WorkerError::Protocol)
        ));
        assert!(matches!(
            WorkerHealth::decode(&[0u8; 21]),
            Err(WorkerError::Protocol)
        ));
    }

    #[test]
    fn status_decodes_health_reply() {
        let health = WorkerHealth {
            used_heap: 1 << 30,
            threads: 8,
            open_fds: 12,
        };
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(health.encode())]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        assert_eq!(worker.status().unwrap(), health);
    }

    /// The real subprocess transport must honor the deadline on BOTH directions: a worker that never
    /// drains stdin AND a request larger than the OS pipe buffer must still time out within the
    /// deadline (the write happens on the writer thread, not in `request`), and `kill()` must
    /// terminate the child + join both threads without hanging. `sleep` ignores stdin and never
    /// writes stdout, standing in for a hung, non-draining worker.
    #[test]
    fn subprocess_transport_deadline_bounds_write_and_read() {
        use std::time::Instant;
        let mut command = Command::new("sleep");
        command.arg("100");
        // `sleep` unavailable in this environment: skip.
        let Ok(mut transport) = SubprocessTransport::spawn(command) else {
            return;
        };
        // A 1 MiB payload far exceeds the ~64 KiB pipe buffer; against a non-draining worker the
        // write cannot complete, but `request` must still return Timeout at the deadline.
        let big = Request::Run(vec![0x5a; 1 << 20]);
        let start = Instant::now();
        let result = transport.request(&big, Duration::from_millis(50));
        assert!(
            matches!(result, Err(WorkerError::Timeout)),
            "hung non-draining worker must time out, got {result:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "request should return promptly at the deadline, not block on the write"
        );
        // Must terminate the child and join both I/O threads without hanging.
        transport.kill();
    }

    #[test]
    fn run_capturing_fills_on_attributable_and_zeroes_otherwise() {
        use std::io::Write as _;
        // A real map file full of 0x7 for the attributable copy.
        let mut map_file = tempfile::NamedTempFile::new().unwrap();
        map_file.write_all(&vec![7u8; MAP_SIZE]).unwrap();
        map_file.flush().unwrap();
        let ok = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 1,
            nonzero_edges: u32::try_from(MAP_SIZE).unwrap(),
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
        }
        .encode();
        let late = RunResult {
            status: WorkerStatus::LateCoverage,
            iteration_id: 2,
            nonzero_edges: 3,
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(ok), Ok(late)]),
            map_file.path(),
            Duration::from_secs(1),
        );
        // Heap-allocate the buffer without a large stack array.
        let mut buf: Box<[u8; MAP_SIZE]> =
            vec![0u8; MAP_SIZE].into_boxed_slice().try_into().unwrap();

        // Attributable → buffer holds the copied map.
        let out = worker.run_capturing(b"a", &mut buf);
        assert!(out.coverage_attributable);
        assert!(
            buf.iter().all(|&b| b == 7),
            "attributable map must be copied"
        );

        // Late coverage → buffer zeroed, restart required, coverage discarded.
        let out = worker.run_capturing(b"b", &mut buf);
        assert!(!out.coverage_attributable);
        assert!(out.restart_required);
        assert!(
            buf.iter().all(|&b| b == 0),
            "discarded coverage must be zeroed, not left stale"
        );
    }

    #[test]
    fn run_capturing_clean_snapshot_but_copy_fails_is_non_attributable_restart() {
        // Worker reports a clean snapshot, but the map file does not exist: coverage is untrusted.
        let ok = RunResult {
            status: WorkerStatus::OkSnapshot,
            iteration_id: 1,
            nonzero_edges: 5,
            covered_classes: vec![],
            evidence: OutcomeEvidence::None,
            message: String::new(),
        }
        .encode();
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(ok)]),
            "/nonexistent/map/file",
            Duration::from_secs(1),
        );
        let mut buf: Box<[u8; MAP_SIZE]> =
            vec![9u8; MAP_SIZE].into_boxed_slice().try_into().unwrap();
        let out = worker.run_capturing(b"a", &mut buf);
        assert!(
            !out.coverage_attributable,
            "a failed map copy must not be reported as attributable"
        );
        assert!(
            out.restart_required,
            "a failed map copy must require restart"
        );
        assert!(
            buf.iter().all(|&b| b == 0),
            "the observer buffer must be zeroed, not left with prior contents"
        );
    }

    /// End-to-end cross-language check: compile the real Java worker (no coverage agent needed for a
    /// protocol round trip) and drive it through the real subprocess transport. Proves the Rust
    /// codecs interoperate with the Java worker's little-endian framing. Skips if the JDK is absent.
    #[test]
    fn real_java_worker_round_trip() {
        let agent = concat!(env!("CARGO_MANIFEST_DIR"), "/../../jvm-coverage-agent/src");
        let sources = [
            format!("{agent}/cov/Cov.java"),
            format!("{agent}/cov/Lifecycle.java"),
            format!("{agent}/cov/Evidence.java"),
            format!("{agent}/cov/RunOutcome.java"),
            format!("{agent}/cov/Findings.java"),
            format!("{agent}/cov/IterationBody.java"),
            format!("{agent}/cov/FixtureBody.java"),
            format!("{agent}/cov/LsIterationBody.java"),
            format!("{agent}/cov/RunBudgetExceededException.java"),
            format!("{agent}/cov/Worker.java"),
            format!("{agent}/fixture/Target.java"),
            format!("{agent}/fixture/LateWriteFixture.java"),
        ];
        assert_sources_present(&sources);
        let out = tempfile::tempdir().unwrap();
        let compiled = Command::new("javac")
            .arg("-d")
            .arg(out.path())
            .args(&sources)
            .status();
        match compiled {
            Ok(status) if status.success() => {}
            // javac ran but the sources failed to compile: a real regression, not a skip.
            Ok(_) => panic!("javac is present but the agent sources failed to compile"),
            Err(_) => return, // javac unavailable: skip
        }
        let map_file = out.path().join("map.bin");
        let mut command = Command::new("java");
        command
            .arg("-cp")
            .arg(out.path())
            .arg("cov.Worker")
            .env("COV_MAP_PATH", &map_file);
        let Ok(transport) = SubprocessTransport::spawn(command) else {
            return;
        };
        let mut worker = JvmWorker::new(transport, &map_file, Duration::from_secs(30));

        // A normal (non-0xEE / non-0xFF) input runs cleanly -> OkSnapshot -> attributable.
        let outcome = worker.run(&[0x01]);
        assert!(
            outcome.coverage_attributable,
            "normal input should be a clean snapshot, got {outcome:?}"
        );
        let map = worker
            .copy_map()
            .expect("worker must publish a MAP_SIZE map");
        assert_eq!(map.len(), MAP_SIZE);

        // Status round trip decodes a well-formed WorkerHealth.
        let health = worker.status().expect("status reply must decode");
        assert!(
            health.threads >= 1,
            "worker reports at least its own thread"
        );
        // Dropping the worker/transport reaps the child.
    }

    /// End-to-end outcome-oracle check on the real Java worker: drive the planted fixture modes for
    /// each outcome class through the real subprocess transport and assert the worker's evidence maps
    /// to the exact [`OutcomeClass`]. Also proves the JVM-path JSON-RPC finding side channel
    /// (`$COV_FINDINGS_PATH`) is read into a deduplicated finding set. Skips if the JDK is absent.
    #[test]
    fn outcome_evidence_classification_matrix() {
        use crate::execution::outcome::OutcomeClass;
        use crate::findings::findings_from_jvm_side_channel;

        let agent = concat!(env!("CARGO_MANIFEST_DIR"), "/../../jvm-coverage-agent/src");
        let sources = [
            format!("{agent}/cov/Cov.java"),
            format!("{agent}/cov/Lifecycle.java"),
            format!("{agent}/cov/Evidence.java"),
            format!("{agent}/cov/RunOutcome.java"),
            format!("{agent}/cov/Findings.java"),
            format!("{agent}/cov/IterationBody.java"),
            format!("{agent}/cov/FixtureBody.java"),
            format!("{agent}/cov/LsIterationBody.java"),
            format!("{agent}/cov/RunBudgetExceededException.java"),
            format!("{agent}/cov/Worker.java"),
            format!("{agent}/fixture/Target.java"),
            format!("{agent}/fixture/LateWriteFixture.java"),
        ];
        assert_sources_present(&sources);
        let out = tempfile::tempdir().unwrap();
        let compiled = Command::new("javac")
            .arg("-d")
            .arg(out.path())
            .args(&sources)
            .status();
        match compiled {
            Ok(status) if status.success() => {}
            Ok(_) => panic!("javac is present but the agent sources failed to compile"),
            Err(_) => return, // javac unavailable: skip
        }

        let map_file = out.path().join("map.bin");
        let findings_file = out.path().join("findings.tsv");
        let mut command = Command::new("java");
        command
            .arg("-cp")
            .arg(out.path())
            .arg("cov.Worker")
            .env("COV_MAP_PATH", &map_file)
            .env("COV_FINDINGS_PATH", &findings_file)
            .env("COV_SETTLE_MS", "1")
            .env("COV_LATE_WATCH_MS", "1")
            .env("COV_QUIESCE_DEADLINE_MS", "2000");
        let Ok(transport) = SubprocessTransport::spawn(command) else {
            return;
        };
        let mut worker = JvmWorker::new(transport, &map_file, Duration::from_secs(30));

        // (planted mode byte, expected class, expected is_finding). The fixture maps each mode to a
        // distinct Evidence tag / thrown error; the worker serializes it and the driver classifies it.
        let matrix: &[(u8, OutcomeClass, bool)] = &[
            (0x01, OutcomeClass::NormalSuccess, false),
            (0xE6, OutcomeClass::TimeoutOrDeadlock, true),
            (0xE7, OutcomeClass::OutOfMemoryOrStackOverflow, true),
            (0xE8, OutcomeClass::OutOfMemoryOrStackOverflow, true),
            (0xE9, OutcomeClass::ForegroundException, true),
            (0xEA, OutcomeClass::BackgroundException, true),
            (0xEB, OutcomeClass::LoggedFatal, true),
            (0xEC, OutcomeClass::JsonRpcError, true),
            (0xED, OutcomeClass::ExpectedCancellation, false),
            (0xEF, OutcomeClass::JvmFatal, true),
        ];
        for (mode, expected, is_finding) in matrix {
            let outcome = worker.run(&[*mode]);
            assert_eq!(
                outcome.outcome_class, *expected,
                "planted mode {mode:#x} should classify as {expected:?}, got {outcome:?}"
            );
            assert_eq!(
                outcome.outcome_class.is_finding(),
                *is_finding,
                "planted mode {mode:#x} finding-membership mismatch for {expected:?}"
            );
        }

        // The JSON-RPC-error mode publishes exactly one finding to the side channel.
        worker.run(&[0xEC]);
        let set = findings_from_jvm_side_channel(
            &std::fs::read_to_string(&findings_file)
                .expect("the JSON-RPC-error mode must publish a findings file"),
        );
        assert_eq!(set.len(), 1, "one JSON-RPC finding expected, got {set:?}");
        assert_eq!(set.as_slice()[0].class, OutcomeClass::JsonRpcError);
        assert_eq!(set.as_slice()[0].error_code, Some(-32603));

        // Negative: an expected cancellation is not a finding — its clean run publishes an empty file.
        worker.run(&[0xED]);
        let cancel_set = findings_from_jvm_side_channel(
            &std::fs::read_to_string(&findings_file).unwrap_or_default(),
        );
        assert!(
            cancel_set.is_empty(),
            "expected cancellation must not produce a finding, got {cancel_set:?}"
        );
    }

    /// A planted protocol desync at the driver boundary: a worker reply that fails to decode is a
    /// [`WorkerStatus::ProtocolError`] and classifies as [`OutcomeClass::ProtocolDesync`] — a
    /// harness/transport fault, not a server finding.
    #[test]
    fn protocol_desync_is_classified_and_not_a_finding() {
        use crate::execution::outcome::OutcomeClass;

        // A malformed reply (unknown status tag) cannot decode → the driver treats it as a protocol
        // error and restarts.
        let mut worker = JvmWorker::new(
            MockTransport::new(vec![Ok(vec![0xFF, 0x00])]),
            "/nonexistent/map",
            Duration::from_secs(1),
        );
        let outcome = worker.run(b"input");
        assert_eq!(outcome.outcome_class, OutcomeClass::ProtocolDesync);
        assert!(!outcome.outcome_class.is_finding());
        assert!(outcome.restart_required);
        assert!(!outcome.coverage_attributable);
    }

    /// End-to-end coverage-lifecycle check on the real Java worker (no coverage agent needed — the
    /// planted fixture records its edge directly). Drives the real subprocess transport and proves
    /// the attribution contract: a clean input is attributable; a planted late write and a planted
    /// snapshot race are both discarded and force an epoch restart; and after a fresh epoch a clean
    /// input's copied map matches the baseline, so a discarded late edge never bleeds into the next
    /// input. Skips if the JDK is absent.
    #[test]
    fn real_java_worker_lifecycle_attribution_and_restart() {
        let agent = concat!(env!("CARGO_MANIFEST_DIR"), "/../../jvm-coverage-agent/src");
        let sources = [
            format!("{agent}/cov/Cov.java"),
            format!("{agent}/cov/Lifecycle.java"),
            format!("{agent}/cov/Evidence.java"),
            format!("{agent}/cov/RunOutcome.java"),
            format!("{agent}/cov/Findings.java"),
            format!("{agent}/cov/IterationBody.java"),
            format!("{agent}/cov/FixtureBody.java"),
            format!("{agent}/cov/LsIterationBody.java"),
            format!("{agent}/cov/RunBudgetExceededException.java"),
            format!("{agent}/cov/Worker.java"),
            format!("{agent}/fixture/Target.java"),
            format!("{agent}/fixture/LateWriteFixture.java"),
        ];
        assert_sources_present(&sources);
        let out = tempfile::tempdir().unwrap();
        let compiled = Command::new("javac")
            .arg("-d")
            .arg(out.path())
            .args(&sources)
            .status();
        match compiled {
            Ok(status) if status.success() => {}
            // javac ran but the sources failed to compile: a real regression, not a skip.
            Ok(_) => panic!("javac is present but the agent sources failed to compile"),
            Err(_) => return, // javac unavailable: skip
        }

        // Spawn one worker epoch with sharp lifecycle windows so the test is fast and deterministic.
        let spawn = |map_file: &std::path::Path| -> Option<JvmWorker<SubprocessTransport>> {
            let mut command = Command::new("java");
            command
                .arg("-cp")
                .arg(out.path())
                .arg("cov.Worker")
                .env("COV_MAP_PATH", map_file)
                .env("COV_SETTLE_MS", "1")
                .env("COV_LATE_WATCH_MS", "1")
                .env("COV_QUIESCE_DEADLINE_MS", "2000");
            let transport = SubprocessTransport::spawn(command).ok()?;
            Some(JvmWorker::new(transport, map_file, Duration::from_secs(30)))
        };

        let planted_late: &[u8] = &[0xE2];
        let planted_race: &[u8] = &[0xE3];
        let clean: &[u8] = &[0x01];

        let mut buf: Box<[u8; MAP_SIZE]> =
            vec![0u8; MAP_SIZE].into_boxed_slice().try_into().unwrap();

        // Epoch A: a clean input (accepted, attributable), then a planted late write (discarded).
        let map_a = out.path().join("map_a.bin");
        let Some(mut worker) = spawn(&map_a) else {
            return;
        };
        let clean_outcome = worker.run_capturing(clean, &mut buf);
        assert!(
            clean_outcome.coverage_attributable && !clean_outcome.restart_required,
            "a clean input must be an attributable snapshot: {clean_outcome:?}"
        );
        let baseline = buf.clone();

        let late_outcome = worker.run_capturing(planted_late, &mut buf);
        assert!(
            !late_outcome.coverage_attributable
                && late_outcome.restart_required
                && late_outcome.instability,
            "a late write must be discarded and force a restart: {late_outcome:?}"
        );
        assert!(
            buf.iter().all(|&b| b == 0),
            "discarded late coverage must zero the observer buffer"
        );
        drop(worker); // the executor would kill the tainted epoch here

        // Epoch B (the restart): a fresh worker serves the same clean input, and its copied map
        // matches the baseline — the discarded late edge did not bleed into the next input.
        let map_b = out.path().join("map_b.bin");
        let Some(mut fresh) = spawn(&map_b) else {
            return;
        };
        let post_restart = fresh.run_capturing(clean, &mut buf);
        assert!(
            post_restart.coverage_attributable && !post_restart.restart_required,
            "the post-restart clean input must be attributable: {post_restart:?}"
        );
        assert_eq!(
            buf.as_slice(),
            baseline.as_slice(),
            "post-restart clean map must match the baseline (no late-edge bleed)"
        );
        drop(fresh);

        // Epoch C: a planted snapshot race is discarded and forces a restart.
        let map_c = out.path().join("map_c.bin");
        let Some(mut racer) = spawn(&map_c) else {
            return;
        };
        let race_outcome = racer.run_capturing(planted_race, &mut buf);
        assert!(
            !race_outcome.coverage_attributable && race_outcome.restart_required,
            "a snapshot race must be discarded and force a restart: {race_outcome:?}"
        );
    }

    /// Panic (not skip) when a checked-in Java source is missing: that is a source-list/repository
    /// regression, not an unavailable external toolchain. Lists every missing path.
    fn assert_sources_present(sources: &[String]) {
        let missing: Vec<&str> = sources
            .iter()
            .filter(|s| !std::path::Path::new(s).exists())
            .map(String::as_str)
            .collect();
        assert!(
            missing.is_empty(),
            "checked-in Java worker sources are missing (source-list regression):\n{}",
            missing.join("\n")
        );
    }

    /// The LS's exact pinned JDK, derived from its launcher wrapper (its FFM `SQLite` binding
    /// segfaults on a foreign JDK build). Returns the `.../bin/java` under the jar's package root.
    fn pinned_java_from_wrapper(ls_jar: &std::path::Path) -> Option<std::path::PathBuf> {
        let pkg_root = ls_jar.ancestors().nth(3)?; // .../lib/<name>/<name>.jar -> package root
        let bin = pkg_root.join("bin");
        let wrapper = std::fs::read_dir(&bin)
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .next()?;
        let text = String::from_utf8_lossy(&std::fs::read(&wrapper).ok()?).into_owned();
        for (start, _) in text.match_indices("/nix/store/") {
            let rest = &text[start..];
            if let Some(end) = rest.find("/bin/java") {
                let candidate = &rest[..end + "/bin/java".len()];
                if candidate.contains("openjdk") && !candidate.contains(['\n', '"', ' ']) {
                    return Some(std::path::PathBuf::from(candidate));
                }
            }
        }
        None
    }

    /// Real in-process language-server lifecycle: launch the worker with the LS jar on its classpath
    /// and `COV_ITERATION_BODY=ls`, so `cov.Worker` embeds `ls.core.ScalaLs` in-JVM over lsp4j
    /// streams and drives a real `initialize` (once) + a per-input `hover` request. Proves two Scala
    /// inputs run through `SubprocessTransport` + `JvmWorker` as attributable `OkSnapshot`s — real
    /// request futures tracked, quiescence honoured, no deadlock — against the actual language
    /// server. Gated on the LS jar (`LS_JAR`) run under its pinned JDK; skips loudly otherwise.
    #[test]
    #[allow(clippy::too_many_lines, reason = "linear end-to-end real-LS setup")]
    fn real_in_process_ls_worker_lifecycle() {
        use libafl::inputs::ToTargetBytes;
        let Some(ls_jar) = std::env::var_os("LS_JAR") else {
            eprintln!("skipping real_in_process_ls_worker_lifecycle: LS_JAR unset");
            return;
        };
        let ls_jar = std::path::PathBuf::from(ls_jar);
        if !ls_jar.exists() {
            eprintln!("skipping: LS_JAR does not exist: {}", ls_jar.display());
            return;
        }
        let java = std::env::var_os("LS_JAVA")
            .map(std::path::PathBuf::from)
            .or_else(|| pinned_java_from_wrapper(&ls_jar))
            .unwrap_or_else(|| std::path::PathBuf::from("java"));
        let Some(javac) = java
            .parent()
            .map(|b| b.join("javac"))
            .filter(|p| p.exists())
        else {
            eprintln!("skipping: no javac next to {}", java.display());
            return;
        };

        let agent = concat!(env!("CARGO_MANIFEST_DIR"), "/../../jvm-coverage-agent/src");
        let sources = [
            format!("{agent}/cov/Cov.java"),
            format!("{agent}/cov/Lifecycle.java"),
            format!("{agent}/cov/Evidence.java"),
            format!("{agent}/cov/RunOutcome.java"),
            format!("{agent}/cov/Findings.java"),
            format!("{agent}/cov/IterationBody.java"),
            format!("{agent}/cov/FixtureBody.java"),
            format!("{agent}/cov/LsIterationBody.java"),
            format!("{agent}/cov/RunBudgetExceededException.java"),
            format!("{agent}/cov/Worker.java"),
            format!("{agent}/fixture/Target.java"),
            format!("{agent}/fixture/LateWriteFixture.java"),
        ];
        assert_sources_present(&sources);
        let out = tempfile::tempdir().unwrap();
        let compiled = Command::new(&javac)
            .arg("-d")
            .arg(out.path())
            .args(&sources)
            .status();
        match compiled {
            Ok(status) if status.success() => {}
            // The pinned javac exists (checked above), so a failed compile is a hard failure.
            Ok(_) => panic!("agent sources failed to compile with {}", javac.display()),
            Err(_) => {
                eprintln!("skipping: could not run javac at {}", javac.display());
                return;
            }
        }

        let map_file = out.path().join("ls-map.bin");
        let classes_file = out.path().join("ls-classes.txt");
        let requests_file = out.path().join("ls-requests.txt");
        let classpath = format!("{}:{}", out.path().display(), ls_jar.display());
        let mut command = Command::new(&java);
        command.arg("--enable-native-access=ALL-UNNAMED");
        // With the coverage agent attached, real language-server classes are instrumented and their
        // reach is recorded; without it the lifecycle/attribution is still exercised (empty map).
        let agent_jar = std::env::var_os("COV_AGENT_JAR").map(std::path::PathBuf::from);
        let agent_attached = agent_jar.as_ref().is_some_and(|j| j.exists());
        if let Some(jar) = agent_jar.as_ref().filter(|j| j.exists()) {
            command.arg(format!("-javaagent:{}", jar.display()));
            command.env("COV_CLASSES_PATH", &classes_file);
        }
        command
            .arg("-cp")
            .arg(&classpath)
            .arg("cov.Worker")
            .env("COV_ITERATION_BODY", "ls")
            .env("COV_MAP_PATH", &map_file)
            .env("COV_REQUESTS_PATH", &requests_file)
            .env("COV_SETTLE_MS", "5")
            .env("COV_LATE_WATCH_MS", "5")
            .env("COV_QUIESCE_DEADLINE_MS", "15000");
        let Ok(transport) = SubprocessTransport::spawn(command) else {
            eprintln!("skipping: could not spawn the in-process LS worker");
            return;
        };
        let mut worker = JvmWorker::new(transport, &map_file, Duration::from_mins(1));
        let mut buf: Box<[u8; MAP_SIZE]> =
            vec![0u8; MAP_SIZE].into_boxed_slice().try_into().unwrap();

        // Build the worker payloads from REAL fuzzer inputs, exactly as JVM-mode fuzzing does: the
        // converter materializes each input's workspace, localizes its URIs, and frames its stored
        // LSP message sequence into the envelope the worker replays against the real server.
        let mut converter = crate::lsp_input::JvmLspInputConverter::new(
            out.path().to_path_buf(),
            crate::execution::scala_profile::ScalaExecutionProfile::presentation_compiler(),
        );

        // Input 1: a two-file workspace and two stored request kinds (hover + completion), so the
        // real server opens both documents and executes both requests.
        let input1 = two_file_input_with_messages();
        let envelope1 = converter.to_target_bytes(&input1).to_vec();
        let first = worker.run_capturing(&envelope1, &mut buf);
        assert!(
            first.coverage_attributable && !first.restart_required,
            "the first real-input run must be an attributable snapshot (requests tracked + drained): {first:?}"
        );

        // Prove the EXACT stored requests were forwarded and completed, not just that some ls.*
        // class was covered by initialize/didOpen. Both stored request kinds must appear.
        let completed = std::fs::read_to_string(&requests_file).unwrap_or_default();
        assert!(
            completed.lines().any(|m| m == "textDocument/hover")
                && completed.lines().any(|m| m == "textDocument/completion"),
            "both stored requests must have executed and completed; completed:\n{completed}"
        );

        if agent_attached {
            // The stored requests must have driven real language-server classes, not just transport.
            let classes = std::fs::read_to_string(&classes_file).unwrap_or_default();
            assert!(
                classes.lines().any(|c| c.starts_with("ls.")),
                "coverage should reach real ls.* classes; covered classes:\n{classes}"
            );
        }

        // Input 2: a different single-file workspace with a different message. It must be
        // attributable and uncontaminated by input 1's documents/background work.
        let input2 = single_file_input_with_message();
        let envelope2 = converter.to_target_bytes(&input2).to_vec();
        let second = worker.run_capturing(&envelope2, &mut buf);
        assert!(
            second.coverage_attributable && !second.restart_required,
            "the second real-input run must be attributable and uncontaminated: {second:?}"
        );
    }

    #[cfg(test)]
    fn scala_document(source: &str) -> crate::text_document::TextDocument {
        let mut doc = crate::text_document::TextDocument::new(
            lsp_fuzz_grammars::Language::Scala,
            source.into(),
        );
        doc.update_metadata();
        doc
    }

    #[cfg(test)]
    fn hover_message(uri: lsp_types::Uri) -> crate::lsp::LspMessage {
        crate::lsp::LspMessage::from_params::<lsp_types::request::HoverRequest>(
            lsp_types::HoverParams {
                text_document_position_params: lsp_types::TextDocumentPositionParams {
                    text_document: lsp_types::TextDocumentIdentifier { uri },
                    position: lsp_types::Position::new(0, 7),
                },
                work_done_progress_params: lsp_types::WorkDoneProgressParams::default(),
            },
        )
    }

    #[cfg(test)]
    fn completion_message(uri: lsp_types::Uri) -> crate::lsp::LspMessage {
        crate::lsp::LspMessage::from_params::<lsp_types::request::Completion>(
            lsp_types::CompletionParams {
                text_document_position: lsp_types::TextDocumentPositionParams {
                    text_document: lsp_types::TextDocumentIdentifier { uri },
                    position: lsp_types::Position::new(1, 4),
                },
                work_done_progress_params: lsp_types::WorkDoneProgressParams::default(),
                partial_result_params: lsp_types::PartialResultParams::default(),
                context: None,
            },
        )
    }

    #[cfg(test)]
    fn source_entry(
        source: &str,
    ) -> crate::file_system::FileSystemEntry<crate::lsp_input::WorkspaceEntry> {
        crate::file_system::FileSystemEntry::File(crate::lsp_input::WorkspaceEntry::SourceFile(
            scala_document(source),
        ))
    }

    #[cfg(test)]
    fn virtual_uri(name: &str) -> lsp_types::Uri {
        crate::lsp_input::uri::virtual_uri_for_path(std::path::Path::new(name))
            .expect("virtual URI for a workspace file")
    }

    #[cfg(test)]
    fn two_file_input_with_messages() -> crate::lsp_input::LspInput {
        use crate::utf8::Utf8Input;
        let workspace = crate::file_system::FileSystemDirectory::from([
            (
                Utf8Input::new("A.scala".to_owned()),
                source_entry("object A:\n  def value: Int = 1\n"),
            ),
            (
                Utf8Input::new("B.scala".to_owned()),
                source_entry("object B:\n  val y = A.value\n"),
            ),
        ]);
        let mut messages = crate::lsp_input::messages::LspMessageSequence::default();
        messages.push(hover_message(virtual_uri("A.scala")));
        messages.push(completion_message(virtual_uri("B.scala")));
        crate::lsp_input::LspInput {
            messages,
            workspace,
        }
    }

    #[cfg(test)]
    fn single_file_input_with_message() -> crate::lsp_input::LspInput {
        use crate::utf8::Utf8Input;
        let workspace = crate::file_system::FileSystemDirectory::from([(
            Utf8Input::new("C.scala".to_owned()),
            source_entry("object C:\n  def z: String = \"c\"\n"),
        )]);
        let mut messages = crate::lsp_input::messages::LspMessageSequence::default();
        messages.push(hover_message(virtual_uri("C.scala")));
        crate::lsp_input::LspInput {
            messages,
            workspace,
        }
    }
}
