//! Finding provenance bundles and cold replay through the shipped language-server entrypoint.
//!
//! A [`FindingBundle`] is the durable, fully-provenanced record of one finding: the serialized
//! [`LspInput`], its oracle [`OutcomeClass`], the deduplicated JSON-RPC error [`FindingSet`], and a
//! [`Provenance`] record carrying everything needed for a one-command cold replay (the target LS
//! commit + classpath hash, the JDK flags, the coverage-agent version/config, the frozen backdrop
//! commit + snapshot / `SemanticDB` / BSP hashes, the native `SQLite`/FFM artifact hash, the Scala
//! profile mode, and the run-timeout budget).
//!
//! The export path is **fail-closed**: a bundle whose required provenance fields are absent is
//! rejected ([`FindingBundle::build`] returns an error) rather than written. A finding is only
//! promoted to [`Replayability::Confirmed`] once [`cold_replay`] reproduces the same outcome class
//! and compatible findings through the shipped `ls.core.Main` stdio entrypoint (from a cold JVM,
//! independent of the in-process worker); until then it stays [`Replayability::InProcessHarnessOnly`]
//! rather than being presented as a confirmed server defect.

use std::{
    borrow::Cow,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{ChildStderr, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use libafl::{
    HasMetadata,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    state::{HasCorpus, HasExecutions},
};
use libafl_bolts::{
    Named,
    tuples::{Handle, Handled, MatchNameRef},
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::execution::jvm_executor::JvmOutcomeObserver;
use crate::execution::outcome::OutcomeClass;
use crate::execution::scala_profile::{ScalaExecutionProfile, ScalaProfileMode};
use crate::findings::{FindingSet, findings_from_json_rpc_errors};
use crate::lsp::json_rpc::{JsonRPCMessage, MessageId};
use crate::lsp_input::LspInput;
use crate::lsp_input::materializer::{
    BackdropOverlayMaterializer, GenericTempRootMaterializer, WorkspaceMaterializer,
};
use crate::lsp_input::server_response::matching::RequestResponseMatching;
use crate::lsp_input::uri;

/// Provenance for a finding: the pinned versions/hashes/flags that make a cold replay reproducible.
///
/// Optional fields carry the value when known; [`Provenance::validate`] enforces which are *required*
/// (LS commit, classpath hash, and agent version always; the backdrop and native-`SQLite` hashes
/// additionally for `index` mode, which runs against the frozen backdrop over a live BSP index).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The Scala profile mode this finding was produced under (`pc` / `index`).
    pub scala_profile_mode: String,
    /// The per-input run-timeout budget in milliseconds.
    pub run_timeout_ms: u64,
    /// The target language-server commit.
    pub ls_commit: Option<String>,
    /// A hash of the language-server classpath.
    pub ls_classpath_hash: Option<String>,
    /// The JVM flags the server ran under (determinism flags, native-access, etc.).
    pub jdk_flags: Vec<String>,
    /// The coverage-agent version.
    pub agent_version: Option<String>,
    /// The coverage-agent configuration (include/exclude scope, map size, ...).
    pub agent_config: Option<String>,
    /// The frozen `zaozi` backdrop commit (index mode).
    pub backdrop_commit: Option<String>,
    /// The location-independent snapshot hash of the frozen backdrop (index mode).
    pub backdrop_snapshot_hash: Option<String>,
    /// The `SemanticDB` artifact hash (index mode).
    pub semanticdb_hash: Option<String>,
    /// The BSP config artifact hash (index mode).
    pub bsp_hash: Option<String>,
    /// The native `SQLite`/FFM artifact hash (index mode).
    pub sqlite_artifact_hash: Option<String>,
}

impl Provenance {
    /// Whether this provenance targets `index` mode (which requires the backdrop/`SQLite` fields).
    #[must_use]
    pub fn is_index_mode(&self) -> bool {
        self.scala_profile_mode == "index"
    }

    /// Build a provenance record for `mode` from the environment: the pinned versions/hashes are
    /// read from env vars an operator sets for a real campaign (`LS_COMMIT`, `LS_CLASSPATH_HASH`,
    /// `COV_AGENT_VERSION`, `COV_AGENT_CONFIG`, `BACKDROP_COMMIT`, `BACKDROP_SNAPSHOT_HASH`,
    /// `SEMANTICDB_HASH`, `BSP_HASH`, `SQLITE_ARTIFACT_HASH`, `JDK_FLAGS`). Absent fields stay `None`
    /// so [`Provenance::validate`] fails closed (findings are not exported without provenance).
    #[must_use]
    pub fn from_env(scala_profile_mode: &str, run_timeout_ms: u64) -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            scala_profile_mode: scala_profile_mode.to_string(),
            run_timeout_ms,
            ls_commit: env("LS_COMMIT"),
            ls_classpath_hash: env("LS_CLASSPATH_HASH"),
            jdk_flags: env("JDK_FLAGS")
                .map(|v| v.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            agent_version: env("COV_AGENT_VERSION"),
            agent_config: env("COV_AGENT_CONFIG"),
            backdrop_commit: env("BACKDROP_COMMIT"),
            backdrop_snapshot_hash: env("BACKDROP_SNAPSHOT_HASH"),
            semanticdb_hash: env("SEMANTICDB_HASH"),
            bsp_hash: env("BSP_HASH"),
            sqlite_artifact_hash: env("SQLITE_ARTIFACT_HASH"),
        }
    }

    /// Validate that all required provenance fields are present, returning the names of any that are
    /// missing. A finding whose provenance does not validate must not be exported.
    ///
    /// # Errors
    ///
    /// Returns [`MissingProvenance`] listing every required-but-absent field.
    pub fn validate(&self) -> Result<(), MissingProvenance> {
        // The known profile modes; an unrecognized mode is rejected (it could otherwise silently
        // bypass the index-mode requirements).
        let mode_known = matches!(self.scala_profile_mode.as_str(), "pc" | "index");
        let mut missing = Vec::new();
        if !mode_known {
            missing.push("scala_profile_mode");
        }
        if self.ls_commit.is_none() {
            missing.push("ls_commit");
        }
        if self.ls_classpath_hash.is_none() {
            missing.push("ls_classpath_hash");
        }
        if self.agent_version.is_none() {
            missing.push("agent_version");
        }
        // The agent config and the JVM flags must be recorded to reproduce the run; an operator with
        // no extra flags records the explicit `none` sentinel rather than leaving them empty.
        if self.agent_config.as_deref().unwrap_or_default().is_empty() {
            missing.push("agent_config");
        }
        if self.jdk_flags.is_empty() {
            missing.push("jdk_flags");
        }
        if self.is_index_mode() {
            if self.backdrop_commit.is_none() {
                missing.push("backdrop_commit");
            }
            if self.backdrop_snapshot_hash.is_none() {
                missing.push("backdrop_snapshot_hash");
            }
            if self.semanticdb_hash.is_none() {
                missing.push("semanticdb_hash");
            }
            if self.bsp_hash.is_none() {
                missing.push("bsp_hash");
            }
            if self.sqlite_artifact_hash.is_none() {
                missing.push("sqlite_artifact_hash");
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(MissingProvenance { missing })
        }
    }
}

/// The set of required provenance fields that were absent, so a finding export can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("finding provenance is incomplete; missing required fields: {missing:?}")]
pub struct MissingProvenance {
    pub missing: Vec<&'static str>,
}

/// Whether a finding has been confirmed to reproduce through the shipped entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Replayability {
    /// Cold replay through shipped `ls.core.Main` reproduced the same outcome class + findings.
    Confirmed,
    /// Observed only in the in-process harness; not (yet) reproduced through the shipped entrypoint,
    /// so it is NOT presented as a confirmed server defect.
    InProcessHarnessOnly,
}

/// A fully-provenanced finding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingBundle {
    pub input: LspInput,
    pub outcome_class: OutcomeClass,
    pub findings: FindingSet,
    pub provenance: Provenance,
    pub replayability: Replayability,
}

/// Whether a run's outcome warrants exporting a finding bundle: a server-defect class, or any
/// recorded JSON-RPC error finding (which can accompany an otherwise-clean run).
#[must_use]
pub fn should_export(outcome_class: OutcomeClass, findings: &FindingSet) -> bool {
    outcome_class.is_finding() || !findings.is_empty()
}

impl FindingBundle {
    /// Build a bundle, rejecting it (fail-closed) if the provenance is incomplete. A freshly built
    /// bundle is [`Replayability::InProcessHarnessOnly`] until a cold replay confirms it.
    ///
    /// # Errors
    ///
    /// Returns [`MissingProvenance`] if a required provenance field is absent.
    pub fn build(
        input: LspInput,
        outcome_class: OutcomeClass,
        findings: FindingSet,
        provenance: Provenance,
    ) -> Result<Self, MissingProvenance> {
        provenance.validate()?;
        Ok(Self {
            input,
            outcome_class,
            findings,
            provenance,
            replayability: Replayability::InProcessHarnessOnly,
        })
    }

    /// Serialize the bundle to CBOR (the same encoding the corpus uses).
    ///
    /// # Errors
    ///
    /// Returns any serialization error.
    pub fn to_cbor(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| io::Error::other(format!("serializing finding bundle: {e}")))?;
        Ok(buf)
    }

    /// Load a bundle from a CBOR file written by [`FindingBundle::write_to`] (for cold replay).
    ///
    /// # Errors
    ///
    /// Returns any I/O or deserialization error.
    pub fn read_from(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        ciborium::from_reader(&bytes[..])
            .map_err(|e| io::Error::other(format!("deserializing finding bundle: {e}")))
    }

    /// Write the bundle to `dir` as a CBOR file named by its outcome class + a hash of the WHOLE
    /// input (workspace *and* message sequence, so two findings that differ only in their messages
    /// get distinct files). Writing is collision-safe: an identical bundle already on disk is left as
    /// is (idempotent), and a different bundle that hashes to the same base name gets a numeric
    /// suffix rather than overwriting the earlier finding. Returns the written (or existing) path.
    ///
    /// # Errors
    ///
    /// Returns any I/O or serialization error.
    pub fn write_to(&self, dir: &Path) -> io::Result<PathBuf> {
        use std::hash::{Hash, Hasher};
        std::fs::create_dir_all(dir)?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.input.hash(&mut hasher);
        let base = format!("finding_{:?}_{:016x}", self.outcome_class, hasher.finish());
        let bytes = self.to_cbor()?;

        let mut suffix = 0u32;
        loop {
            let name = if suffix == 0 {
                format!("{base}.cbor")
            } else {
                format!("{base}_{suffix}.cbor")
            };
            let path = dir.join(name);
            match std::fs::read(&path) {
                // An identical bundle is already recorded — nothing to do (idempotent).
                Ok(existing) if existing == bytes => return Ok(path),
                // A different bundle hashed to this name — never overwrite it; try the next suffix.
                Ok(_) => suffix += 1,
                // Free slot.
                Err(_) => {
                    std::fs::write(&path, &bytes)?;
                    return Ok(path);
                }
            }
        }
    }

    /// Cold-replay this finding through the shipped `ls.core.Main` and, if it reproduces the same
    /// outcome class and compatible findings, promote it to [`Replayability::Confirmed`]. Returns
    /// whether it was confirmed. A finding that does not reproduce stays
    /// [`Replayability::InProcessHarnessOnly`].
    ///
    /// # Errors
    ///
    /// Returns any I/O error launching or driving the shipped entrypoint.
    pub fn confirm_via_cold_replay(&mut self, config: &ColdReplayConfig<'_>) -> io::Result<bool> {
        let replay = cold_replay(&self.input, config)?;
        let confirmed = check_equivalence(self, &replay);
        self.replayability = if confirmed {
            Replayability::Confirmed
        } else {
            Replayability::InProcessHarnessOnly
        };
        Ok(confirmed)
    }
}

/// How to cold-replay an input through the shipped entrypoint, carrying the SAME execution surface
/// the JVM fuzzing path uses: the Scala profile (initialize params + mode → materializer selection),
/// the temp root, and — for `index` mode — the verified frozen backdrop root (so documents overlay
/// the backdrop and responses lift frozen-source URIs exactly like the fuzzing path).
#[derive(Debug)]
pub struct ColdReplayConfig<'a> {
    /// The Scala execution profile; its mode selects the materializer and supplies initialize params.
    pub profile: &'a ScalaExecutionProfile,
    /// The shipped-entrypoint program (the LS's pinned `java`).
    pub program: String,
    /// The program arguments (classpath + `ls.core.Main` + native-access flags).
    pub args: Vec<String>,
    /// A scratch root for materializing the input's workspace (`pc` mode).
    pub temp_root: PathBuf,
    /// The verified frozen backdrop root, required for `index` mode.
    pub backdrop_root: Option<PathBuf>,
    /// The overall replay deadline; a server that never replies is a timeout.
    pub timeout: Duration,
}

/// What a cold replay through the shipped entrypoint observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayObservation {
    pub outcome_class: OutcomeClass,
    pub findings: FindingSet,
}

/// Whether a cold replay reproduced the bundle: the same outcome class, and every finding in the
/// bundle is present in the replay (the replay may surface additional ones).
#[must_use]
pub fn check_equivalence(bundle: &FindingBundle, replay: &ReplayObservation) -> bool {
    if bundle.outcome_class != replay.outcome_class {
        return false;
    }
    let replayed: std::collections::HashSet<String> = replay
        .findings
        .iter()
        .map(crate::findings::Finding::signature)
        .collect();
    bundle
        .findings
        .iter()
        .all(|f| replayed.contains(&f.signature()))
}

/// How the shipped-entrypoint process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessEnd {
    /// Exited cleanly (status 0).
    Clean,
    /// Exited with a non-zero status code (an abnormal termination without a signal).
    NonZero,
    /// Killed by a signal (no exit code) — a hard crash (SIGSEGV, ...).
    Signalled,
    /// Did not finish within the deadline and was killed by the driver.
    TimedOut,
}

/// Classify a cold replay across the FULL outcome oracle from the process end + its stderr + any
/// JSON-RPC error findings. Stderr/exit evidence (which the shipped entrypoint emits before dying)
/// distinguishes memory exhaustion, an uncaught foreground/background exception, a logged fatal, and a
/// hard JVM fatal — so a real server defect is not mislabelled a timeout or left harness-only.
fn classify_replay(end: ProcessEnd, stderr: &str, findings: &FindingSet) -> OutcomeClass {
    // A hang is a timeout regardless of what little the process printed.
    if end == ProcessEnd::TimedOut {
        return OutcomeClass::TimeoutOrDeadlock;
    }
    // Memory exhaustion: the JVM prints the error then dies.
    if stderr.contains("OutOfMemoryError") || stderr.contains("StackOverflowError") {
        return OutcomeClass::OutOfMemoryOrStackOverflow;
    }
    // An uncaught exception the JVM printed to stderr — foreground (main/request thread) vs background.
    if let Some(class) = uncaught_exception_class(stderr) {
        return class;
    }
    // A fatal-level log line emitted before exit.
    if has_fatal_log(stderr) {
        return OutcomeClass::LoggedFatal;
    }
    // Any other abnormal termination (a signal or a non-zero exit with no clearer evidence).
    if matches!(end, ProcessEnd::Signalled | ProcessEnd::NonZero) {
        return OutcomeClass::JvmFatal;
    }
    // A clean exit: a JSON-RPC error response is a finding, otherwise a normal success.
    if findings.is_empty() {
        OutcomeClass::NormalSuccess
    } else {
        OutcomeClass::JsonRpcError
    }
}

/// The outcome class for an `Exception in thread "<name>"` line the JVM prints for an uncaught
/// exception: `main` (or the LSP request loop) is a foreground exception, any other thread is a
/// background exception. A bare stack trace (`\tat ...`) with no thread header is treated as
/// foreground. Returns `None` if there is no uncaught-exception evidence.
fn uncaught_exception_class(stderr: &str) -> Option<OutcomeClass> {
    const MARKER: &str = "Exception in thread \"";
    if let Some(start) = stderr.find(MARKER) {
        let rest = &stderr[start + MARKER.len()..];
        let thread = rest.split('"').next().unwrap_or_default();
        return Some(if thread == "main" {
            OutcomeClass::ForegroundException
        } else {
            OutcomeClass::BackgroundException
        });
    }
    // A printed stack trace with no thread header (e.g. `Throwable.printStackTrace`) — foreground.
    if stderr.contains("\n\tat ") || stderr.starts_with("\tat ") {
        return Some(OutcomeClass::ForegroundException);
    }
    None
}

/// Whether stderr carries a fatal-level log line (a `FATAL`/`SEVERE` marker).
fn has_fatal_log(stderr: &str) -> bool {
    stderr.contains("FATAL") || stderr.contains("SEVERE")
}

/// Upper bound on captured stderr, so a chatty shipped entrypoint cannot exhaust the driver's memory.
const STDERR_CAPTURE_CAP: usize = 64 * 1024;

/// Stage the cold-replay writes onto `writer`, mirroring the warm in-process worker
/// (`cov::LsIterationBody`: `initialized` once per epoch, then `requestAndWait` for each request, never
/// `shutdown`/`exit` per input).
///
/// It writes `initialize` and AWAITS its response (id 0) before sending `initialized` — mirroring
/// `ensureInitialized`, so the server never receives `initialized` before answering `initialize`. In
/// index mode it then waits for the async BSP/index bootstrap readiness marker on stderr (`ready_rx`,
/// fed by the stderr reader) before any request, so requests do not race the bootstrap into a spurious
/// `-32803 "workspace is not ready"`; PC mode never prints that marker, so it proceeds straight to the
/// steps (waiting for it would burn the whole deadline and misclassify the run as a timeout). Then it
/// replays each step in order: a notification is written and left, while a request is written alone and
/// its exact response id (from `resp_id_rx`, fed by the stdout reader) is awaited before the next frame
/// — so a later/out-of-order response can never let teardown cut off an earlier request. Finally it
/// writes `shutdown`/`exit`, only after every request step has replied or the deadline expired. Every
/// wait is bounded by a single overall `deadline` so a broken/hung server can never hang us. Generic
/// over the writer so the ordering is directly testable against an in-memory recording writer.
fn drive_replay_writes<W: Write>(
    writer: &mut W,
    frames: &ColdReplayFrames,
    deadline: Duration,
    ready_rx: &Receiver<()>,
    resp_id_rx: &Receiver<usize>,
) {
    let deadline_at = Instant::now() + deadline;
    let remaining = || deadline_at.saturating_duration_since(Instant::now());
    // Track which response ids have arrived (a later one may precede the request currently awaited),
    // so awaiting an id already seen returns immediately.
    let mut seen = std::collections::HashSet::new();
    // Await response `target`, remembering any other ids that arrive first, bounded by the deadline.
    let await_response = |target: usize, seen: &mut std::collections::HashSet<usize>| {
        while !seen.contains(&target) {
            let wait = remaining();
            if wait.is_zero() {
                break;
            }
            match resp_id_rx.recv_timeout(wait) {
                Ok(rid) => {
                    seen.insert(rid);
                }
                Err(_) => break, // deadline or reader gone: stop awaiting
            }
        }
    };

    // initialize, and AWAIT its response before `initialized` — mirrors the warm worker's
    // `ensureInitialized` so the server never receives `initialized` before answering `initialize`.
    let _ = writer.write_all(&frames.initialize);
    let _ = writer.flush();
    await_response(COLD_REPLAY_INITIALIZE_ID, &mut seen);

    // initialized (in index mode this kicks off the async BSP/index bootstrap).
    let _ = writer.write_all(&frames.initialized);
    let _ = writer.flush();

    // Index mode then waits for the BSP/index bootstrap readiness marker on stderr before any request,
    // so requests do not race the bootstrap into a spurious `-32803 "workspace is not ready"`. PC mode
    // never prints that marker (and initialize is already awaited above), so it proceeds to the steps.
    if frames.wait_for_bsp_ready {
        let _ = ready_rx.recv_timeout(remaining());
    }

    for step in &frames.steps {
        let _ = writer.write_all(step.bytes());
        let _ = writer.flush();
        if let ReplayStep::Request { id, .. } = step {
            await_response(*id, &mut seen);
        }
    }
    let _ = writer.write_all(&frames.teardown);
    let _ = writer.flush();
}

/// Feed the entrypoint's stdin on a thread via [`drive_replay_writes`], then drop stdin to signal
/// end-of-input.
fn spawn_request_writer(
    mut stdin: ChildStdin,
    frames: ColdReplayFrames,
    deadline: Duration,
    ready_rx: Receiver<()>,
    resp_id_rx: Receiver<usize>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        drive_replay_writes(&mut stdin, &frames, deadline, &ready_rx, &resp_id_rx);
        drop(stdin); // signal end-of-input
    })
}

/// Read the entrypoint's stdout to EOF, sending the full byte buffer on `out_tx` at the end. While
/// reading, announce each newly-seen response id on `resp_id_tx` so the writer can await the exact
/// request it just sent before writing the next frame (responses may arrive out of order).
fn spawn_response_reader(
    mut stdout: ChildStdout,
    resp_id_tx: Sender<usize>,
    out_tx: Sender<Vec<u8>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut announced = std::collections::HashSet::new();
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    // Re-parse the accumulated buffer (tiny for a replay) and announce any response id
                    // not seen before, so an out-of-order or duplicated reply is reported exactly once.
                    for rid in response_ids(&buf) {
                        if announced.insert(rid) {
                            let _ = resp_id_tx.send(rid);
                        }
                    }
                }
            }
        }
        let _ = out_tx.send(buf);
    })
}

/// Read the entrypoint's stderr to EOF, returning at most [`STDERR_CAPTURE_CAP`] retained bytes (but
/// still draining the rest so a chatty process can neither exhaust memory nor block on a full pipe).
/// While reading, once the [`LS_BOOTSTRAP_READY_MARKER`] appears, signal `ready_tx` so the writer may
/// send the requests. A bounded rolling window keeps a marker split across reads detectable.
fn spawn_stderr_reader(mut stderr: ChildStderr, ready_tx: Sender<()>) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut retained = Vec::new();
        let mut window = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut signalled = false;
        loop {
            match stderr.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if retained.len() < STDERR_CAPTURE_CAP {
                        let room = STDERR_CAPTURE_CAP - retained.len();
                        retained.extend_from_slice(&chunk[..n.min(room)]);
                    }
                    if !signalled {
                        window.extend_from_slice(&chunk[..n]);
                        if String::from_utf8_lossy(&window).contains(LS_BOOTSTRAP_READY_MARKER) {
                            signalled = true;
                            let _ = ready_tx.send(());
                            window = Vec::new();
                        } else {
                            let keep = LS_BOOTSTRAP_READY_MARKER.len().saturating_sub(1);
                            if window.len() > keep {
                                window.drain(..window.len() - keep);
                            }
                        }
                    }
                }
            }
        }
        String::from_utf8_lossy(&retained).into_owned()
    })
}

/// Cold-replay `input` through the shipped `ls.core.Main` stdio entrypoint, using the SAME
/// materializer + initialize surface as the JVM fuzzing path: `pc` mode materializes under a temp
/// root and initializes there; `index` mode overlays the verified frozen backdrop and initializes at
/// the backdrop root, and response URIs lift frozen-source paths exactly like the fuzzing path. The
/// writes are staged behind a bootstrap-readiness barrier and a response barrier (see [`cold_replay`]'s
/// body) so the replay faithfully reproduces the warm in-process worker's surface. Bounded by the
/// config's timeout.
///
/// # Errors
///
/// Returns any I/O error materializing the workspace or launching the entrypoint, or an error if
/// `index` mode is requested without a backdrop root.
pub fn cold_replay(
    input: &LspInput,
    config: &ColdReplayConfig<'_>,
) -> io::Result<ReplayObservation> {
    let materializer: Box<dyn WorkspaceMaterializer> = match config.profile.mode() {
        ScalaProfileMode::PresentationCompiler => {
            Box::new(GenericTempRootMaterializer::new(config.temp_root.clone()))
        }
        ScalaProfileMode::Index => {
            let root = config.backdrop_root.clone().ok_or_else(|| {
                io::Error::other("index-mode cold replay requires a verified backdrop root")
            })?;
            Box::new(BackdropOverlayMaterializer::new(root))
        }
    };
    let placed = materializer.materialize(input)?;
    let frames = build_cold_replay_frames(
        input,
        config.profile,
        &placed.root_uri,
        &placed.localization_dir,
    );

    let mut child = Command::new(&config.program)
        .args(&config.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("no stderr"))?;

    // Drive the writes with barriers (see `spawn_request_writer`) that mirror the in-process worker's
    // steady state and per-request await; the stderr reader releases readiness, the stdout reader
    // announces each response id, both bounded by the deadline so a hung server can never hang us.
    let (ready_tx, ready_rx) = channel::<()>();
    let (resp_id_tx, resp_id_rx) = channel::<usize>();
    let writer = spawn_request_writer(stdin, frames, config.timeout, ready_rx, resp_id_rx);
    let (tx, rx) = channel();
    let reader = spawn_response_reader(stdout, resp_id_tx, tx);
    let err_reader = spawn_stderr_reader(stderr, ready_tx);

    // The server exits on `exit`, closing stdout and completing the read; if it hangs, the deadline
    // fires and we kill it (which closes the pipe and ends the reader threads).
    let (received_bytes, timed_out) = match rx.recv_timeout(config.timeout) {
        Ok(bytes) => (bytes, false),
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            (Vec::new(), true)
        }
    };
    let status = child.wait()?;
    let _ = writer.join();
    let _ = reader.join();
    let stderr_text = err_reader.join().unwrap_or_default();

    let end = if timed_out {
        ProcessEnd::TimedOut
    } else {
        match status.code() {
            Some(0) => ProcessEnd::Clean,
            Some(_) => ProcessEnd::NonZero,
            None => ProcessEnd::Signalled,
        }
    };

    let received = parse_lsp_payloads(&received_bytes);
    let backdrop_root = config.backdrop_root.as_deref().and_then(Path::to_str);
    // Match against the SAME allowlist-filtered stored requests the stream actually sent.
    let stored = cold_replay_stored_messages(input, config.profile);
    let findings = replay_findings(&stored, &received, backdrop_root);
    let outcome_class = classify_replay(end, &stderr_text, &findings);
    Ok(ReplayObservation {
        outcome_class,
        findings,
    })
}

/// The generic LSP lifecycle methods the fuzzing worker owns per epoch and never replays from the
/// input stream (cold replay likewise supplies its own).
const LIFECYCLE_METHODS: &[&str] = &["initialize", "initialized", "shutdown", "exit"];

/// Whether a message with this method is replayed to the shipped entrypoint under `profile`, mirroring
/// [`cov::LsIterationBody`]'s dispatch rule: generic lifecycle is never replayed from the input, and a
/// stored message outside the profile's method allowlist is dropped.
fn is_replayed(method: &str, profile: &ScalaExecutionProfile) -> bool {
    !LIFECYCLE_METHODS.contains(&method) && profile.allowed_methods().contains(&method)
}

/// The full cold-replay stream (handshake + every step + teardown concatenated), used by tests that
/// assert the ordered method surface and id numbering. The live path writes these parts with a
/// bootstrap-readiness barrier and a per-request response barrier between them (see
/// [`build_cold_replay_frames`] and [`cold_replay`]).
#[cfg(test)]
fn build_cold_replay_stream(
    input: &LspInput,
    profile: &ScalaExecutionProfile,
    root_uri: &str,
    localization_dir: &Path,
) -> Vec<u8> {
    let frames = build_cold_replay_frames(input, profile, root_uri, localization_dir);
    let mut stream = frames.initialize;
    stream.extend(frames.initialized);
    for step in &frames.steps {
        stream.extend_from_slice(step.bytes());
    }
    stream.extend(frames.teardown);
    stream
}

/// The id of the profile-supplied `initialize` request cold replay sends (the worker's initialize is
/// likewise id 0). The first sent stored request is id 1, matching [`RequestResponseMatching`].
const COLD_REPLAY_INITIALIZE_ID: usize = 0;

/// The log line the shipped LS prints (to stderr) once its BSP/index bootstrap has finished and it
/// will serve real per-request outcomes. This is the readiness gate a compliant client waits on after
/// `initialized` and before any query — until it appears, a request is rejected with a spurious
/// `-32803 "workspace is not ready: waiting for the initialized notification"` rather than the genuine
/// outcome, so cold replay MUST wait for it too or it would never match a real finding produced by the
/// (warm, long-since-bootstrapped) in-process worker.
const LS_BOOTSTRAP_READY_MARKER: &str = "bootstrap finished: ready";

/// One frame the driver replays after the handshake. A request must be awaited before the next frame
/// is sent (mirroring the worker's `requestAndWait`); a notification is fire-and-forget.
#[derive(Debug)]
enum ReplayStep {
    /// A notification (e.g. `textDocument/didOpen`) — write and move on, no response is expected.
    Notification(Vec<u8>),
    /// A request — write it, then wait for the response with this exact `id` before the next frame.
    Request { id: usize, bytes: Vec<u8> },
}

impl ReplayStep {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Notification(b) | Self::Request { bytes: b, .. } => b,
        }
    }
}

/// The parts of a cold-replay stream, written with barriers between them (see [`cold_replay`]).
struct ColdReplayFrames {
    /// `initialize` (id 0), sent first and AWAITED (its response) before `initialized` — a server may
    /// otherwise receive `initialized` before it has answered `initialize`, unlike the warm worker's
    /// `ensureInitialized`.
    initialize: Vec<u8>,
    /// `initialized`, sent only after the `initialize` response. In index mode this kicks off the
    /// async BSP/index bootstrap whose readiness is then awaited on stderr.
    initialized: Vec<u8>,
    /// The filtered didOpens + stored requests in input order, replayed AFTER the server signals
    /// readiness. Requests are sent one at a time and each is awaited before the next frame, exactly
    /// like [`cov::LsIterationBody`]'s per-request `requestAndWait` loop.
    steps: Vec<ReplayStep>,
    /// `shutdown` + `exit`, sent only after every request step has been answered (or the deadline
    /// expired) — the worker never tears the server down mid-request, so tearing down while a request
    /// is still in flight would drop its response and lose the finding.
    teardown: Vec<u8>,
    /// Whether to wait for the BSP/index bootstrap readiness marker on stderr before replaying steps.
    /// Only index mode brings up the async BSP/index (whose readiness the server logs); a PC-mode
    /// server never prints that marker, so PC mode must NOT wait for it (else the whole deadline is
    /// spent waiting and the run is misclassified as a timeout). PC readiness is the `initialize`
    /// response instead (awaited via the response barrier).
    wait_for_bsp_ready: bool,
}

/// Split the cold-replay stream into [`ColdReplayFrames`] so the driver can stage the writes: send the
/// handshake, WAIT for bootstrap readiness ([`LS_BOOTSTRAP_READY_MARKER`]), replay each step (awaiting
/// every request's exact response before the next frame), then send `shutdown`/`exit`. This reproduces
/// the steady state AND the request-by-request await the persistent in-process worker uses (it emits
/// `initialized` once per epoch and never sends `shutdown`/`exit` per input). Concatenating the parts
/// reproduces the previous single stream byte-for-byte (same ordering, same id numbering: initialize is
/// id 0, the first sent stored request is id 1), so response matching is unaffected; only the write
/// *timing* changes.
fn build_cold_replay_frames(
    input: &LspInput,
    profile: &ScalaExecutionProfile,
    root_uri: &str,
    localization_dir: &Path,
) -> ColdReplayFrames {
    let localize_uri = uri::workspace_uri(localization_dir)
        .map(|p| format!("file://{p}"))
        .unwrap_or_default();
    let mut id = COLD_REPLAY_INITIALIZE_ID;
    // The handshake, split so the driver can await the `initialize` response before sending
    // `initialized` (mirroring the warm worker's `ensureInitialized`): the profile-supplied
    // initialize (id 0), then the initialized notification.
    let initialize =
        JsonRPCMessage::request(id, "initialize".into(), profile.initialize_params(root_uri))
            .to_lsp_payload();
    id += 1;
    let initialized =
        JsonRPCMessage::notification("initialized".into(), serde_json::json!({})).to_lsp_payload();
    // The steps: generated didOpens + stored messages (filtered by the profile allowlist like the
    // worker), in input order. Each is a request (awaited by id) or a notification (fire-and-forget).
    // Track the documents opened but not closed, so we can replay the warm worker's end-of-run
    // `didClose` cleanup below (a crash/logged-fatal/coverage during that cleanup is attributed to the
    // input, so cold replay must exercise it too or such findings look non-reproducible).
    let mut steps = Vec::new();
    let mut open_docs: Vec<String> = Vec::new();
    for msg in input.message_sequence() {
        if !is_replayed(msg.method(), profile) {
            continue;
        }
        let before = id;
        let message = msg.into_json_rpc(&mut id, Some(&localize_uri));
        if let JsonRPCMessage::Notification { method, params, .. } = &message {
            match method.as_ref() {
                "textDocument/didOpen" => {
                    if let Some(uri) = document_uri(params)
                        && !open_docs.contains(&uri)
                    {
                        open_docs.push(uri);
                    }
                }
                "textDocument/didClose" => {
                    if let Some(uri) = document_uri(params) {
                        open_docs.retain(|u| u != &uri);
                    }
                }
                _ => {}
            }
        }
        let bytes = message.to_lsp_payload();
        // `into_json_rpc` consumed `before` as a request's id and advanced `id`; a notification did not.
        steps.push(match message {
            JsonRPCMessage::Request { .. } => ReplayStep::Request { id: before, bytes },
            _ => ReplayStep::Notification(bytes),
        });
    }
    // Mirror the warm worker's end-of-run cleanup: close every still-open document (in open order)
    // before teardown, so a finding that only manifests during `didClose` reproduces here too.
    for uri in &open_docs {
        let close = JsonRPCMessage::notification(
            "textDocument/didClose".into(),
            serde_json::json!({ "textDocument": { "uri": uri } }),
        )
        .to_lsp_payload();
        steps.push(ReplayStep::Notification(close));
    }
    // The teardown: a graceful shutdown/exit, sent only after every request step has been answered.
    let mut teardown =
        JsonRPCMessage::request(id, "shutdown".into(), serde_json::Value::Null).to_lsp_payload();
    teardown.extend(
        JsonRPCMessage::notification("exit".into(), serde_json::Value::Null).to_lsp_payload(),
    );
    ColdReplayFrames {
        initialize,
        initialized,
        steps,
        teardown,
        // Only index mode brings up the async BSP/index bootstrap whose readiness the server logs.
        wait_for_bsp_ready: profile.mode() == ScalaProfileMode::Index,
    }
}

/// The numeric response ids present in `bytes` (a stdout prefix), in occurrence order — used by the
/// reader to announce each newly-seen response so the writer can await a specific request's reply.
fn response_ids(bytes: &[u8]) -> Vec<usize> {
    parse_lsp_payloads(bytes)
        .iter()
        .filter_map(|m| match m {
            JsonRPCMessage::Response {
                id: Some(MessageId::Number(rid)),
                ..
            } => Some(*rid),
            _ => None,
        })
        .collect()
}

/// The stored input messages that cold replay actually sends (dropping lifecycle + methods outside
/// the profile allowlist), in input order — the list the response matching is run against, so a
/// dropped stored request is never expected in the replay responses.
fn cold_replay_stored_messages(
    input: &LspInput,
    profile: &ScalaExecutionProfile,
) -> Vec<crate::lsp::LspMessage> {
    input
        .messages
        .iter()
        .filter(|m| is_replayed(m.method(), profile))
        .cloned()
        .collect()
}

/// The `textDocument.uri` of a `didOpen`/`didClose` notification's params, if present — used to track
/// which documents the replayed sequence leaves open so cold replay can mirror the warm worker's
/// end-of-run `didClose` cleanup.
fn document_uri(params: &serde_json::Value) -> Option<String> {
    params
        .get("textDocument")?
        .get("uri")?
        .as_str()
        .map(ToString::to_string)
}

/// Parse every complete `Content-Length`-framed LSP payload from `bytes` (stopping at the first
/// incomplete/garbled frame).
fn parse_lsp_payloads(bytes: &[u8]) -> Vec<JsonRPCMessage> {
    let mut cursor = Cursor::new(bytes);
    let mut messages = Vec::new();
    while let Ok(message) = JsonRPCMessage::read_lsp_payload(&mut cursor) {
        messages.push(message);
    }
    messages
}

/// Derive the JSON-RPC error findings from a replay's received messages, matching them against the
/// SAME filtered stored requests that were actually sent (`stored`), with the same 1-based
/// stored-request numbering as the native path so a dropped request is never expected. `backdrop_root`
/// (index mode) scopes frozen-source URI lifting exactly like the fuzzing path.
fn replay_findings(
    stored: &[crate::lsp::LspMessage],
    received: &[JsonRPCMessage],
    backdrop_root: Option<&str>,
) -> FindingSet {
    match RequestResponseMatching::match_messages(stored.iter(), received.iter(), backdrop_root) {
        Ok(matching) => {
            findings_from_json_rpc_errors(matching.errors.iter().map(|(m, e)| (m.method(), e)))
        }
        Err(_) => FindingSet::new(),
    }
}

/// A `LibAFL` feedback that exports a [`FindingBundle`] for every finding run, reading the executor's
/// [`JvmOutcomeObserver`] immediately after the execution (so it never depends on stale last-run
/// state that a later execution has overwritten). It contributes no novelty (`is_interesting` always
/// returns `false`); the export is a side effect. Export is fail-closed: a finding whose provenance
/// is incomplete is logged and skipped, not written as a confirmed finding.
#[derive(Debug)]
pub struct JvmFindingExportFeedback {
    observer_handle: Handle<JvmOutcomeObserver>,
    provenance: Provenance,
    output_dir: PathBuf,
}

impl JvmFindingExportFeedback {
    /// Build the feedback over the executor's outcome observer, tagging exported bundles with
    /// `provenance` and writing them under `output_dir`.
    #[must_use]
    pub fn new(observer: &JvmOutcomeObserver, provenance: Provenance, output_dir: PathBuf) -> Self {
        Self {
            observer_handle: observer.handle(),
            provenance,
            output_dir,
        }
    }
}

impl Named for JvmFindingExportFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("JvmFindingExport");
        &NAME
    }
}

impl<State> StateInitializer<State> for JvmFindingExportFeedback {}

impl<EM, Observers, State> Feedback<EM, LspInput, Observers, State> for JvmFindingExportFeedback
where
    State: HasMetadata + HasExecutions + HasCorpus<LspInput>,
    Observers: MatchNameRef,
    EM: EventFirer<LspInput, State>,
{
    fn is_interesting(
        &mut self,
        _state: &mut State,
        _manager: &mut EM,
        input: &LspInput,
        observers: &Observers,
        _exit_kind: &ExitKind,
    ) -> Result<bool, libafl::Error> {
        if let Some(observer) = observers.get(&self.observer_handle)
            && let Some(class) = observer.last_outcome()
            && should_export(class, observer.findings())
        {
            match FindingBundle::build(
                input.clone(),
                class,
                observer.findings().clone(),
                self.provenance.clone(),
            ) {
                Ok(bundle) => {
                    if let Err(e) = bundle.write_to(&self.output_dir) {
                        warn!("failed to write finding bundle: {e}");
                    }
                }
                Err(missing) => {
                    warn!("finding not exported (incomplete provenance): {missing}");
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;

    fn pc_provenance() -> Provenance {
        Provenance {
            scala_profile_mode: "pc".to_string(),
            run_timeout_ms: 30_000,
            ls_commit: Some("abc123".to_string()),
            ls_classpath_hash: Some("cp-hash".to_string()),
            jdk_flags: vec!["-XX:-UseCompactObjectHeaders".to_string()],
            agent_version: Some("agent-1".to_string()),
            agent_config: Some("asm-9.8".to_string()),
            backdrop_commit: None,
            backdrop_snapshot_hash: None,
            semanticdb_hash: None,
            bsp_hash: None,
            sqlite_artifact_hash: None,
        }
    }

    fn index_provenance() -> Provenance {
        Provenance {
            scala_profile_mode: "index".to_string(),
            backdrop_commit: Some("fefb58e9".to_string()),
            backdrop_snapshot_hash: Some("snap-hash".to_string()),
            semanticdb_hash: Some("sdb-hash".to_string()),
            bsp_hash: Some("bsp-hash".to_string()),
            sqlite_artifact_hash: Some("sqlite-hash".to_string()),
            ..pc_provenance()
        }
    }

    #[test]
    fn complete_provenance_is_accepted() {
        assert!(pc_provenance().validate().is_ok());
        assert!(index_provenance().validate().is_ok());
        let bundle = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            pc_provenance(),
        )
        .expect("complete provenance builds");
        // A freshly built bundle is not yet confirmed through the shipped entrypoint.
        assert_eq!(bundle.replayability, Replayability::InProcessHarnessOnly);
    }

    #[test]
    fn missing_required_provenance_is_rejected() {
        // Each always-required field rejects when absent, in pc mode.
        for clear in [
            "ls_commit",
            "ls_classpath_hash",
            "agent_version",
            "agent_config",
            "jdk_flags",
        ] {
            let mut prov = pc_provenance();
            match clear {
                "ls_commit" => prov.ls_commit = None,
                "ls_classpath_hash" => prov.ls_classpath_hash = None,
                "agent_version" => prov.agent_version = None,
                "agent_config" => prov.agent_config = None,
                "jdk_flags" => prov.jdk_flags.clear(),
                _ => unreachable!(),
            }
            let err = prov.validate().unwrap_err();
            assert!(err.missing.contains(&clear), "{clear} should be required");
            assert!(
                FindingBundle::build(
                    LspInput::default(),
                    OutcomeClass::JsonRpcError,
                    FindingSet::new(),
                    prov,
                )
                .is_err()
            );
        }

        // An empty agent_config is treated the same as a missing one.
        let mut prov = pc_provenance();
        prov.agent_config = Some(String::new());
        assert!(
            prov.validate()
                .unwrap_err()
                .missing
                .contains(&"agent_config")
        );

        // An unknown profile mode is rejected (it could otherwise bypass index-mode requirements).
        let mut prov = pc_provenance();
        prov.scala_profile_mode = "bogus".to_string();
        assert!(
            prov.validate()
                .unwrap_err()
                .missing
                .contains(&"scala_profile_mode")
        );

        // Index mode additionally requires all backdrop + SemanticDB + BSP + native SQLite fields.
        for clear in [
            "backdrop_commit",
            "backdrop_snapshot_hash",
            "semanticdb_hash",
            "bsp_hash",
            "sqlite_artifact_hash",
        ] {
            let mut prov = index_provenance();
            match clear {
                "backdrop_commit" => prov.backdrop_commit = None,
                "backdrop_snapshot_hash" => prov.backdrop_snapshot_hash = None,
                "semanticdb_hash" => prov.semanticdb_hash = None,
                "bsp_hash" => prov.bsp_hash = None,
                "sqlite_artifact_hash" => prov.sqlite_artifact_hash = None,
                _ => unreachable!(),
            }
            assert!(
                prov.validate().unwrap_err().missing.contains(&clear),
                "{clear} should be required in index mode"
            );
        }
        // None of those index-only fields are required in pc mode.
        assert!(pc_provenance().validate().is_ok());
    }

    #[test]
    fn should_export_only_findings() {
        assert!(should_export(OutcomeClass::JvmFatal, &FindingSet::new()));
        assert!(should_export(
            OutcomeClass::JsonRpcError,
            &FindingSet::new()
        ));
        assert!(!should_export(
            OutcomeClass::NormalSuccess,
            &FindingSet::new()
        ));
        assert!(!should_export(
            OutcomeClass::ExpectedCancellation,
            &FindingSet::new()
        ));
        // A non-empty finding set exports even on an otherwise-clean class.
        let mut set = FindingSet::new();
        set.record(Finding::json_rpc_error(
            "textDocument/hover",
            -32603,
            "boom",
        ));
        assert!(should_export(OutcomeClass::NormalSuccess, &set));
    }

    #[test]
    fn equivalence_requires_same_class_and_findings() {
        let mut findings = FindingSet::new();
        findings.record(Finding::json_rpc_error(
            "textDocument/hover",
            -32603,
            "boom at line 5",
        ));
        let bundle = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::JsonRpcError,
            findings.clone(),
            pc_provenance(),
        )
        .unwrap();

        // Same class + the bundle's finding reproduced (numbers normalized) → equivalent.
        let mut replayed = FindingSet::new();
        replayed.record(Finding::json_rpc_error(
            "textDocument/hover",
            -32603,
            "boom at line 42",
        ));
        assert!(check_equivalence(
            &bundle,
            &ReplayObservation {
                outcome_class: OutcomeClass::JsonRpcError,
                findings: replayed,
            }
        ));

        // A different class is not equivalent.
        assert!(!check_equivalence(
            &bundle,
            &ReplayObservation {
                outcome_class: OutcomeClass::NormalSuccess,
                findings: findings.clone(),
            }
        ));

        // A missing finding is not equivalent.
        assert!(!check_equivalence(
            &bundle,
            &ReplayObservation {
                outcome_class: OutcomeClass::JsonRpcError,
                findings: FindingSet::new(),
            }
        ));
    }

    #[test]
    fn confirm_leaves_harness_only_on_mismatch() {
        // Without a real shipped entrypoint we cannot confirm; a bundle whose replay does not match
        // stays in-process-harness-only. (The live path is exercised by the gated test below.)
        let bundle = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            pc_provenance(),
        )
        .unwrap();
        assert_eq!(bundle.replayability, Replayability::InProcessHarnessOnly);
    }

    #[test]
    fn classify_replay_covers_each_case() {
        let empty = FindingSet::new();
        let mut errs = FindingSet::new();
        errs.record(Finding::json_rpc_error("m", -1, "e"));
        // A hang is a timeout.
        assert_eq!(
            classify_replay(ProcessEnd::TimedOut, "", &empty),
            OutcomeClass::TimeoutOrDeadlock
        );
        // Memory exhaustion from stderr, whatever the exit.
        assert_eq!(
            classify_replay(ProcessEnd::NonZero, "java.lang.OutOfMemoryError", &empty),
            OutcomeClass::OutOfMemoryOrStackOverflow
        );
        assert_eq!(
            classify_replay(
                ProcessEnd::Signalled,
                "java.lang.StackOverflowError",
                &empty
            ),
            OutcomeClass::OutOfMemoryOrStackOverflow
        );
        // Uncaught exceptions: foreground vs background by thread.
        assert_eq!(
            classify_replay(
                ProcessEnd::NonZero,
                "Exception in thread \"main\" x",
                &empty
            ),
            OutcomeClass::ForegroundException
        );
        assert_eq!(
            classify_replay(
                ProcessEnd::NonZero,
                "Exception in thread \"pool-1\" x",
                &empty
            ),
            OutcomeClass::BackgroundException
        );
        // A fatal-log line.
        assert_eq!(
            classify_replay(ProcessEnd::NonZero, "FATAL boom", &empty),
            OutcomeClass::LoggedFatal
        );
        // A non-zero exit or a signal with no clearer evidence is a hard JVM fatal.
        assert_eq!(
            classify_replay(ProcessEnd::NonZero, "", &empty),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            classify_replay(ProcessEnd::Signalled, "", &empty),
            OutcomeClass::JvmFatal
        );
        // A clean exit: JSON-RPC errors are findings, otherwise a normal success.
        assert_eq!(
            classify_replay(ProcessEnd::Clean, "", &errs),
            OutcomeClass::JsonRpcError
        );
        assert_eq!(
            classify_replay(ProcessEnd::Clean, "", &empty),
            OutcomeClass::NormalSuccess
        );
    }

    // Run a cold replay against a small shell script (no real LS) to exercise the process-end +
    // stderr classification end to end.
    fn replay_script(script: &str, timeout: Duration) -> OutcomeClass {
        let profile = ScalaExecutionProfile::presentation_compiler();
        let temp = tempfile::tempdir().unwrap();
        // PC replay waits for the `initialize` response (id 0), not the BSP stderr marker, so the
        // fake server must emit that framed response first (a real PC server does). Its `{}` result
        // triggers no classification rule, so it does not affect what the script tests.
        let init_response =
            JsonRPCMessage::response(Some(0usize), Some(serde_json::json!({})), None)
                .to_lsp_payload();
        let resp_file = temp.path().join("init-response.bin");
        std::fs::write(&resp_file, &init_response).unwrap();
        let script = format!("cat {}; {}", resp_file.display(), script);
        let config = ColdReplayConfig {
            profile: &profile,
            program: "sh".to_string(),
            args: vec!["-c".to_string(), script],
            temp_root: temp.path().to_path_buf(),
            backdrop_root: None,
            timeout,
        };
        cold_replay(&LspInput::default(), &config)
            .expect("cold replay launches the script")
            .outcome_class
    }

    #[test]
    fn cold_replay_classifies_process_failures_from_stderr_and_exit() {
        let t = Duration::from_secs(5);
        assert_eq!(
            replay_script("cat >/dev/null; exit 0", t),
            OutcomeClass::NormalSuccess
        );
        assert_eq!(
            replay_script("cat >/dev/null; exit 3", t),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            replay_script(
                "cat >/dev/null; echo 'java.lang.OutOfMemoryError: Java heap space' >&2; exit 1",
                t
            ),
            OutcomeClass::OutOfMemoryOrStackOverflow
        );
        assert_eq!(
            replay_script(
                "cat >/dev/null; echo 'Exception in thread \"main\" java.lang.NullPointerException' >&2; exit 1",
                t
            ),
            OutcomeClass::ForegroundException
        );
        assert_eq!(
            replay_script(
                "cat >/dev/null; echo 'Exception in thread \"pool-1-thread-2\" java.lang.IllegalStateException' >&2; exit 1",
                t
            ),
            OutcomeClass::BackgroundException
        );
        assert_eq!(
            replay_script(
                "cat >/dev/null; echo 'FATAL: server aborting' >&2; exit 1",
                t
            ),
            OutcomeClass::LoggedFatal
        );
        // A hang is killed at the deadline and classed as a timeout.
        assert_eq!(
            replay_script("cat >/dev/null; sleep 30", Duration::from_millis(400)),
            OutcomeClass::TimeoutOrDeadlock
        );
    }

    // Stderr well beyond the cap does not blow up the driver, and only the retained prefix classifies:
    // a `FATAL` marker written AFTER the cap is dropped (so a hard JVM fatal, not a logged fatal),
    // proving truncation; a marker WITHIN the cap still classifies.
    #[test]
    fn cold_replay_bounds_stderr_capture() {
        let t = Duration::from_secs(10);
        // ~70 KiB of 'x' (> 64 KiB cap), then a late FATAL beyond the cap.
        assert_eq!(
            replay_script(
                "cat >/dev/null; head -c 70000 /dev/zero | tr '\\0' 'x' >&2; echo 'FATAL late' >&2; exit 1",
                t
            ),
            OutcomeClass::JvmFatal,
            "a FATAL emitted past the cap must be truncated away, not classified"
        );
        // The same marker within the retained prefix is still classified.
        assert_eq!(
            replay_script(
                "cat >/dev/null; echo 'FATAL early' >&2; head -c 70000 /dev/zero | tr '\\0' 'x' >&2; exit 1",
                t
            ),
            OutcomeClass::LoggedFatal
        );
    }

    fn request(method: &str, params: serde_json::Value) -> crate::lsp::LspMessage {
        crate::lsp::LspMessage::try_from_json(method, params).unwrap()
    }

    fn position_params(uri: &str) -> serde_json::Value {
        serde_json::json!({
            "textDocument": { "uri": uri },
            "position": { "line": 0, "character": 0 },
        })
    }

    // The methods actually sent to the entrypoint, in order, from a built cold-replay stream.
    fn replayed_methods(input: &LspInput, profile: &ScalaExecutionProfile) -> Vec<(String, bool)> {
        let dir = tempfile::tempdir().unwrap();
        let stream = build_cold_replay_stream(input, profile, "file:///root", dir.path());
        parse_lsp_payloads(&stream)
            .iter()
            .map(|m| match m {
                JsonRPCMessage::Request { method, .. } => (method.to_string(), true),
                JsonRPCMessage::Notification { method, .. } => (method.to_string(), false),
                JsonRPCMessage::Response { .. } => ("<response>".to_string(), false),
            })
            .collect()
    }

    #[test]
    fn cold_replay_drops_disallowed_stored_requests_pc_mode() {
        // A pc-mode input carrying an index-only stored request (workspace/symbol) alongside an
        // allowed hover: cold replay must send hover but drop workspace/symbol.
        let mut input = LspInput::default();
        input.messages.push(request(
            "textDocument/hover",
            position_params("lsp-fuzz://a.scala"),
        ));
        input.messages.push(request(
            "workspace/symbol",
            serde_json::json!({ "query": "x" }),
        ));
        let methods = replayed_methods(&input, &ScalaExecutionProfile::presentation_compiler());
        assert!(
            !methods.iter().any(|(m, _)| m == "workspace/symbol"),
            "an index-only request must not reach the entrypoint in pc mode: {methods:?}"
        );
        assert!(
            methods
                .iter()
                .any(|(m, is_req)| m == "textDocument/hover" && *is_req)
        );
    }

    #[test]
    fn cold_replay_drops_disallowed_stored_requests_index_mode() {
        // An index-mode input carrying a pc-only stored request (textDocument/completion) alongside
        // an allowed references: cold replay must send references but drop completion.
        let mut input = LspInput::default();
        input.messages.push(request("textDocument/references", {
            let mut p = position_params("lsp-fuzz://a.scala");
            p["context"] = serde_json::json!({ "includeDeclaration": true });
            p
        }));
        input.messages.push(request(
            "textDocument/completion",
            position_params("lsp-fuzz://a.scala"),
        ));
        let methods = replayed_methods(&input, &ScalaExecutionProfile::index());
        assert!(
            !methods.iter().any(|(m, _)| m == "textDocument/completion"),
            "a pc-only request must not reach the entrypoint in index mode: {methods:?}"
        );
        assert!(
            methods
                .iter()
                .any(|(m, is_req)| m == "textDocument/references" && *is_req)
        );
    }

    // The single method + kind (`true` = request awaited by id) carried by a replay step.
    fn step_method(step: &ReplayStep) -> (String, bool) {
        let m = parse_lsp_payloads(step.bytes()).into_iter().next().unwrap();
        match (m, step) {
            (JsonRPCMessage::Request { method, .. }, ReplayStep::Request { .. }) => {
                (method.to_string(), true)
            }
            (JsonRPCMessage::Notification { method, .. }, ReplayStep::Notification(_)) => {
                (method.to_string(), false)
            }
            other => panic!("step bytes / variant mismatch: {other:?}"),
        }
    }

    #[test]
    fn cold_replay_frames_split_handshake_steps_teardown() {
        // The frames must isolate the handshake (initialize + initialized) from the ordered replay
        // steps and the teardown (shutdown + exit), and mark the stored request as an awaited Request
        // carrying its id so the driver can wait for that exact response before the next frame.
        let mut input = LspInput::default();
        input.messages.push(request("textDocument/references", {
            let mut p = position_params("lsp-fuzz://a.scala");
            p["context"] = serde_json::json!({ "includeDeclaration": true });
            p
        }));
        let profile = ScalaExecutionProfile::index();
        let dir = tempfile::tempdir().unwrap();
        let frames = build_cold_replay_frames(&input, &profile, "file:///root", dir.path());

        let methods = |bytes: &[u8]| {
            parse_lsp_payloads(bytes)
                .iter()
                .filter_map(|m| match m {
                    JsonRPCMessage::Request { method, .. }
                    | JsonRPCMessage::Notification { method, .. } => Some(method.to_string()),
                    JsonRPCMessage::Response { .. } => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(methods(&frames.initialize), vec!["initialize"]);
        assert_eq!(methods(&frames.initialized), vec!["initialized"]);
        assert_eq!(methods(&frames.teardown), vec!["shutdown", "exit"]);
        // One replay step: the references request, awaited, with id 1 (initialize consumed id 0).
        assert_eq!(frames.steps.len(), 1);
        assert_eq!(
            step_method(&frames.steps[0]),
            ("textDocument/references".to_string(), true)
        );
        assert!(matches!(frames.steps[0], ReplayStep::Request { id: 1, .. }));
    }

    /// An input with a source file is auto-`didOpen`ed; cold replay must mirror the warm worker's
    /// end-of-run cleanup by emitting a `didClose` for it (with the SAME localized URI) after the
    /// steps and before teardown, so a finding that only manifests during cleanup reproduces.
    #[test]
    fn cold_replay_closes_opened_documents_before_teardown() {
        use crate::{
            file_system::{FileSystemDirectory, FileSystemEntry},
            lsp_input::{WorkspaceEntry, messages::LspMessageSequence},
            text_document::TextDocument,
            utf8::Utf8Input,
        };
        use lsp_fuzz_grammars::Language;

        let mut doc = TextDocument::new(Language::Scala, "object A:\n  def x = 1\n".into());
        doc.update_metadata();
        let input = LspInput {
            messages: LspMessageSequence::default(),
            workspace: FileSystemDirectory::from([(
                Utf8Input::new("main.scala".to_owned()),
                FileSystemEntry::File(WorkspaceEntry::SourceFile(doc)),
            )]),
        };
        let profile = ScalaExecutionProfile::presentation_compiler();
        let dir = tempfile::tempdir().unwrap();
        let stream = build_cold_replay_stream(&input, &profile, "file:///root", dir.path());
        let msgs = parse_lsp_payloads(&stream);
        let method_order: Vec<String> = msgs
            .iter()
            .filter_map(|m| match m {
                JsonRPCMessage::Request { method, .. }
                | JsonRPCMessage::Notification { method, .. } => Some(method.to_string()),
                JsonRPCMessage::Response { .. } => None,
            })
            .collect();

        let open_at = method_order
            .iter()
            .position(|m| m == "textDocument/didOpen")
            .expect("the source file is opened");
        let close_at = method_order
            .iter()
            .position(|m| m == "textDocument/didClose")
            .expect("the opened document is closed before teardown");
        let shutdown_at = method_order
            .iter()
            .position(|m| m == "shutdown")
            .expect("teardown present");
        assert!(
            open_at < close_at && close_at < shutdown_at,
            "expected didOpen < didClose < shutdown, got {method_order:?}"
        );

        // The didClose targets the SAME localized URI the didOpen used (so the server closes the doc
        // it opened, exactly like the warm worker).
        let open_uri = msgs.iter().find_map(|m| match m {
            JsonRPCMessage::Notification { method, params, .. }
                if method == "textDocument/didOpen" =>
            {
                document_uri(params)
            }
            _ => None,
        });
        let close_uri = msgs.iter().find_map(|m| match m {
            JsonRPCMessage::Notification { method, params, .. }
                if method == "textDocument/didClose" =>
            {
                document_uri(params)
            }
            _ => None,
        });
        assert!(
            open_uri.is_some() && open_uri == close_uri,
            "close must target the opened URI"
        );
    }

    /// Only index mode brings up the async BSP/index bootstrap whose readiness the server logs, so
    /// only index frames wait for it. A PC-mode server never prints the marker; waiting for it would
    /// spend the entire replay deadline and misclassify the run as a timeout.
    #[test]
    fn only_index_frames_wait_for_bsp_readiness() {
        let dir = tempfile::tempdir().unwrap();
        let pc = build_cold_replay_frames(
            &LspInput::default(),
            &ScalaExecutionProfile::presentation_compiler(),
            "file:///root",
            dir.path(),
        );
        let index = build_cold_replay_frames(
            &LspInput::default(),
            &ScalaExecutionProfile::index(),
            "file:///root",
            dir.path(),
        );
        assert!(
            !pc.wait_for_bsp_ready,
            "PC replay must not wait for the BSP readiness marker"
        );
        assert!(
            index.wait_for_bsp_ready,
            "index replay must wait for the BSP readiness marker"
        );
    }

    #[test]
    fn response_ids_extracts_only_numeric_response_ids_in_order() {
        let mut bytes = JsonRPCMessage::response(Some(2usize), None, None).to_lsp_payload();
        bytes.extend(
            JsonRPCMessage::response(Some(1usize), Some(serde_json::json!({})), None)
                .to_lsp_payload(),
        );
        // A request (has an id but is not a Response) must not be reported as a response id.
        bytes.extend(
            JsonRPCMessage::request(9usize, "x".into(), serde_json::Value::Null).to_lsp_payload(),
        );
        assert_eq!(response_ids(&bytes), vec![2, 1]);
    }

    #[test]
    fn cold_replay_frames_have_no_request_step_when_all_dropped() {
        // An index-mode input carrying only a pc-only request (completion) has it dropped, so there is
        // no request step to await — the driver tears down right after readiness.
        let mut input = LspInput::default();
        input.messages.push(request(
            "textDocument/completion",
            position_params("lsp-fuzz://a.scala"),
        ));
        let profile = ScalaExecutionProfile::index();
        let dir = tempfile::tempdir().unwrap();
        let frames = build_cold_replay_frames(&input, &profile, "file:///root", dir.path());
        assert!(
            !frames
                .steps
                .iter()
                .any(|s| matches!(s, ReplayStep::Request { .. }))
        );
    }

    /// A `Write` that records into a shared buffer the test can inspect while the driver runs.
    #[derive(Clone)]
    struct RecordingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The request ids and lifecycle methods present in `bytes`, in occurrence order — used to assert
    /// exactly what the driver has written so far.
    fn written_requests(bytes: &[u8]) -> Vec<(String, Option<usize>)> {
        parse_lsp_payloads(bytes)
            .into_iter()
            .filter_map(|m| match m {
                JsonRPCMessage::Request {
                    method,
                    id: MessageId::Number(n),
                    ..
                } => Some((method.to_string(), Some(n))),
                JsonRPCMessage::Notification { method, .. } => Some((method.to_string(), None)),
                _ => None,
            })
            .collect()
    }

    /// Deterministic regression against a batched cold-replay writer, observing the WRITE STREAM (stdin)
    /// directly: [`drive_replay_writes`] runs on a background thread against a recording writer while
    /// the test hand-drives the readiness/response channels, and asserts the exact frames written at
    /// each step. It proves the driver sends one request at a time and awaits that request's response
    /// before the next frame — so it FAILS if requests are batched after readiness or if teardown is
    /// sent after only the highest response id is observed.
    #[test]
    fn drive_replay_writes_sends_one_request_at_a_time_and_gates_teardown() {
        let mut input = LspInput::default();
        // Two pc-allowed requests → ids 1 (hover) and 2 (definition) in input order.
        input.messages.push(request(
            "textDocument/hover",
            position_params("lsp-fuzz://a.scala"),
        ));
        input.messages.push(request(
            "textDocument/definition",
            position_params("lsp-fuzz://a.scala"),
        ));
        let profile = ScalaExecutionProfile::presentation_compiler();
        let dir = tempfile::tempdir().unwrap();
        let frames = build_cold_replay_frames(&input, &profile, "file:///root", dir.path());

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writer = RecordingWriter(buf.clone());
        // PC mode does not wait for the BSP stderr marker, so `ready_tx` stays unused here; PC
        // readiness is the `initialize` response (id 0), delivered on `resp_tx` below.
        let (_ready_tx, ready_rx) = channel::<()>();
        let (resp_tx, resp_rx) = channel::<usize>();
        let driver = std::thread::spawn(move || {
            drive_replay_writes(
                &mut writer,
                &frames,
                Duration::from_secs(10),
                &ready_rx,
                &resp_rx,
            );
        });

        // Poll the shared buffer until `pred` holds, or panic after a bounded wait.
        let wait_until = |pred: &dyn Fn(&[(String, Option<usize>)]) -> bool, what: &str| {
            for _ in 0..400 {
                if pred(&written_requests(&buf.lock().unwrap())) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!(
                "timed out waiting for: {what}\ngot: {:?}",
                written_requests(&buf.lock().unwrap())
            );
        };
        let has = |v: &[(String, Option<usize>)], m: &str, id: Option<usize>| {
            v.iter().any(|(mm, ii)| mm == m && *ii == id)
        };

        // (a) The driver writes `initialize` and BLOCKS awaiting its response (id 0) before
        //     `initialized` — so `initialized` and any request must be ABSENT until id 0 is delivered.
        wait_until(&|v| has(v, "initialize", Some(0)), "initialize written");
        std::thread::sleep(Duration::from_millis(30));
        {
            let v = written_requests(&buf.lock().unwrap());
            assert!(
                !has(&v, "initialized", None),
                "initialized must not be sent before the initialize response: {v:?}"
            );
            assert!(
                !v.iter().any(|(m, _)| m.starts_with("textDocument/")),
                "no request may be sent before initialize is answered: {v:?}"
            );
        }

        // (b) After the initialize response (id 0), the driver writes `initialized`, then ONLY request
        //     id 1, and blocks awaiting its response — request id 2 and shutdown/exit must be absent.
        resp_tx.send(0).unwrap();
        wait_until(
            &|v| has(v, "initialized", None) && has(v, "textDocument/hover", Some(1)),
            "initialized + request id 1 written",
        );
        {
            let v = written_requests(&buf.lock().unwrap());
            assert!(
                !has(&v, "textDocument/definition", Some(2)),
                "req 2 must wait for req 1's response: {v:?}"
            );
            assert!(
                !has(&v, "shutdown", Some(3)),
                "teardown must not precede req 1's response: {v:?}"
            );
        }

        // (c) Deliver response id 2 EARLY (id 1 still outstanding). The driver is awaiting id 1, so it
        //     must NOT advance: request id 2 and shutdown/exit stay absent.
        resp_tx.send(2).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        {
            let v = written_requests(&buf.lock().unwrap());
            assert!(
                !has(&v, "textDocument/definition", Some(2)) && !has(&v, "shutdown", Some(3)),
                "an early response for a LATER request must not release an earlier await: {v:?}"
            );
        }

        // (d) Deliver response id 1. The driver writes request id 2; its id 2 is already seen, so
        //     teardown proceeds — shutdown/exit are written.
        resp_tx.send(1).unwrap();
        wait_until(
            &|v| has(v, "shutdown", Some(3)),
            "teardown written after both requests",
        );
        {
            let v = written_requests(&buf.lock().unwrap());
            assert!(
                has(&v, "textDocument/definition", Some(2)),
                "req 2 must be written after req 1 replied: {v:?}"
            );
            assert!(has(&v, "exit", None), "exit follows shutdown: {v:?}");
        }
        driver.join().unwrap();
    }

    #[test]
    fn cold_replay_stream_ids_line_up_with_matching() {
        // The first sent stored request must get id 1 (the profile initialize is id 0), matching the
        // 1-based numbering RequestResponseMatching uses over the filtered stored list.
        let mut input = LspInput::default();
        input.messages.push(request(
            "workspace/symbol",
            serde_json::json!({ "query": "x" }),
        )); // dropped in pc
        input.messages.push(request(
            "textDocument/hover",
            position_params("lsp-fuzz://a.scala"),
        )); // sent
        let profile = ScalaExecutionProfile::presentation_compiler();
        let dir = tempfile::tempdir().unwrap();
        let stream = build_cold_replay_stream(&input, &profile, "file:///root", dir.path());
        let hover_id = parse_lsp_payloads(&stream)
            .into_iter()
            .find_map(|m| match m {
                JsonRPCMessage::Request { id, method, .. } if method == "textDocument/hover" => {
                    Some(id)
                }
                _ => None,
            });
        assert_eq!(hover_id, Some(crate::lsp::json_rpc::MessageId::Number(1)));
        // The filtered stored list keeps only the allowed request, so matching numbers it as id 1.
        let stored = cold_replay_stored_messages(&input, &profile);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].method(), "textDocument/hover");
    }

    // Build a minimal fake frozen backdrop with the markers the index materializer verifies.
    fn fake_backdrop(dir: &Path) {
        std::fs::write(dir.join("backdrop-metadata.json"), b"{}").unwrap();
        std::fs::create_dir_all(dir.join("bsp")).unwrap();
        std::fs::write(dir.join("bsp").join("mill-bsp.json"), b"{}").unwrap();
        let sdb = dir.join("semanticdb");
        std::fs::create_dir_all(&sdb).unwrap();
        std::fs::write(sdb.join("Main.scala.semanticdb"), b"\0").unwrap();
    }

    #[test]
    fn index_cold_replay_overlays_backdrop_and_initializes_at_its_root() {
        let backdrop = tempfile::tempdir().unwrap();
        fake_backdrop(backdrop.path());
        let capture = backdrop.path().join("captured-stream.bin");
        // The driver awaits the initialize response (id 0) before `initialized`, so the fake server
        // must emit that framed response on stdout first (a real server does).
        let init_response =
            JsonRPCMessage::response(Some(0usize), Some(serde_json::json!({})), None)
                .to_lsp_payload();
        let resp_file = backdrop.path().join("init-response.bin");
        std::fs::write(&resp_file, &init_response).unwrap();
        let profile = ScalaExecutionProfile::index();
        // The script emits the id-0 response on stdout, then the bootstrap-ready marker on stderr so
        // the index handshake barrier releases, then captures everything the entrypoint would receive.
        let config = ColdReplayConfig {
            profile: &profile,
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                format!(
                    "cat {}; echo '{LS_BOOTSTRAP_READY_MARKER}' >&2; cat > {} ; exit 0",
                    resp_file.display(),
                    capture.display()
                ),
            ],
            temp_root: tempfile::tempdir().unwrap().path().to_path_buf(),
            backdrop_root: Some(backdrop.path().to_path_buf()),
            timeout: Duration::from_secs(5),
        };
        let observation = cold_replay(&LspInput::default(), &config).unwrap();
        assert_eq!(observation.outcome_class, OutcomeClass::NormalSuccess);

        // The index materializer overlaid the backdrop (created its overlay dir under the root).
        assert!(backdrop.path().join(".lsp-fuzz-overlay").is_dir());

        // The captured initialize request roots at the backdrop root, not a scratch temp dir.
        let stream = std::fs::read(&capture).unwrap();
        let messages = parse_lsp_payloads(&stream);
        let backdrop_uri = format!("file://{}", uri::workspace_uri(backdrop.path()).unwrap());
        let init = messages
            .iter()
            .find_map(|m| match m {
                JsonRPCMessage::Request { method, params, .. } if method == "initialize" => {
                    Some(params.clone())
                }
                _ => None,
            })
            .expect("the stream contains an initialize request");
        assert_eq!(init["rootUri"].as_str(), Some(backdrop_uri.as_str()));
    }

    #[test]
    fn index_cold_replay_requires_a_backdrop_root() {
        let profile = ScalaExecutionProfile::index();
        let config = ColdReplayConfig {
            profile: &profile,
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "exit 0".to_string()],
            temp_root: tempfile::tempdir().unwrap().path().to_path_buf(),
            backdrop_root: None,
            timeout: Duration::from_secs(5),
        };
        assert!(cold_replay(&LspInput::default(), &config).is_err());
    }

    /// Live cold replay through the shipped `ls.core.Main`: a benign input replays to a clean
    /// outcome. Gated on `LS_JAR` (skips loudly when absent); set `LS_JAVA` to the LS's pinned JDK
    /// (a foreign JDK build segfaults the FFM `SQLite` binding — see the pinned-JDK bitlesson).
    #[test]
    fn cold_replay_through_shipped_entrypoint_reproduces_a_clean_run() {
        let Some(ls_jar) = std::env::var_os("LS_JAR") else {
            eprintln!("skipping cold_replay live test: LS_JAR unset");
            return;
        };
        let ls_jar = PathBuf::from(ls_jar);
        if !ls_jar.exists() {
            eprintln!("skipping: LS_JAR does not exist: {}", ls_jar.display());
            return;
        }
        let java = std::env::var_os("LS_JAVA").map_or_else(|| PathBuf::from("java"), PathBuf::from);

        let profile = ScalaExecutionProfile::presentation_compiler();
        let temp = tempfile::tempdir().unwrap();
        let config = ColdReplayConfig {
            profile: &profile,
            program: java.display().to_string(),
            args: vec![
                "--enable-native-access=ALL-UNNAMED".to_string(),
                "-cp".to_string(),
                ls_jar.display().to_string(),
                "ls.core.Main".to_string(),
                // Match the fuzzer's in-process PC surface (the current LS forks the PC by default).
                "--in-process-pc".to_string(),
            ],
            temp_root: temp.path().to_path_buf(),
            backdrop_root: None,
            timeout: Duration::from_mins(1),
        };
        let observation = cold_replay(&LspInput::default(), &config)
            .expect("cold replay launches the entrypoint");
        // A benign input drives initialize/shutdown/exit with no JSON-RPC errors and no crash.
        assert_eq!(observation.outcome_class, OutcomeClass::NormalSuccess);
        assert!(observation.findings.is_empty());
    }

    /// A bundle round-trips through CBOR and writes to disk.
    #[test]
    fn bundle_serializes_and_writes() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            pc_provenance(),
        )
        .unwrap();
        let path = bundle.write_to(dir.path()).unwrap();
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        let decoded: FindingBundle = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(decoded, bundle);
        // `read_from` is the inverse of `write_to` (used by the cold-replay CLI).
        assert_eq!(FindingBundle::read_from(&path).unwrap(), bundle);
    }

    #[test]
    fn write_is_one_bundle_per_finding_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();

        // Two inputs share the (empty) workspace but differ in their message sequence; each must get
        // its own file because the name hashes the WHOLE input, not just the workspace.
        let input_a = LspInput::default();
        let mut input_b = LspInput::default();
        input_b.messages.push(crate::lsp::LspMessage::Shutdown(()));
        let b_a = FindingBundle::build(
            input_a,
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            pc_provenance(),
        )
        .unwrap();
        let b_b = FindingBundle::build(
            input_b,
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            pc_provenance(),
        )
        .unwrap();
        let pa = b_a.write_to(dir.path()).unwrap();
        let pb = b_b.write_to(dir.path()).unwrap();
        assert_ne!(
            pa, pb,
            "different message sequences must not share a bundle file"
        );

        // Re-writing an identical bundle is idempotent (no new file).
        assert_eq!(b_a.write_to(dir.path()).unwrap(), pa);

        // Two DIFFERENT bundles that hash to the same base name (same input + class, different
        // findings) get a collision-safe suffix rather than overwriting each other.
        let same_input = LspInput::default();
        let mut findings = FindingSet::new();
        findings.record(Finding::json_rpc_error(
            "textDocument/hover",
            -32603,
            "boom",
        ));
        let b_c = FindingBundle::build(
            same_input,
            OutcomeClass::NormalSuccess,
            FindingSet::new(),
            pc_provenance(),
        )
        .unwrap();
        let b_d = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::NormalSuccess,
            findings,
            pc_provenance(),
        )
        .unwrap();
        let pc = b_c.write_to(dir.path()).unwrap();
        let pd = b_d.write_to(dir.path()).unwrap();
        assert_ne!(
            pc, pd,
            "a differing bundle must not overwrite an existing one"
        );
        assert!(pc.exists() && pd.exists());
    }
}
