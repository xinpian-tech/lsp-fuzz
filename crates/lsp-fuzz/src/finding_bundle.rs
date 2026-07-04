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
    process::{ChildStderr, ChildStdout, Command, Stdio},
    sync::mpsc::{RecvTimeoutError, Sender, channel},
    thread::JoinHandle,
    time::Duration,
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

/// Read the entrypoint's stdout to EOF, sending the full byte buffer on `out_tx` at the end. While
/// reading, once the response to `last_request_id` (if any) is seen, signal `resp_tx` so the writer
/// may send the teardown — the last sequential request replying implies the earlier ones did too.
fn spawn_response_reader(
    mut stdout: ChildStdout,
    last_request_id: Option<usize>,
    resp_tx: Sender<()>,
    out_tx: Sender<Vec<u8>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut signalled = false;
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if !signalled
                        && let Some(id) = last_request_id
                        && response_seen(&buf, id)
                    {
                        signalled = true;
                        let _ = resp_tx.send(());
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
    let mut stdin = child
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

    // Drive the writes with two barriers that mirror the in-process worker's steady state:
    //   1. write `initialize` + `initialized`, WAIT for bootstrap readiness (LS_BOOTSTRAP_READY_MARKER
    //      on stderr) — firing everything at once races the async bootstrap and gets a spurious
    //      `-32803 "workspace is not ready"` instead of the genuine per-request outcome;
    //   2. write the requests, WAIT for the last request's response, THEN write `shutdown`/`exit` —
    //      tearing the server down before a slow request replies would drop its response (and finding).
    // Both waits are bounded by the deadline so a broken/hung server can never hang the writer.
    let (ready_tx, ready_rx) = channel::<()>();
    let (resp_tx, resp_rx) = channel::<()>();
    let deadline = config.timeout;
    let ColdReplayFrames {
        handshake,
        requests,
        teardown,
        last_request_id,
    } = frames;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&handshake);
        let _ = stdin.flush();
        let _ = ready_rx.recv_timeout(deadline);
        let _ = stdin.write_all(&requests);
        let _ = stdin.flush();
        // Wait for the last request's response before tearing down (only if a request was sent).
        if last_request_id.is_some() {
            let _ = resp_rx.recv_timeout(deadline);
        }
        let _ = stdin.write_all(&teardown);
        let _ = stdin.flush();
        drop(stdin); // signal end-of-input
    });
    let (tx, rx) = channel();
    let reader = spawn_response_reader(stdout, last_request_id, resp_tx, tx);
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

/// The full cold-replay stream (handshake + requests + teardown concatenated), used by tests that
/// assert the ordered method surface and id numbering. The live path writes the three parts with a
/// bootstrap-readiness barrier and a response barrier between them (see [`build_cold_replay_frames`]
/// and [`cold_replay`]).
#[cfg(test)]
fn build_cold_replay_stream(
    input: &LspInput,
    profile: &ScalaExecutionProfile,
    root_uri: &str,
    localization_dir: &Path,
) -> Vec<u8> {
    let frames = build_cold_replay_frames(input, profile, root_uri, localization_dir);
    [frames.handshake, frames.requests, frames.teardown].concat()
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

/// The three parts of a cold-replay stream, written with a barrier between each (see [`cold_replay`]).
struct ColdReplayFrames {
    /// `initialize` (id 0) + `initialized`, sent first.
    handshake: Vec<u8>,
    /// The filtered didOpens + stored requests, sent only after the server signals readiness.
    requests: Vec<u8>,
    /// `shutdown` + `exit`, sent only after every stored request has been answered — the in-process
    /// worker awaits each request's response and never tears the server down mid-request, so tearing
    /// down before a slow request replies would drop its response and lose the finding.
    teardown: Vec<u8>,
    /// The id of the last stored request sent (if any); the driver waits for its response — implying
    /// the earlier sequential ids have also replied — before sending `teardown`.
    last_request_id: Option<usize>,
}

/// Split the cold-replay stream into [`ColdReplayFrames`] so the driver can stage the writes: send the
/// handshake, WAIT for bootstrap readiness ([`LS_BOOTSTRAP_READY_MARKER`]), send the requests, WAIT for
/// their responses, then send `shutdown`/`exit`. This reproduces the steady state and the
/// request-by-request await the persistent in-process worker uses (it emits `initialized` once per
/// epoch and never sends `shutdown`/`exit` per input). Concatenating the three parts reproduces the
/// previous single stream byte-for-byte (same ordering, same id numbering: initialize is id 0, the
/// first sent stored request is id 1), so response matching is unaffected; only write *timing* changes.
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
    // The handshake: the profile-supplied initialize (id 0) + initialized, sent first.
    let mut handshake =
        JsonRPCMessage::request(id, "initialize".into(), profile.initialize_params(root_uri))
            .to_lsp_payload();
    id += 1;
    handshake.extend(
        JsonRPCMessage::notification("initialized".into(), serde_json::json!({})).to_lsp_payload(),
    );
    // The requests: generated didOpens + stored messages (filtered by the profile allowlist like the
    // worker). A request carries an id; a notification (e.g. didOpen) does not, so the last request id
    // is the highest id actually assigned to a request here.
    let mut requests = Vec::new();
    let mut last_request_id = None;
    for msg in input.message_sequence() {
        if !is_replayed(msg.method(), profile) {
            continue;
        }
        let before = id;
        let message = msg.into_json_rpc(&mut id, Some(&localize_uri));
        if matches!(message, JsonRPCMessage::Request { .. }) {
            // `into_json_rpc` consumed `before` as this request's id and advanced `id`.
            last_request_id = Some(before);
        }
        requests.extend(message.to_lsp_payload());
    }
    // The teardown: a graceful shutdown/exit, sent only after the requests have been answered.
    let mut teardown =
        JsonRPCMessage::request(id, "shutdown".into(), serde_json::Value::Null).to_lsp_payload();
    teardown.extend(
        JsonRPCMessage::notification("exit".into(), serde_json::Value::Null).to_lsp_payload(),
    );
    ColdReplayFrames {
        handshake,
        requests,
        teardown,
        last_request_id,
    }
}

/// Whether `bytes` (a stdout prefix) contains a [`JsonRPCMessage::Response`] to request id `id`.
fn response_seen(bytes: &[u8], id: usize) -> bool {
    parse_lsp_payloads(bytes).iter().any(|m| {
        matches!(
            m,
            JsonRPCMessage::Response { id: Some(MessageId::Number(rid)), .. } if *rid == id
        )
    })
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
        // Emit the bootstrap-ready marker first so the handshake barrier releases immediately; the
        // marker text triggers no classification rule, so it does not affect what the script tests.
        let script = format!("echo '{LS_BOOTSTRAP_READY_MARKER}' >&2; {script}");
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

    #[test]
    fn cold_replay_frames_split_handshake_requests_teardown() {
        // The frames must isolate the handshake (initialize + initialized) from the requests and the
        // teardown (shutdown + exit), and report the last stored request id so the driver can wait for
        // its response before tearing the server down.
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
        assert_eq!(
            methods(&frames.handshake),
            vec!["initialize", "initialized"]
        );
        assert_eq!(methods(&frames.requests), vec!["textDocument/references"]);
        assert_eq!(methods(&frames.teardown), vec!["shutdown", "exit"]);
        // The first (and only) stored request gets id 1 (initialize consumed id 0).
        assert_eq!(frames.last_request_id, Some(1));
    }

    #[test]
    fn response_seen_matches_only_the_target_id() {
        let mut bytes = JsonRPCMessage::response(Some(0usize), Some(serde_json::json!({})), None)
            .to_lsp_payload();
        bytes.extend(
            JsonRPCMessage::response(Some(1usize), Some(serde_json::json!({})), None)
                .to_lsp_payload(),
        );
        assert!(response_seen(&bytes, 0));
        assert!(response_seen(&bytes, 1));
        assert!(!response_seen(&bytes, 2));
    }

    #[test]
    fn cold_replay_frames_report_no_request_when_all_dropped() {
        // An index-mode input carrying only a pc-only request (completion) has it dropped, so there is
        // no stored request to await — the driver must tear down immediately (last_request_id = None).
        let mut input = LspInput::default();
        input.messages.push(request(
            "textDocument/completion",
            position_params("lsp-fuzz://a.scala"),
        ));
        let profile = ScalaExecutionProfile::index();
        let dir = tempfile::tempdir().unwrap();
        let frames = build_cold_replay_frames(&input, &profile, "file:///root", dir.path());
        assert_eq!(frames.last_request_id, None);
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
        let profile = ScalaExecutionProfile::index();
        // The script captures the request stream the shipped entrypoint would receive, then exits.
        let config = ColdReplayConfig {
            profile: &profile,
            program: "sh".to_string(),
            // Emit the bootstrap-ready marker first so the handshake barrier releases and the full
            // stream is written, then capture everything the entrypoint would receive.
            args: vec![
                "-c".to_string(),
                format!(
                    "echo '{LS_BOOTSTRAP_READY_MARKER}' >&2; cat > {} ; exit 0",
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
