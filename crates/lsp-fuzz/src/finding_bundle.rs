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
    process::{Command, Stdio},
    sync::mpsc::{RecvTimeoutError, channel},
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
use crate::execution::workspace_observer::HasWorkspace;
use crate::findings::{FindingSet, findings_from_json_rpc_errors};
use crate::lsp::json_rpc::JsonRPCMessage;
use crate::lsp_input::LspInput;
use crate::lsp_input::materializer::{GenericTempRootMaterializer, WorkspaceMaterializer};
use crate::lsp_input::server_response::matching::RequestResponseMatching;

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
    pub agent_config: String,
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
            agent_config: env("COV_AGENT_CONFIG").unwrap_or_default(),
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
        let mut missing = Vec::new();
        if self.ls_commit.is_none() {
            missing.push("ls_commit");
        }
        if self.ls_classpath_hash.is_none() {
            missing.push("ls_classpath_hash");
        }
        if self.agent_version.is_none() {
            missing.push("agent_version");
        }
        if self.is_index_mode() {
            if self.backdrop_commit.is_none() {
                missing.push("backdrop_commit");
            }
            if self.backdrop_snapshot_hash.is_none() {
                missing.push("backdrop_snapshot_hash");
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

    /// Write the bundle to `dir` as a CBOR file named by its input hash + outcome class. Returns the
    /// written path.
    ///
    /// # Errors
    ///
    /// Returns any I/O or serialization error.
    pub fn write_to(&self, dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let name = format!(
            "finding_{:?}_{}.cbor",
            self.outcome_class,
            self.input.workspace_hash()
        );
        let path = dir.join(name);
        std::fs::write(&path, self.to_cbor()?)?;
        Ok(path)
    }

    /// Cold-replay this finding through the shipped `ls.core.Main` and, if it reproduces the same
    /// outcome class and compatible findings, promote it to [`Replayability::Confirmed`]. Returns
    /// whether it was confirmed. A finding that does not reproduce stays
    /// [`Replayability::InProcessHarnessOnly`].
    ///
    /// # Errors
    ///
    /// Returns any I/O error launching or driving the shipped entrypoint.
    pub fn confirm_via_cold_replay(
        &mut self,
        program: &str,
        args: &[String],
        temp_root: &Path,
        timeout: Duration,
    ) -> io::Result<bool> {
        let replay = cold_replay(&self.input, program, args, temp_root, timeout)?;
        let confirmed = check_equivalence(self, &replay);
        self.replayability = if confirmed {
            Replayability::Confirmed
        } else {
            Replayability::InProcessHarnessOnly
        };
        Ok(confirmed)
    }
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

/// Classify a cold replay's raw observations into an [`OutcomeClass`] the way the shipped entrypoint
/// is judged: a crashed process is a JVM fatal; otherwise a JSON-RPC error response is a JSON-RPC
/// error finding; no reply at all is a timeout; anything else is a normal success.
fn classify_replay(
    crashed: bool,
    timed_out: bool,
    findings: &FindingSet,
    got_reply: bool,
) -> OutcomeClass {
    if crashed {
        OutcomeClass::JvmFatal
    } else if timed_out || !got_reply {
        OutcomeClass::TimeoutOrDeadlock
    } else if !findings.is_empty() {
        OutcomeClass::JsonRpcError
    } else {
        OutcomeClass::NormalSuccess
    }
}

/// Cold-replay `input` through the shipped `ls.core.Main` stdio entrypoint (`program` + `args`),
/// materializing its workspace under `temp_root` and localizing its URIs exactly as the fuzzer does,
/// then observing the outcome. Bounded by `timeout`: a server that never replies is a timeout.
///
/// # Errors
///
/// Returns any I/O error materializing the workspace or launching the entrypoint.
pub fn cold_replay(
    input: &LspInput,
    program: &str,
    args: &[String],
    temp_root: &Path,
    timeout: Duration,
) -> io::Result<ReplayObservation> {
    let materializer = GenericTempRootMaterializer::new(temp_root.to_path_buf());
    let placed = materializer.materialize(input)?;
    let stream = input.request_bytes(&placed.localization_dir);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;

    // Write the full request stream on a thread (it may exceed the pipe buffer) and read the reply
    // stream to EOF on another, so neither direction can deadlock the caller.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&stream);
        let _ = stdin.flush();
        drop(stdin); // signal end-of-input
    });
    let (tx, rx) = channel();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    // The server exits on `exit`, closing stdout and completing the read; if it hangs, the deadline
    // fires and we kill it (which closes the pipe and ends the reader thread).
    let (received_bytes, timed_out) = match rx.recv_timeout(timeout) {
        Ok(bytes) => (bytes, false),
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            (Vec::new(), true)
        }
    };
    let status = child.wait()?;
    let _ = writer.join();
    let _ = reader.join();
    // A process killed by a signal (no exit code) crashed; a clean or non-zero exit did not.
    let crashed = !timed_out && status.code().is_none();

    let received = parse_lsp_payloads(&received_bytes);
    let got_reply = !received.is_empty();
    let findings = replay_findings(input, &received);
    let outcome_class = classify_replay(crashed, timed_out, &findings, got_reply);
    Ok(ReplayObservation {
        outcome_class,
        findings,
    })
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

/// Derive the JSON-RPC error findings from a replay's received messages, using the same
/// request/response matching (and the same 1-based stored-request numbering) as the native path.
fn replay_findings(input: &LspInput, received: &[JsonRPCMessage]) -> FindingSet {
    match RequestResponseMatching::match_messages(input.messages.iter(), received.iter(), None) {
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
            agent_config: "asm-9.8".to_string(),
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
        // A missing always-required field (agent_version) rejects, in pc mode.
        let mut prov = pc_provenance();
        prov.agent_version = None;
        let err = prov.validate().unwrap_err();
        assert!(err.missing.contains(&"agent_version"));
        assert!(
            FindingBundle::build(
                LspInput::default(),
                OutcomeClass::JsonRpcError,
                FindingSet::new(),
                prov,
            )
            .is_err()
        );

        // Index mode additionally requires the backdrop + native SQLite fields.
        let mut prov = index_provenance();
        prov.backdrop_snapshot_hash = None;
        prov.sqlite_artifact_hash = None;
        let err = prov.validate().unwrap_err();
        assert!(err.missing.contains(&"backdrop_snapshot_hash"));
        assert!(err.missing.contains(&"sqlite_artifact_hash"));
        // The same fields are NOT required in pc mode.
        let mut pc = pc_provenance();
        pc.backdrop_snapshot_hash = None;
        assert!(pc.validate().is_ok());
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
        assert_eq!(
            classify_replay(true, false, &empty, false),
            OutcomeClass::JvmFatal
        );
        assert_eq!(
            classify_replay(false, true, &empty, false),
            OutcomeClass::TimeoutOrDeadlock
        );
        assert_eq!(
            classify_replay(false, false, &empty, false),
            OutcomeClass::TimeoutOrDeadlock
        );
        assert_eq!(
            classify_replay(false, false, &errs, true),
            OutcomeClass::JsonRpcError
        );
        assert_eq!(
            classify_replay(false, false, &empty, true),
            OutcomeClass::NormalSuccess
        );
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

        let temp = tempfile::tempdir().unwrap();
        let args = vec![
            "--enable-native-access=ALL-UNNAMED".to_string(),
            "-cp".to_string(),
            ls_jar.display().to_string(),
            "ls.core.Main".to_string(),
        ];
        let observation = cold_replay(
            &LspInput::default(),
            &java.display().to_string(),
            &args,
            temp.path(),
            Duration::from_mins(1),
        )
        .expect("cold replay should launch the shipped entrypoint");
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
    }
}
