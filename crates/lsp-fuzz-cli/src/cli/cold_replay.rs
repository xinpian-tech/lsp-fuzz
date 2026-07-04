use std::{path::PathBuf, time::Duration};

use anyhow::{Context, bail};
use lsp_fuzz::{
    execution::scala_profile::ScalaExecutionProfile,
    finding_bundle::{ColdReplayConfig, FindingBundle, Replayability},
};
use tracing::info;

use crate::cli::GlobalOptions;

/// Cold-replay a finding bundle from a fresh JVM through the shipped `ls.core.Main` stdio entrypoint
/// and report whether it reproduces the recorded outcome class. This is the one-command cold replay:
/// the bundle carries the serialized input + provenance, and this command drives it against the
/// shipped server exactly the way the fuzzer would, confirming the finding or leaving it labelled
/// in-process-harness-only.
#[derive(Debug, clap::Parser)]
pub struct ColdReplayCommand {
    /// The finding bundle (CBOR) to replay.
    #[clap(long, short)]
    bundle: PathBuf,

    /// The target language-server jar (its classpath). Defaults to the `LS_JAR` environment variable.
    #[clap(long, env = "LS_JAR")]
    ls_jar: PathBuf,

    /// The JVM to launch the server with — MUST be the server's exact pinned JDK (a foreign build
    /// segfaults the FFM `SQLite` binding). Defaults to `LS_JAVA`, then `java` on `PATH`.
    #[clap(long, env = "LS_JAVA", default_value = "java")]
    java: PathBuf,

    /// The verified frozen backdrop root (required to replay an `index`-mode finding). Defaults to the
    /// `BACKDROP_OUT` environment variable.
    #[clap(long, env = "BACKDROP_OUT")]
    backdrop_root: Option<PathBuf>,

    /// Where to write the updated bundle (with its confirmed replayability), if set.
    #[clap(long, short)]
    output: Option<PathBuf>,

    /// Total replay deadline in milliseconds, overriding the bundle's recorded per-input run budget.
    /// A cold replay boots a fresh JVM and bootstraps the server's index from scratch, which takes far
    /// longer than the warm in-process worker's per-input budget, so a generous value is usually needed.
    #[clap(long)]
    timeout_ms: Option<u64>,
}

/// Load a finding bundle from `path` and revalidate its provenance, rejecting a bundle whose required
/// provenance fields are absent (e.g. a hand-edited or corrupt CBOR) before any replay — so the
/// operator replay path upholds the fully-provenanced guarantee, not only the export path.
fn load_validated_bundle(path: &std::path::Path) -> anyhow::Result<FindingBundle> {
    let bundle = FindingBundle::read_from(path)
        .with_context(|| format!("Loading finding bundle {}", path.display()))?;
    bundle.provenance.validate().map_err(|missing| {
        anyhow::anyhow!(
            "finding bundle {} has incomplete provenance: {missing}",
            path.display()
        )
    })?;
    Ok(bundle)
}

/// Build the `java` arguments for a cold replay: the SAME determinism flags as the fuzzing
/// config (disable compact object headers, AOT/CDS, and non-serial GC — see
/// `docs/jvm-coverage-agent.md`), then the runtime flags the server needs. `--enable-native-access` is
/// required for the server's FFM `SQLite` binding; `--in-process-pc` runs the presentation compiler in
/// this JVM (the shipped `Main` forks the PC by default, but the fuzzer's in-process worker embeds
/// `ls.core.ScalaLs`, so cold replay must match that surface for a comparable outcome).
fn scala_launch_args(profile: &ScalaExecutionProfile, ls_jar: &std::path::Path) -> Vec<String> {
    let mut args: Vec<String> = profile
        .determinism_flags()
        .iter()
        .map(ToString::to_string)
        .collect();
    args.extend([
        "--enable-native-access=ALL-UNNAMED".to_string(),
        "-cp".to_string(),
        ls_jar.display().to_string(),
        "ls.core.Main".to_string(),
        "--in-process-pc".to_string(),
    ]);
    args
}

/// The first required piece of replay environment that is missing, or `None` if all present.
/// `--backdrop-root` covers `BACKDROP_OUT`; every other var in the profile's `required_env` must be
/// present in the process environment (the spawned server inherits it), checked via `env_present`.
fn missing_replay_env(
    profile: &ScalaExecutionProfile,
    backdrop_supplied: bool,
    env_present: impl Fn(&str) -> bool,
) -> Option<String> {
    if profile.mode() == lsp_fuzz::execution::scala_profile::ScalaProfileMode::Index
        && !backdrop_supplied
    {
        return Some("--backdrop-root (or BACKDROP_OUT)".to_string());
    }
    profile
        .required_env()
        .iter()
        .find(|var| **var != "BACKDROP_OUT" && !env_present(var))
        .map(|var| {
            format!("the {var} environment variable (the server's pinned native configuration)")
        })
}

impl ColdReplayCommand {
    pub fn run(self, _global_options: GlobalOptions) -> anyhow::Result<()> {
        let mut bundle = load_validated_bundle(&self.bundle)?;

        // Rebuild the execution profile the finding was produced under so the replay drives the same
        // materializer / initialize / method-allowlist surface.
        let profile = match bundle.provenance.scala_profile_mode.as_str() {
            "pc" => ScalaExecutionProfile::presentation_compiler(),
            "index" => ScalaExecutionProfile::index(),
            other => bail!("finding bundle has an unknown Scala profile mode: {other:?}"),
        };
        // The spawned server inherits this process's environment, so the profile's required env
        // (BACKDROP_OUT — satisfied by --backdrop-root — and, in index mode, LS_SQLITE_LIB) must be
        // present up front. Without the pinned native SQLite the replay would run under a different
        // native config than the fuzzing run and could fail (or diverge) on the FFM/SQLite path rather
        // than reproduce the finding.
        if let Some(missing) = missing_replay_env(&profile, self.backdrop_root.is_some(), |v| {
            std::env::var_os(v).is_some()
        }) {
            bail!(
                "replaying a {}-mode finding requires {missing}; set it before cold replay so the \
                 replay matches the fuzzing run's native/backdrop surface",
                profile.mode().as_str()
            );
        }

        let temp_dir =
            std::env::temp_dir().join(format!("lsp-fuzz-cold-replay-{}", std::process::id()));
        let config = ColdReplayConfig {
            profile: &profile,
            program: self.java.display().to_string(),
            args: scala_launch_args(&profile, &self.ls_jar),
            temp_root: temp_dir,
            backdrop_root: self.backdrop_root.clone(),
            timeout: Duration::from_millis(
                self.timeout_ms
                    .unwrap_or(bundle.provenance.run_timeout_ms)
                    .max(1),
            ),
        };

        info!(
            "Cold-replaying {:?} finding ({} mode) through shipped ls.core.Main",
            bundle.outcome_class, bundle.provenance.scala_profile_mode
        );
        let confirmed = bundle
            .confirm_via_cold_replay(&config)
            .context("Cold-replaying the finding through the shipped entrypoint")?;

        match bundle.replayability {
            Replayability::Confirmed => info!(
                "CONFIRMED: the shipped entrypoint reproduced the {:?} outcome",
                bundle.outcome_class
            ),
            Replayability::InProcessHarnessOnly => info!(
                "IN-PROCESS-HARNESS-ONLY: the shipped entrypoint did NOT reproduce the {:?} outcome; \
                 not a confirmed server finding",
                bundle.outcome_class
            ),
        }

        if let Some(output) = &self.output {
            std::fs::write(
                output,
                bundle.to_cbor().context("Serializing updated bundle")?,
            )
            .with_context(|| format!("Writing updated bundle to {}", output.display()))?;
        }

        // A non-reproducing finding is not an error — it is a real (harness-only) result.
        let _ = confirmed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use lsp_fuzz::{
        execution::outcome::OutcomeClass,
        finding_bundle::{FindingBundle, Provenance, Replayability},
        findings::FindingSet,
        lsp_input::LspInput,
    };

    use lsp_fuzz::execution::scala_profile::ScalaExecutionProfile;

    use super::{ColdReplayCommand, load_validated_bundle, missing_replay_env, scala_launch_args};

    /// Index-mode cold replay requires the backdrop AND the pinned native `SQLite` env; PC mode
    /// requires neither. The check is env-injected so it does not depend on the test process's env.
    #[test]
    fn missing_replay_env_requires_index_backdrop_and_sqlite() {
        let index = ScalaExecutionProfile::index();
        // No backdrop → the backdrop is reported first.
        assert!(
            missing_replay_env(&index, false, |_| true)
                .unwrap()
                .contains("backdrop")
        );
        // Backdrop present but LS_SQLITE_LIB absent → it is reported.
        assert!(
            missing_replay_env(&index, true, |_| false)
                .unwrap()
                .contains("LS_SQLITE_LIB")
        );
        // Backdrop present and all env present → nothing missing.
        assert!(missing_replay_env(&index, true, |_| true).is_none());
        // PC mode needs neither a backdrop nor extra env.
        let pc = ScalaExecutionProfile::presentation_compiler();
        assert!(missing_replay_env(&pc, false, |_| false).is_none());
    }

    /// Cold replay must launch under the determinism flags (before `-cp`/main class) for both
    /// Scala modes, so the replay reproduces the fuzzing config's coverage/behavior surface.
    #[test]
    fn scala_launch_args_carry_the_determinism_flags() {
        for profile in [
            ScalaExecutionProfile::index(),
            ScalaExecutionProfile::presentation_compiler(),
        ] {
            let args = scala_launch_args(&profile, std::path::Path::new("/path/to/ls.jar"));
            assert!(
                profile.missing_determinism_flags(&args).is_empty(),
                "cold-replay launch must carry every determinism flag: {args:?}"
            );
            // The determinism flags precede `-cp` (they are JVM flags, not program args).
            let cp = args.iter().position(|a| a == "-cp").unwrap();
            for flag in profile.determinism_flags() {
                assert!(
                    args[..cp].iter().any(|a| a == flag),
                    "flag {flag} must precede -cp"
                );
            }
        }
    }

    /// A bundle whose provenance is incomplete (as if hand-edited/corrupted) is rejected on load,
    /// before any server is spawned — the operator replay path stays fully provenanced.
    #[test]
    fn cold_replay_rejects_incomplete_provenance_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tampered.cbor");
        // Construct a bundle directly (bypassing FindingBundle::build's validation) with a missing
        // required field, and serialize it.
        let bundle = FindingBundle {
            input: LspInput::default(),
            outcome_class: OutcomeClass::JvmFatal,
            findings: FindingSet::new(),
            provenance: Provenance {
                scala_profile_mode: "pc".to_string(),
                run_timeout_ms: 30_000,
                ls_commit: None, // required field missing
                ls_classpath_hash: Some("cp".to_string()),
                jdk_flags: vec!["none".to_string()],
                agent_version: Some("agent-1".to_string()),
                agent_config: Some("asm-9.8".to_string()),
                backdrop_commit: None,
                backdrop_snapshot_hash: None,
                semanticdb_hash: None,
                bsp_hash: None,
                sqlite_artifact_hash: None,
            },
            replayability: Replayability::InProcessHarnessOnly,
        };
        std::fs::write(&path, bundle.to_cbor().unwrap()).unwrap();

        let err = load_validated_bundle(&path).unwrap_err();
        assert!(
            err.to_string().contains("incomplete provenance"),
            "expected a provenance rejection, got: {err}"
        );
    }

    /// A complete bundle loads and revalidates cleanly.
    #[test]
    fn cold_replay_loads_complete_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("good.cbor");
        let provenance = Provenance {
            scala_profile_mode: "pc".to_string(),
            run_timeout_ms: 30_000,
            ls_commit: Some("abc".to_string()),
            ls_classpath_hash: Some("cp".to_string()),
            jdk_flags: vec!["none".to_string()],
            agent_version: Some("agent-1".to_string()),
            agent_config: Some("asm-9.8".to_string()),
            backdrop_commit: None,
            backdrop_snapshot_hash: None,
            semanticdb_hash: None,
            bsp_hash: None,
            sqlite_artifact_hash: None,
        };
        let bundle = FindingBundle::build(
            LspInput::default(),
            OutcomeClass::JvmFatal,
            FindingSet::new(),
            provenance,
        )
        .unwrap();
        std::fs::write(&path, bundle.to_cbor().unwrap()).unwrap();
        assert!(load_validated_bundle(&path).is_ok());
    }

    /// The cold-replay command parses with a bundle + jar and optional java/backdrop/output, so it is
    /// usable as a one-command cold replay (the live run is gated on a real server at runtime).
    #[test]
    fn cold_replay_parses_bundle_and_jar() {
        let parsed = ColdReplayCommand::try_parse_from([
            "cold-replay",
            "--bundle",
            "/tmp/finding.cbor",
            "--ls-jar",
            "/path/to/ls.jar",
            "--java",
            "/nix/store/pinned-jdk/bin/java",
            "--backdrop-root",
            "/path/to/backdrop",
            "--output",
            "/tmp/confirmed.cbor",
        ])
        .expect("cold-replay should parse a bundle + jar + optional flags");
        assert_eq!(parsed.bundle, std::path::PathBuf::from("/tmp/finding.cbor"));
        assert_eq!(parsed.ls_jar, std::path::PathBuf::from("/path/to/ls.jar"));
        assert_eq!(
            parsed.backdrop_root,
            Some(std::path::PathBuf::from("/path/to/backdrop"))
        );
        assert_eq!(
            parsed.output,
            Some(std::path::PathBuf::from("/tmp/confirmed.cbor"))
        );
    }
}
