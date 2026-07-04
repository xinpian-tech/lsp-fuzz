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
}

impl ColdReplayCommand {
    pub fn run(self, _global_options: GlobalOptions) -> anyhow::Result<()> {
        let mut bundle = FindingBundle::read_from(&self.bundle)
            .with_context(|| format!("Loading finding bundle {}", self.bundle.display()))?;

        // Rebuild the execution profile the finding was produced under so the replay drives the same
        // materializer / initialize / method-allowlist surface.
        let profile = match bundle.provenance.scala_profile_mode.as_str() {
            "pc" => ScalaExecutionProfile::presentation_compiler(),
            "index" => ScalaExecutionProfile::index(),
            other => bail!("finding bundle has an unknown Scala profile mode: {other:?}"),
        };
        if profile.mode() == lsp_fuzz::execution::scala_profile::ScalaProfileMode::Index
            && self.backdrop_root.is_none()
        {
            bail!(
                "replaying an index-mode finding requires --backdrop-root (or BACKDROP_OUT); the \
                 server needs the verified frozen backdrop"
            );
        }

        let temp_dir =
            std::env::temp_dir().join(format!("lsp-fuzz-cold-replay-{}", std::process::id()));
        let config = ColdReplayConfig {
            profile: &profile,
            program: self.java.display().to_string(),
            // `--enable-native-access` is required for the server's FFM SQLite binding.
            args: vec![
                "--enable-native-access=ALL-UNNAMED".to_string(),
                "-cp".to_string(),
                self.ls_jar.display().to_string(),
                "ls.core.Main".to_string(),
            ],
            temp_root: temp_dir,
            backdrop_root: self.backdrop_root.clone(),
            timeout: Duration::from_millis(bundle.provenance.run_timeout_ms.max(1)),
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

    use super::ColdReplayCommand;

    /// The cold-replay command parses with a bundle + jar and optional java/backdrop/output, so it is
    /// invokable as a one-command cold replay (the live run is gated on a real server at runtime).
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
