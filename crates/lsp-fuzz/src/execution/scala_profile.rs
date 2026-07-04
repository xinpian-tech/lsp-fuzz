//! The Scala execution profile.
//!
//! A [`ScalaExecutionProfile`] isolates everything Scala/language-server-specific about a fuzzing
//! run behind one value: the LSP `initialize` params + client capabilities, the language id and
//! file extensions, the per-mode LSP method allowlist, the intentional invalid-message generation
//! policy, the per-mode timeout windows, and the environment a mode requires. The JVM worker
//! envelope carries the profile's `initialize` params and allowlist so the embedded server is
//! initialized and driven exactly as the profile prescribes, while the generic virtual-workspace
//! path stays profile-free.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use lsp_fuzz_grammars::Language;
use serde_json::{Value, json};

use crate::lsp::GeneratorsConfig;

/// The two language-server modes the target exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ScalaProfileMode {
    /// Presentation-compiler paths (completion/hover/signatureHelp/definition on open buffers). The
    /// server runs this without a build; it is the default.
    #[default]
    #[value(name = "pc")]
    PresentationCompiler,
    /// Live BSP/index paths (references/rename/workspace-symbol) over a pre-indexed backdrop. Needs
    /// the pinned native `SQLite` library and a verified backdrop root.
    #[value(name = "index")]
    Index,
}

impl ScalaProfileMode {
    /// The stable string id for this mode (`pc` / `index`), used in provenance records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ScalaProfileMode::PresentationCompiler => "pc",
            ScalaProfileMode::Index => "index",
        }
    }
}

/// A Scala fuzzing profile: the language-server-facing policy for one mode.
#[derive(Debug, Clone)]
pub struct ScalaExecutionProfile {
    mode: ScalaProfileMode,
    generate_invalid_messages: bool,
}

impl ScalaExecutionProfile {
    /// The presentation-compiler mode (no BSP/index required).
    #[must_use]
    pub fn presentation_compiler() -> Self {
        Self {
            mode: ScalaProfileMode::PresentationCompiler,
            generate_invalid_messages: true,
        }
    }

    /// The BSP-backed index mode (requires the pinned `SQLite` + a verified backdrop).
    #[must_use]
    pub fn index() -> Self {
        Self {
            mode: ScalaProfileMode::Index,
            generate_invalid_messages: true,
        }
    }

    /// Build the profile for `mode`.
    #[must_use]
    pub fn for_mode(mode: ScalaProfileMode) -> Self {
        match mode {
            ScalaProfileMode::PresentationCompiler => Self::presentation_compiler(),
            ScalaProfileMode::Index => Self::index(),
        }
    }

    #[must_use]
    pub fn mode(&self) -> ScalaProfileMode {
        self.mode
    }

    #[must_use]
    pub fn language(&self) -> Language {
        Language::Scala
    }

    #[must_use]
    pub fn language_id(&self) -> &'static str {
        "scala"
    }

    #[must_use]
    pub fn file_extensions(&self) -> &'static [&'static str] {
        &["scala", "sc"]
    }

    /// Whether the profile opts into intentionally invalid message generation (malformed
    /// positions/ranges/params). Applied to [`GeneratorsConfig`] via [`Self::apply_generation_policy`].
    #[must_use]
    pub fn generate_invalid_messages(&self) -> bool {
        self.generate_invalid_messages
    }

    /// The LSP methods this mode is allowed to drive. A stored message whose method is not in this
    /// set is dropped by the worker rather than forwarded to the server.
    #[must_use]
    pub fn allowed_methods(&self) -> &'static [&'static str] {
        const PC: &[&str] = &[
            "textDocument/didOpen",
            "textDocument/didChange",
            "textDocument/didClose",
            "textDocument/completion",
            "textDocument/hover",
            "textDocument/signatureHelp",
            "textDocument/definition",
        ];
        const INDEX: &[&str] = &[
            "textDocument/didOpen",
            "textDocument/didChange",
            "textDocument/didClose",
            "textDocument/definition",
            "textDocument/references",
            "textDocument/prepareRename",
            "textDocument/rename",
            "workspace/symbol",
        ];
        match self.mode {
            ScalaProfileMode::PresentationCompiler => PC,
            ScalaProfileMode::Index => INDEX,
        }
    }

    /// The per-input run timeout (the direct message sequence).
    #[must_use]
    pub fn run_timeout(&self) -> Duration {
        match self.mode {
            ScalaProfileMode::PresentationCompiler => Duration::from_secs(30),
            ScalaProfileMode::Index => Duration::from_mins(1),
        }
    }

    /// The quiescence deadline (background settle) after the direct sequence returns.
    #[must_use]
    pub fn quiescence_deadline(&self) -> Duration {
        match self.mode {
            ScalaProfileMode::PresentationCompiler => Duration::from_secs(1),
            ScalaProfileMode::Index => Duration::from_secs(3),
        }
    }

    /// The per-input run budget in milliseconds (for the worker's `COV_RUN_TIMEOUT_MS`).
    #[must_use]
    pub fn run_timeout_ms(&self) -> u64 {
        u64::try_from(self.run_timeout().as_millis()).unwrap_or(u64::MAX)
    }

    /// The quiescence deadline in milliseconds (for the worker's `COV_QUIESCE_DEADLINE_MS`).
    #[must_use]
    pub fn quiescence_deadline_ms(&self) -> u64 {
        u64::try_from(self.quiescence_deadline().as_millis()).unwrap_or(u64::MAX)
    }

    /// How long the Rust driver waits for a worker reply. It must exceed the worker's total
    /// per-input processing (run + quiescence + snapshot/late-watch/protocol slack), so it is derived
    /// from the profile rather than hard-coded.
    #[must_use]
    pub fn worker_reply_deadline(&self) -> Duration {
        self.run_timeout() + self.quiescence_deadline() + Duration::from_secs(5)
    }

    /// Environment variables this mode requires to be set before it can run.
    #[must_use]
    pub fn required_env(&self) -> &'static [&'static str] {
        match self.mode {
            ScalaProfileMode::PresentationCompiler => &[],
            // The index path opens a SQLite MetaStore through the FFM binding (needs the language
            // server's pinned native library) over a frozen, pre-indexed backdrop.
            ScalaProfileMode::Index => &["LS_SQLITE_LIB", "BACKDROP_OUT"],
        }
    }

    /// The JVM determinism flags the Scala fuzzing configuration must launch the language
    /// server under, so coverage is stable across identical inputs: disable compact object headers,
    /// disable the AOT/CDS archive (`-Xshare:off`, and never pass `-XX:AOTCache*`), and use a
    /// single-threaded GC to cut GC-thread coverage noise (documented in `docs/jvm-coverage-agent.md`).
    /// The same set for both modes — it is the fuzzing config, not a per-mode policy.
    #[must_use]
    pub fn determinism_flags(&self) -> &'static [&'static str] {
        &[
            "-XX:-UseCompactObjectHeaders",
            "-Xshare:off",
            "-XX:+UseSerialGC",
        ]
    }

    /// The determinism flags absent from a candidate JVM launch `argv`, in declared order. A
    /// launch surface for the Scala fuzzing config must carry all of them; a non-empty result means the
    /// launch is not running under the pinned determinism configuration and coverage may be unstable.
    #[must_use]
    pub fn missing_determinism_flags(&self, argv: &[String]) -> Vec<&'static str> {
        self.determinism_flags()
            .iter()
            .copied()
            .filter(|flag| !argv.iter().any(|a| a == flag))
            .collect()
    }

    /// Verify the required environment for this mode is present, and — for index mode — that
    /// `BACKDROP_OUT` points at a verified backdrop.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the first missing variable or invalid backdrop.
    pub fn validate_environment(&self) -> Result<(), String> {
        for var in self.required_env() {
            if std::env::var_os(var).is_none() {
                return Err(format!(
                    "the Scala {:?} mode requires the {var} environment variable to be set",
                    self.mode
                ));
            }
        }
        if self.mode == ScalaProfileMode::Index {
            // `required_env` guaranteed BACKDROP_OUT is set above.
            let root = PathBuf::from(std::env::var_os("BACKDROP_OUT").unwrap_or_default());
            validate_backdrop_root(&root)?;
        }
        Ok(())
    }

    /// Apply this profile's invalid-message policy to a generators config: when the policy is off,
    /// no invalid positions/ranges are produced and the invalid-code frequency is zeroed.
    #[must_use]
    pub fn apply_generation_policy(&self, mut config: GeneratorsConfig) -> GeneratorsConfig {
        if !self.generate_invalid_messages {
            config.invalid_input.positions = false;
            config.invalid_input.ranges = false;
            config.invalid_input.code_frequency = 0.0;
        }
        config
    }

    /// Build the LSP `initialize` params for this profile, rooted at `root_uri`. Client capabilities
    /// are declared explicitly per mode (not derived from method names).
    #[must_use]
    pub fn initialize_params(&self, root_uri: &str) -> Value {
        let text_document = match self.mode {
            ScalaProfileMode::PresentationCompiler => json!({
                "completion": {},
                "hover": {},
                "signatureHelp": {},
                "definition": {},
            }),
            ScalaProfileMode::Index => json!({
                "definition": {},
                "references": {},
                // Prepare support is a sub-capability of `rename`, not a standalone capability.
                "rename": { "prepareSupport": true },
            }),
        };
        let workspace = match self.mode {
            ScalaProfileMode::PresentationCompiler => json!({}),
            ScalaProfileMode::Index => json!({ "symbol": {} }),
        };
        json!({
            "processId": null,
            "rootUri": root_uri,
            "workspaceFolders": [{ "uri": root_uri, "name": "lsp-fuzz" }],
            "capabilities": {
                "textDocument": text_document,
                "workspace": workspace,
            },
        })
    }
}

/// Fail closed unless `root` is a directory holding the verified backdrop markers: the metadata
/// file, the frozen BSP config, and at least one `SemanticDB` output file.
///
/// # Errors
///
/// Returns a message naming the first missing marker.
pub fn validate_backdrop_root(root: &Path) -> Result<(), String> {
    if !root.is_dir() {
        return Err(format!(
            "backdrop root is not a directory: {}",
            root.display()
        ));
    }
    if !root.join("backdrop-metadata.json").is_file() {
        return Err(format!(
            "backdrop root is missing backdrop-metadata.json: {}",
            root.display()
        ));
    }
    if !root.join("bsp").join("mill-bsp.json").is_file() {
        return Err(format!(
            "backdrop root is missing bsp/mill-bsp.json: {}",
            root.display()
        ));
    }
    if !contains_semanticdb(&root.join("semanticdb")) {
        return Err(format!(
            "backdrop root has no SemanticDB output under semanticdb/: {}",
            root.display()
        ));
    }
    Ok(())
}

/// Whether `dir` contains at least one `*.semanticdb` file (searched recursively).
fn contains_semanticdb(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if contains_semanticdb(&path) {
                return true;
            }
        } else if path.extension().is_some_and(|ext| ext == "semanticdb") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_and_index_allowlists_differ_as_specified() {
        let pc = ScalaExecutionProfile::presentation_compiler();
        let index = ScalaExecutionProfile::index();
        assert!(pc.allowed_methods().contains(&"textDocument/completion"));
        assert!(pc.allowed_methods().contains(&"textDocument/signatureHelp"));
        assert!(!pc.allowed_methods().contains(&"textDocument/references"));
        assert!(index.allowed_methods().contains(&"textDocument/references"));
        assert!(index.allowed_methods().contains(&"workspace/symbol"));
        assert!(!index.allowed_methods().contains(&"textDocument/completion"));
    }

    #[test]
    fn pc_capabilities_declare_signature_help() {
        let params = ScalaExecutionProfile::presentation_compiler().initialize_params("file:///w/");
        assert_eq!(params["rootUri"], "file:///w/");
        let td = &params["capabilities"]["textDocument"];
        assert!(td["completion"].is_object());
        assert!(td["hover"].is_object());
        assert!(td["signatureHelp"].is_object());
        assert!(td["definition"].is_object());
    }

    #[test]
    fn index_capabilities_use_rename_prepare_support_not_a_top_level_key() {
        let params = ScalaExecutionProfile::index().initialize_params("file:///w/");
        let td = &params["capabilities"]["textDocument"];
        // The mechanical builder would have produced a bogus top-level `prepareRename` key.
        assert!(td.get("prepareRename").is_none());
        assert_eq!(td["rename"]["prepareSupport"], true);
        assert!(params["capabilities"]["workspace"]["symbol"].is_object());
    }

    #[test]
    fn index_requires_sqlite_and_backdrop_env() {
        assert_eq!(
            ScalaExecutionProfile::index().required_env(),
            &["LS_SQLITE_LIB", "BACKDROP_OUT"]
        );
        assert!(
            ScalaExecutionProfile::presentation_compiler()
                .validate_environment()
                .is_ok()
        );
    }

    #[test]
    fn backdrop_validation_requires_all_markers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Empty dir: rejected.
        assert!(validate_backdrop_root(root).is_err());
        std::fs::write(root.join("backdrop-metadata.json"), b"{}").unwrap();
        assert!(validate_backdrop_root(root).is_err());
        std::fs::create_dir_all(root.join("bsp")).unwrap();
        std::fs::write(root.join("bsp").join("mill-bsp.json"), b"{}").unwrap();
        assert!(validate_backdrop_root(root).is_err());
        std::fs::create_dir_all(root.join("semanticdb").join("pkg")).unwrap();
        std::fs::write(
            root.join("semanticdb")
                .join("pkg")
                .join("A.scala.semanticdb"),
            b"x",
        )
        .unwrap();
        assert!(validate_backdrop_root(root).is_ok());
    }

    #[test]
    fn invalid_message_policy_zeroes_generation_when_off() {
        let mut profile = ScalaExecutionProfile::presentation_compiler();
        profile.generate_invalid_messages = false;
        let config = profile.apply_generation_policy(GeneratorsConfig::full());
        assert!(!config.invalid_input.positions);
        assert!(!config.invalid_input.ranges);
        assert!(config.invalid_input.code_frequency.abs() < f64::EPSILON);

        // With the policy on, the config keeps its invalid-input generation.
        let on = ScalaExecutionProfile::presentation_compiler()
            .apply_generation_policy(GeneratorsConfig::full());
        assert!(on.invalid_input.positions);
    }

    #[test]
    fn timeout_policy_is_per_mode_and_applied() {
        let pc = ScalaExecutionProfile::presentation_compiler();
        let index = ScalaExecutionProfile::index();
        assert_eq!(pc.run_timeout_ms(), 30_000);
        assert_eq!(pc.quiescence_deadline_ms(), 1_000);
        assert_eq!(index.run_timeout_ms(), 60_000);
        assert_eq!(index.quiescence_deadline_ms(), 3_000);
        // The transport reply deadline exceeds run + quiescence, and index waits longer than PC.
        assert!(pc.worker_reply_deadline() > pc.run_timeout() + pc.quiescence_deadline());
        assert!(index.worker_reply_deadline() > pc.worker_reply_deadline());
    }

    #[test]
    fn language_id_and_extensions_are_scala() {
        let profile = ScalaExecutionProfile::presentation_compiler();
        assert_eq!(profile.language_id(), "scala");
        assert_eq!(profile.file_extensions(), &["scala", "sc"]);
        assert_eq!(profile.language(), Language::Scala);
        assert_eq!(profile.mode(), ScalaProfileMode::PresentationCompiler);
    }

    #[test]
    fn determinism_flags_are_the_expected_set_for_both_modes() {
        let expected = [
            "-XX:-UseCompactObjectHeaders",
            "-Xshare:off",
            "-XX:+UseSerialGC",
        ];
        assert_eq!(
            ScalaExecutionProfile::index().determinism_flags(),
            &expected
        );
        assert_eq!(
            ScalaExecutionProfile::presentation_compiler().determinism_flags(),
            &expected
        );
    }

    #[test]
    fn missing_determinism_flags_detects_absent_and_wrong_sign_flags() {
        let profile = ScalaExecutionProfile::index();
        let complete: Vec<String> = [
            "java",
            "-XX:-UseCompactObjectHeaders",
            "-Xshare:off",
            "-XX:+UseSerialGC",
            "-cp",
            "ls.jar",
            "ls.core.Main",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert!(profile.missing_determinism_flags(&complete).is_empty());

        // The WRONG-sign compact-headers flag (`+` instead of `-`) does not satisfy the requirement,
        // and `-Xshare:off` / `+UseSerialGC` are absent → all three reported missing.
        let wrong: Vec<String> = ["java", "-XX:+UseCompactObjectHeaders", "-cp", "ls.jar"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            profile.missing_determinism_flags(&wrong),
            vec![
                "-XX:-UseCompactObjectHeaders",
                "-Xshare:off",
                "-XX:+UseSerialGC",
            ]
        );
    }
}
