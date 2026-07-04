//! The Scala execution profile.
//!
//! A [`ScalaExecutionProfile`] isolates everything Scala/language-server-specific about a fuzzing
//! run behind one value: the LSP `initialize` params + client capabilities, the language id and
//! file extensions, the per-régime LSP method allowlist, the intentional invalid-message generation
//! policy, the per-régime timeout windows, and the environment a régime requires. The JVM worker
//! envelope carries the profile's `initialize` params and allowlist so the embedded server is
//! initialized and driven exactly as the profile prescribes, while the generic virtual-workspace
//! path stays profile-free.

use std::time::Duration;

use lsp_fuzz_grammars::Language;
use serde_json::{Value, json};

/// The two régimes the target language server exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ScalaRegime {
    /// Presentation-compiler paths (completion/hover/definition on open buffers). The server runs
    /// this without a build; it is the default.
    #[default]
    #[value(name = "pc")]
    PresentationCompiler,
    /// Live BSP/index paths (references/rename/workspace-symbol) over a pre-indexed backdrop. Needs
    /// the pinned native `SQLite` library and a backdrop root.
    #[value(name = "index")]
    Index,
}

/// A Scala fuzzing profile: the language-server-facing policy for one régime.
#[derive(Debug, Clone)]
pub struct ScalaExecutionProfile {
    regime: ScalaRegime,
    generate_invalid_messages: bool,
}

impl ScalaExecutionProfile {
    /// The presentation-compiler régime (no BSP/index required).
    #[must_use]
    pub fn presentation_compiler() -> Self {
        Self {
            regime: ScalaRegime::PresentationCompiler,
            generate_invalid_messages: true,
        }
    }

    /// The BSP-backed index régime (requires the pinned `SQLite` + a backdrop).
    #[must_use]
    pub fn index() -> Self {
        Self {
            regime: ScalaRegime::Index,
            generate_invalid_messages: true,
        }
    }

    /// Build the profile for `regime`.
    #[must_use]
    pub fn for_regime(regime: ScalaRegime) -> Self {
        match regime {
            ScalaRegime::PresentationCompiler => Self::presentation_compiler(),
            ScalaRegime::Index => Self::index(),
        }
    }

    #[must_use]
    pub fn regime(&self) -> ScalaRegime {
        self.regime
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
    /// positions/ranges/params). Consumed by message generation config.
    #[must_use]
    pub fn generate_invalid_messages(&self) -> bool {
        self.generate_invalid_messages
    }

    /// The LSP methods this régime is allowed to drive. A stored message whose method is not in
    /// this set is dropped by the worker rather than forwarded to the server.
    #[must_use]
    pub fn allowed_methods(&self) -> &'static [&'static str] {
        const PC: &[&str] = &[
            "textDocument/didOpen",
            "textDocument/didChange",
            "textDocument/didClose",
            "textDocument/completion",
            "textDocument/hover",
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
        match self.regime {
            ScalaRegime::PresentationCompiler => PC,
            ScalaRegime::Index => INDEX,
        }
    }

    /// The per-input run timeout (the direct message sequence).
    #[must_use]
    pub fn run_timeout(&self) -> Duration {
        match self.regime {
            ScalaRegime::PresentationCompiler => Duration::from_secs(30),
            ScalaRegime::Index => Duration::from_mins(1),
        }
    }

    /// The quiescence deadline (background settle) after the direct sequence returns.
    #[must_use]
    pub fn quiescence_deadline(&self) -> Duration {
        match self.regime {
            ScalaRegime::PresentationCompiler => Duration::from_secs(1),
            ScalaRegime::Index => Duration::from_secs(3),
        }
    }

    /// Environment variables this régime requires to be set before it can run.
    #[must_use]
    pub fn required_env(&self) -> &'static [&'static str] {
        match self.regime {
            ScalaRegime::PresentationCompiler => &[],
            // The index path opens a SQLite MetaStore through the FFM binding, which must use the
            // language server's pinned native library.
            ScalaRegime::Index => &["LS_SQLITE_LIB"],
        }
    }

    /// Verify the required environment for this régime is present.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the first missing variable.
    pub fn validate_environment(&self) -> Result<(), String> {
        for var in self.required_env() {
            if std::env::var_os(var).is_none() {
                return Err(format!(
                    "the Scala {:?} régime requires the {var} environment variable to be set",
                    self.regime
                ));
            }
        }
        Ok(())
    }

    /// Build the LSP `initialize` params for this profile, rooted at `root_uri`. Client capabilities
    /// declare exactly the features this régime drives.
    #[must_use]
    pub fn initialize_params(&self, root_uri: &str) -> Value {
        let mut text_document = serde_json::Map::new();
        for method in self.allowed_methods() {
            if let Some(feature) = method.strip_prefix("textDocument/") {
                // didOpen/didChange/didClose are synchronization, not standalone capabilities.
                if matches!(feature, "didOpen" | "didChange" | "didClose") {
                    continue;
                }
                text_document.insert(feature.to_owned(), json!({}));
            }
        }
        let mut workspace = serde_json::Map::new();
        if self.allowed_methods().contains(&"workspace/symbol") {
            workspace.insert("symbol".to_owned(), json!({}));
        }
        json!({
            "processId": null,
            "rootUri": root_uri,
            "workspaceFolders": [{ "uri": root_uri, "name": "lsp-fuzz" }],
            "capabilities": {
                "textDocument": Value::Object(text_document),
                "workspace": Value::Object(workspace),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pc_and_index_allowlists_differ_as_specified() {
        let pc = ScalaExecutionProfile::presentation_compiler();
        let index = ScalaExecutionProfile::index();
        assert!(pc.allowed_methods().contains(&"textDocument/completion"));
        assert!(!pc.allowed_methods().contains(&"textDocument/references"));
        assert!(index.allowed_methods().contains(&"textDocument/references"));
        assert!(index.allowed_methods().contains(&"workspace/symbol"));
        assert!(!index.allowed_methods().contains(&"textDocument/completion"));
    }

    #[test]
    fn initialize_params_carry_root_and_capabilities() {
        let profile = ScalaExecutionProfile::presentation_compiler();
        let params = profile.initialize_params("file:///tmp/ws/");
        assert_eq!(params["rootUri"], "file:///tmp/ws/");
        assert_eq!(params["workspaceFolders"][0]["uri"], "file:///tmp/ws/");
        assert!(params["capabilities"]["textDocument"]["completion"].is_object());
        assert!(params["capabilities"]["textDocument"]["hover"].is_object());
        // didOpen is synchronization, not a standalone capability.
        assert!(
            params["capabilities"]["textDocument"]
                .get("didOpen")
                .is_none()
        );
    }

    #[test]
    fn index_requires_sqlite_env() {
        let index = ScalaExecutionProfile::index();
        assert_eq!(index.required_env(), &["LS_SQLITE_LIB"]);
        // PC needs nothing.
        assert!(
            ScalaExecutionProfile::presentation_compiler()
                .validate_environment()
                .is_ok()
        );
    }

    #[test]
    fn language_id_and_extensions_are_scala() {
        let profile = ScalaExecutionProfile::presentation_compiler();
        assert_eq!(profile.language_id(), "scala");
        assert_eq!(profile.file_extensions(), &["scala", "sc"]);
        assert_eq!(profile.language(), Language::Scala);
    }
}
