//! Workspace materialization for the JVM worker.
//!
//! A [`WorkspaceMaterializer`] isolates *how* a fuzzer input's workspace is placed on disk for the
//! in-process language server, and what root the server initializes against. Two strategies:
//!
//! - [`GenericTempRootMaterializer`] writes the whole input workspace under a per-input directory in
//!   a temp root and initializes at that temp root — the mode used for the presentation-compiler
//!   profile and matching the previous inline behavior exactly.
//! - [`BackdropOverlayMaterializer`] keeps a verified, immutable pre-indexed backdrop root and writes
//!   only the input's source files as a per-input overlay under it, never re-copying the frozen
//!   `zaozi` tree — the substrate the index profile needs. The server initializes at the backdrop
//!   root so both the frozen index and the overlay are inside the initialized root.
//!
//! The generic virtual-FS / native `request_bytes` path is unaffected: only the JVM converter routes
//! through a materializer.

use std::{
    io,
    path::{Path, PathBuf},
};

use derive_new::new as New;

use super::{LspInput, uri};
use crate::execution::{scala_profile::validate_backdrop_root, workspace_observer::HasWorkspace};

/// The result of materializing one input: the initialized `file://` root and the directory the
/// input's message URIs localize to (both inside that root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialized {
    pub root_uri: String,
    pub localization_dir: PathBuf,
}

/// Places an input's workspace on disk and reports the root to initialize against.
pub trait WorkspaceMaterializer: std::fmt::Debug {
    /// Materialize `input` (idempotent for an identical input).
    ///
    /// # Errors
    ///
    /// Returns any I/O error creating directories/files, or an invalid-backdrop error for the index
    /// materializer.
    fn materialize(&self, input: &LspInput) -> io::Result<Materialized>;
}

/// Build the `file://<dir>/` root URI for `dir`.
fn file_uri(dir: &Path) -> String {
    uri::workspace_uri(dir)
        .map(|path| format!("file://{path}"))
        .unwrap_or_default()
}

/// Writes the full input workspace under `<workspace_root>/lsp-fuzz-workspace_<hash>` and
/// initializes at `workspace_root` (every per-input directory is inside it).
#[derive(Debug, New)]
pub struct GenericTempRootMaterializer {
    workspace_root: PathBuf,
}

impl WorkspaceMaterializer for GenericTempRootMaterializer {
    fn materialize(&self, input: &LspInput) -> io::Result<Materialized> {
        let dir = self.workspace_root.join(format!(
            "{}{}",
            LspInput::WORKSPACE_DIR_PREFIX,
            input.workspace_hash()
        ));
        std::fs::create_dir_all(&dir)?;
        input.setup_workspace(&dir)?;
        Ok(Materialized {
            root_uri: file_uri(&self.workspace_root),
            localization_dir: dir,
        })
    }
}

/// Keeps a verified, immutable pre-indexed backdrop root and writes only the input's files as a
/// per-input overlay under it. The frozen `sources/`/`semanticdb/`/`bsp/` content is never touched
/// and the tree is never re-copied; the server initializes at the backdrop root.
///
/// Coverage/indexing note: the overlay is a per-input *dirty buffer* placed under the
/// `.lsp-fuzz-overlay/` scratch dir, which is OUTSIDE the frozen, pre-indexed `sources/` tree — so
/// an overlay file has no `SemanticDB` of its own. On a substrate that only carries the recovered
/// index and has no live build server, the index is empty until a build target produces
/// `SemanticDB`, so semantic
/// requests (`textDocument/references`, `textDocument/rename`) over the overlay return
/// `-32803 "… has no SemanticDB output"`. That path still fuzzes the server's index request
/// dispatch, lifecycle, and error-oracle surface (a crash there is a genuine finding); the semantic
/// *result* surface (real reference/rename locations) requires a build-server-backed indexed
/// workspace and is validated by the live reindex gate script under `jvm-coverage-agent/`
/// (references/rename over the frozen backdrop with a live build server attached).
#[derive(Debug, New)]
pub struct BackdropOverlayMaterializer {
    backdrop_root: PathBuf,
}

impl BackdropOverlayMaterializer {
    /// The parent directory holding per-input overlays (scratch, not part of the frozen backdrop).
    const OVERLAY_DIR: &str = ".lsp-fuzz-overlay";
}

impl WorkspaceMaterializer for BackdropOverlayMaterializer {
    fn materialize(&self, input: &LspInput) -> io::Result<Materialized> {
        // Fail closed unless the frozen backdrop is present and verified.
        validate_backdrop_root(&self.backdrop_root)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Per-input overlay under the backdrop root — only the input's files, no tree re-copy. The
        // overlay parent is cleared first so overlays never accumulate; the frozen content (checked
        // above) is untouched.
        let overlay_parent = self.backdrop_root.join(Self::OVERLAY_DIR);
        let _ = std::fs::remove_dir_all(&overlay_parent);
        let overlay = overlay_parent.join(format!(
            "{}{}",
            LspInput::WORKSPACE_DIR_PREFIX,
            input.workspace_hash()
        ));
        std::fs::create_dir_all(&overlay)?;
        input.setup_workspace(&overlay)?;
        Ok(Materialized {
            root_uri: file_uri(&self.backdrop_root),
            localization_dir: overlay,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        file_system::{FileSystemDirectory, FileSystemEntry},
        lsp_input::{WorkspaceEntry, messages::LspMessageSequence},
        text_document::TextDocument,
        utf8::Utf8Input,
    };
    use lsp_fuzz_grammars::Language;

    fn scala_input() -> LspInput {
        let mut doc = TextDocument::new(Language::Scala, "object A:\n  def x = 1\n".into());
        doc.update_metadata();
        LspInput {
            messages: LspMessageSequence::default(),
            workspace: FileSystemDirectory::from([(
                Utf8Input::new("main.scala".to_owned()),
                FileSystemEntry::File(WorkspaceEntry::SourceFile(doc)),
            )]),
        }
    }

    /// The generic materializer keeps the previous behavior: workspace under a per-input dir in the
    /// temp root, initialized at the temp root.
    #[test]
    fn generic_materializer_uses_temp_root() {
        let tmp = tempfile::tempdir().unwrap();
        let m = GenericTempRootMaterializer::new(tmp.path().to_path_buf());
        let input = scala_input();
        let out = m.materialize(&input).unwrap();
        assert_eq!(out.root_uri, format!("file://{}/", tmp.path().display()));
        assert!(out.localization_dir.starts_with(tmp.path()));
        assert!(out.localization_dir.join("main.scala").is_file());
    }

    fn write_frozen_backdrop(root: &Path) {
        std::fs::write(root.join("backdrop-metadata.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("bsp")).unwrap();
        std::fs::write(root.join("bsp").join("mill-bsp.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("semanticdb").join("pkg")).unwrap();
        std::fs::write(
            root.join("semanticdb")
                .join("pkg")
                .join("Frozen.scala.semanticdb"),
            b"sdb",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("sources").join("mod")).unwrap();
        std::fs::write(
            root.join("sources").join("mod").join("Frozen.scala"),
            b"object Frozen\n",
        )
        .unwrap();
    }

    /// The backdrop materializer writes only the input's overlay under the backdrop root, leaves the
    /// frozen content untouched, does not re-copy the tree, and initializes at the backdrop root.
    #[test]
    fn backdrop_materializer_overlays_without_recopy() {
        let tmp = tempfile::tempdir().unwrap();
        let backdrop = tmp.path();
        write_frozen_backdrop(backdrop);

        let m = BackdropOverlayMaterializer::new(backdrop.to_path_buf());
        let out = m.materialize(&scala_input()).unwrap();

        // Initialized at the backdrop root; overlay is inside it.
        assert_eq!(out.root_uri, format!("file://{}/", backdrop.display()));
        assert!(out.localization_dir.starts_with(backdrop));
        assert!(out.localization_dir.join("main.scala").is_file());

        // The frozen backdrop content is untouched.
        assert!(
            backdrop
                .join("sources")
                .join("mod")
                .join("Frozen.scala")
                .is_file()
        );
        assert!(
            backdrop
                .join("semanticdb")
                .join("pkg")
                .join("Frozen.scala.semanticdb")
                .is_file()
        );

        // The overlay holds only the input's file — the zaozi tree is not re-copied into it.
        assert!(!out.localization_dir.join("sources").exists());
        assert!(!out.localization_dir.join("semanticdb").exists());
    }

    #[test]
    fn backdrop_materializer_rejects_an_unverified_root() {
        let tmp = tempfile::tempdir().unwrap();
        // No markers written: fail closed.
        let m = BackdropOverlayMaterializer::new(tmp.path().to_path_buf());
        assert!(m.materialize(&scala_input()).is_err());
    }
}
