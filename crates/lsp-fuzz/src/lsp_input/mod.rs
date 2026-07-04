use std::{
    borrow::Cow,
    fs::File,
    hash::{DefaultHasher, Hash, Hasher},
    io::BufWriter,
    path::{Path, PathBuf},
};

use derive_new::new as New;
use libafl::{
    HasMetadata,
    corpus::CorpusId,
    generators::Generator,
    inputs::{BytesInput, HasTargetBytes, Input, ToTargetBytes},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand},
};
use libafl_bolts::{HasLen, Named, ownedref::OwnedSlice, rands::Rand};
use lsp_fuzz_grammars::Language;
use lsp_types::Uri;
use messages::LspMessageSequence;
use serde::{Deserialize, Serialize};

use crate::{
    execution::scala_profile::ScalaExecutionProfile,
    execution::workspace_observer::HasWorkspace,
    file_system::{FileSystemDirectory, FileSystemEntry},
    lsp,
    text_document::{
        GrammarBasedMutation, TextDocument,
        generation::{GrammarContextLookup, NamedNodeGenerator, RandomRuleSelectionStrategy},
    },
    utils::AflContext,
};

pub type FileContentInput = BytesInput;

pub mod materializer;
pub mod message_edit;
pub mod messages;
pub mod ops_curiosity;
pub mod server_response;
mod session;
pub mod uri;

/// An entry in the LSP server workspace
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkspaceEntry {
    /// A text document that will be sent to the LSP server
    ///
    /// A `textDocument/didOpen` will be issued for this entry after LSP server initialization.
    SourceFile(TextDocument),

    /// A skeleton file within the workspace
    ///
    /// The file will not be sent to the LSP server after initialization.
    /// It is only written to the workspace directory for LSP servers that needs it.
    /// (e.g., `package.json`, `Cargo.toml`).
    Skeleton(Vec<u8>),
}

impl WorkspaceEntry {
    #[must_use]
    pub const fn as_source_file(&self) -> Option<&TextDocument> {
        if let WorkspaceEntry::SourceFile(doc) = self {
            Some(doc)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn as_source_file_mut(&mut self) -> Option<&mut TextDocument> {
        if let WorkspaceEntry::SourceFile(doc) = self {
            Some(doc)
        } else {
            None
        }
    }

    #[must_use]
    pub fn as_skeleton(&self) -> Option<&[u8]> {
        if let WorkspaceEntry::Skeleton(bytes) = self {
            Some(bytes.as_slice())
        } else {
            None
        }
    }

    #[must_use]
    pub const fn as_skeleton_mut(&mut self) -> Option<&mut Vec<u8>> {
        if let WorkspaceEntry::Skeleton(bytes) = self {
            Some(bytes)
        } else {
            None
        }
    }
}

impl HasLen for WorkspaceEntry {
    fn len(&self) -> usize {
        match self {
            WorkspaceEntry::SourceFile(doc) => doc.len(),
            WorkspaceEntry::Skeleton(bytes) => bytes.len(),
        }
    }
}

impl HasTargetBytes for WorkspaceEntry {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        match self {
            WorkspaceEntry::SourceFile(doc) => doc.target_bytes(),
            WorkspaceEntry::Skeleton(bytes) => bytes.as_slice().into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct LspInput {
    pub messages: LspMessageSequence,
    pub workspace: FileSystemDirectory<WorkspaceEntry>,
}

impl LspInput {
    pub const NAME_PREFIX: &str = "input_";
    pub const PROTOCOL_PREFIX: &str = "lsp-fuzz://";
    pub const PROROCOL_PREFIX: &str = Self::PROTOCOL_PREFIX;

    #[must_use]
    pub fn root_uri() -> Uri {
        uri::root_uri()
    }

    /// Retrieves a text document from the workspace by its URI.
    ///
    /// This function looks up a text document in the workspace using the provided URI.
    /// The URI must have the prefix specified by `LspInput::PROROCOL_PREFIX` as it maps to
    /// the fuzzer's virtual file system.
    ///
    /// # Arguments
    ///
    /// * `uri` - The URI of the text document to retrieve
    ///
    /// # Returns
    ///
    /// * `Some(&TextDocument)` - The found text document
    /// * `None` - If no text document exists at the given URI or if the entry is not a source file
    ///
    /// # Panics
    ///
    /// Panics if `uri` does not start with [`LspInput::PROROCOL_PREFIX`].
    ///
    #[must_use]
    pub fn get_text_document(&self, uri: &lsp_types::Uri) -> Option<&TextDocument> {
        let path =
            uri::path_from_virtual_uri(uri).expect("The URI must start with the fuzzer URI scheme");
        if let Some(FileSystemEntry::File(WorkspaceEntry::SourceFile(doc))) =
            self.workspace.get(path)
        {
            Some(doc)
        } else {
            None
        }
    }
}

impl Input for LspInput {
    fn generate_name(&self, id: Option<CorpusId>) -> String {
        let id_str = id.map_or_else(
            || {
                let mut hasher = DefaultHasher::new();
                self.hash(&mut hasher);
                format!("h_{}", hasher.finish())
            },
            |it| it.to_string(),
        );
        format!("{}{}", Self::NAME_PREFIX, id_str)
    }

    fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    where
        P: AsRef<Path>,
    {
        let file = File::create(path)?;
        let buf_writer = BufWriter::new(file);
        ciborium::into_writer(self, buf_writer)
            .map_err(|e| libafl::Error::serialize(format!("{e:#?}")))
    }

    fn from_file<P>(path: P) -> Result<Self, libafl::Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(path)?;
        let buf_reader = std::io::BufReader::new(file);
        ciborium::from_reader(buf_reader).map_err(|e| libafl::Error::serialize(format!("{e:#?}")))
    }
}

impl HasLen for LspInput {
    fn len(&self) -> usize {
        self.messages.len() + self.workspace.len()
    }
}

#[derive(Debug, New)]
pub struct LspInputBytesConverter {
    workspace_root: PathBuf,
}

impl ToTargetBytes<LspInput> for LspInputBytesConverter {
    fn to_target_bytes<'a>(&mut self, input: &'a LspInput) -> OwnedSlice<'a, u8> {
        let input_hash = input.workspace_hash();
        let workspace_dir = self
            .workspace_root
            .join(format!("{}{input_hash}", LspInput::WORKSPACE_DIR_PREFIX));
        input.request_bytes(&workspace_dir).into()
    }
}

/// Target-bytes converter for the JVM in-process worker.
///
/// Unlike [`LspInputBytesConverter`] (which yields a bare LSP wire stream for the native fork
/// server), this materializes the input's workspace on disk so the embedded language server can read
/// the source files, and emits a self-describing envelope the worker parses:
///
/// ```text
/// <u32-le n><rootUri>  <u32-le n><initializeParams JSON>  <u32-le n><allowed methods, \n-separated>
/// <localized framed JSON-RPC stream>
/// ```
///
/// The `initialize` params + method allowlist come from the [`ScalaExecutionProfile`], so the worker
/// initializes and gates the server exactly as the profile prescribes. The stream is the same
/// localized `initialize … exit` message sequence [`LspInput::request_bytes`] produces (virtual
/// `lsp-fuzz://` URIs rewritten to the materialized `file://` workspace); the worker owns lifecycle
/// (`initialize`/`initialized`/`shutdown`/`exit`) and replays the per-input `didOpen`s and stored
/// messages from that stream, so mutating `input.messages`/`input.workspace` changes exactly what the
/// real server executes.
#[derive(Debug)]
pub struct JvmLspInputConverter {
    profile: ScalaExecutionProfile,
    materializer: Box<dyn materializer::WorkspaceMaterializer>,
}

impl JvmLspInputConverter {
    /// Build the converter for `profile`, choosing the materializer by mode: the presentation
    /// compiler uses a generic temp root under `workspace_root`; the index mode overlays a verified
    /// backdrop taken from `BACKDROP_OUT` (falling back to `workspace_root` if unset — the profile's
    /// environment validation rejects a missing/invalid backdrop before this point).
    #[must_use]
    pub fn new(workspace_root: PathBuf, profile: ScalaExecutionProfile) -> Self {
        use crate::execution::scala_profile::ScalaProfileMode;
        let materializer: Box<dyn materializer::WorkspaceMaterializer> = match profile.mode() {
            ScalaProfileMode::PresentationCompiler => Box::new(
                materializer::GenericTempRootMaterializer::new(workspace_root),
            ),
            ScalaProfileMode::Index => {
                let backdrop = std::env::var_os("BACKDROP_OUT")
                    .map(PathBuf::from)
                    .unwrap_or(workspace_root);
                Box::new(materializer::BackdropOverlayMaterializer::new(backdrop))
            }
        };
        Self {
            profile,
            materializer,
        }
    }
}

impl ToTargetBytes<LspInput> for JvmLspInputConverter {
    fn to_target_bytes<'a>(&mut self, input: &'a LspInput) -> OwnedSlice<'a, u8> {
        // Materialization failure must not silently replay an input against a missing workspace
        // (`ToTargetBytes` cannot return an error), so fail loudly with context.
        let placed = self
            .materializer
            .materialize(input)
            .unwrap_or_else(|e| panic!("failed to materialize the JVM workspace: {e}"));

        // The epoch is initialized once against the materializer's root, so every input's documents
        // (localized under it) live inside the initialized root even though `initialize` is sent
        // only once.
        let init_params = self.profile.initialize_params(&placed.root_uri).to_string();
        let allowed_methods = self.profile.allowed_methods().join("\n");
        let stream = input.request_bytes(&placed.localization_dir);

        let mut envelope = Vec::with_capacity(
            12 + placed.root_uri.len() + init_params.len() + allowed_methods.len() + stream.len(),
        );
        push_length_prefixed(&mut envelope, placed.root_uri.as_bytes());
        push_length_prefixed(&mut envelope, init_params.as_bytes());
        push_length_prefixed(&mut envelope, allowed_methods.as_bytes());
        envelope.extend_from_slice(&stream);
        envelope.into()
    }
}

/// Append `<u32-le len><bytes>` to `out`.
fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(0);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

impl HasWorkspace for LspInput {
    fn workspace_hash(&self) -> u64 {
        let mut hasher = ahash::AHasher::default();
        self.workspace.hash(&mut hasher);
        hasher.finish()
    }

    fn setup_workspace(&self, workspace_root: &Path) -> Result<(), std::io::Error> {
        self.workspace.write_to_fs(workspace_root)
    }
}

impl LspInput {
    pub const WORKSPACE_DIR_PREFIX: &str = "lsp-fuzz-workspace_";

    /// Converts a localized `file://` workspace URI back into the virtual `lsp-fuzz://` form.
    ///
    /// # Panics
    ///
    /// Panics if the lifted URI cannot be parsed back into a valid [`Uri`].
    #[must_use]
    pub fn lift_uri(uri: &lsp_types::Uri) -> Cow<'_, lsp_types::Uri> {
        uri::lift_uri(uri)
    }

    /// Serializes the full LSP session into wire-format payload bytes.
    ///
    /// # Panics
    ///
    /// Panics if `workspace_dir` is not valid UTF-8.
    #[must_use]
    pub fn request_bytes(&self, workspace_dir: &Path) -> Vec<u8> {
        session::request_bytes(self, workspace_dir)
    }

    /// Expands the stored input into the complete LSP session message stream.
    ///
    /// # Panics
    ///
    /// Panics if a workspace source file path is not valid UTF-8 or if a generated virtual URI
    /// cannot be parsed as an [`Uri`].
    pub fn message_sequence(&self) -> impl Iterator<Item = lsp::LspMessage> + use<'_> {
        session::message_sequence(self)
    }
}

#[derive(Debug, derive_more::Constructor)]
pub struct LspInputMutator<TM, RM> {
    text_document_mutator: TM,
    requests_mutator: RM,
}

impl<TM, RM> Named for LspInputMutator<TM, RM> {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("LspInputMutator");
        &NAME
    }
}

impl<TM, RM, State> Mutator<LspInput, State> for LspInputMutator<TM, RM>
where
    TM: Mutator<LspInput, State>,
    RM: Mutator<LspInput, State>,
    State: HasMetadata + HasCorpus<LspInput> + HasMaxSize + HasRand,
{
    fn mutate(
        &mut self,
        state: &mut State,
        input: &mut LspInput,
    ) -> Result<MutationResult, libafl::Error> {
        let mut result = MutationResult::Skipped;
        if state.rand_mut().coinflip(0.5)
            && self.text_document_mutator.mutate(state, input)? == MutationResult::Mutated
        {
            result = MutationResult::Mutated;
        }
        if self.requests_mutator.mutate(state, input)? == MutationResult::Mutated {
            result = MutationResult::Mutated;
        }
        Ok(result)
    }

    fn post_exec(
        &mut self,
        state: &mut State,
        new_corpus_id: Option<CorpusId>,
    ) -> Result<(), libafl::Error> {
        self.text_document_mutator.post_exec(state, new_corpus_id)?;
        self.requests_mutator.post_exec(state, new_corpus_id)?;
        Ok(())
    }
}

#[derive(Debug, New)]
pub struct LspInputGenerator<'a> {
    grammar_lookup: &'a GrammarContextLookup,
}

impl<State> Generator<LspInput, State> for LspInputGenerator<'_>
where
    State: HasRand,
{
    fn generate(&mut self, state: &mut State) -> Result<LspInput, libafl::Error> {
        let rand = state.rand_mut();
        let grammar = rand
            .choose(self.grammar_lookup.iter())
            .afl_context("The grammar lookup context is empry")?;
        let language = grammar.language();
        let ext = rand
            .choose(language.file_extensions())
            .afl_context("The language has no extensions")?;
        let document_content = loop {
            let selection_strategy = RandomRuleSelectionStrategy;
            let generator = NamedNodeGenerator::new(grammar, selection_strategy);
            let generate_node = generator.generate(grammar.start_symbol(), state);
            if let Ok(code) = generate_node {
                break code;
            }
        };
        let mut text_document = TextDocument::new(language, document_content.clone());
        text_document.update_metadata();

        let workspace = session::workspace_for_document(language, text_document, ext);
        Ok(LspInput {
            messages: LspMessageSequence::default(),
            workspace,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_lift_uri() {
        // Given a URI with workspace prefix
        let uri_str = "file:///tmp/lsp-fuzz-workspace_2333/abc/file.rs".to_owned();
        let uri = Uri::from_str(&uri_str).unwrap();

        // When lifting the URI
        let lifted = LspInput::lift_uri(&uri);

        // Then the result has fuzzer protocol prefix and workspace path
        assert_eq!(
            lifted.as_str(),
            format!("{}/abc/file.rs", LspInput::PROTOCOL_PREFIX)
        );

        // Given a URI without workspace prefix
        let uri = Uri::from_str("file:///other/path").unwrap();

        // When lifting the URI
        let lifted = LspInput::lift_uri(&uri);

        // Then the original URI is returned unchanged
        assert_eq!(lifted.as_str(), "file:///other/path");
    }

    /// Read a `<u32-le len><bytes>` section at `*pos`, advancing `*pos`.
    fn read_section<'a>(payload: &'a [u8], pos: &mut usize) -> &'a [u8] {
        let len = u32::from_le_bytes(payload[*pos..*pos + 4].try_into().unwrap()) as usize;
        let start = *pos + 4;
        *pos = start + len;
        &payload[start..start + len]
    }

    fn scala_input() -> LspInput {
        use crate::utf8::Utf8Input;
        let mut doc = TextDocument::new(Language::Scala, "object A:\n  def x = 1\n".into());
        doc.update_metadata();
        let workspace = FileSystemDirectory::from([(
            Utf8Input::new("main.scala".to_owned()),
            FileSystemEntry::File(WorkspaceEntry::SourceFile(doc)),
        )]);
        LspInput {
            messages: LspMessageSequence::default(),
            workspace,
        }
    }

    #[test]
    fn jvm_envelope_carries_profile_root_params_and_allowlist() {
        use crate::execution::scala_profile::ScalaExecutionProfile;

        let tmp = tempfile::tempdir().unwrap();
        let input = scala_input();

        // Presentation-compiler profile.
        let mut pc = JvmLspInputConverter::new(
            tmp.path().to_path_buf(),
            ScalaExecutionProfile::presentation_compiler(),
        );
        let bytes = pc.to_target_bytes(&input);
        let mut pos = 0;
        let root_uri = std::str::from_utf8(read_section(&bytes, &mut pos)).unwrap();
        let init_params = std::str::from_utf8(read_section(&bytes, &mut pos)).unwrap();
        let allowed = std::str::from_utf8(read_section(&bytes, &mut pos)).unwrap();

        assert!(root_uri.starts_with("file://") && root_uri.contains(tmp.path().to_str().unwrap()));
        assert!(
            init_params.contains(root_uri),
            "initialize params must carry the root"
        );
        assert!(
            init_params.contains("completion"),
            "PC capabilities declare completion"
        );
        assert!(allowed.lines().any(|m| m == "textDocument/completion"));
        assert!(allowed.lines().any(|m| m == "textDocument/hover"));
        assert!(!allowed.lines().any(|m| m == "textDocument/references"));
        // The stream (initialize .. exit frames) follows the three sections.
        assert!(
            pos < bytes.len(),
            "the framed LSP stream must follow the header sections"
        );

        // Index profile: the allowlist differs (references / workspace-symbol enabled). Index mode
        // materializes against a verified backdrop root, so seed `tmp` (its fallback root when
        // BACKDROP_OUT is unset) with the frozen backdrop markers.
        std::fs::write(tmp.path().join("backdrop-metadata.json"), b"{}").unwrap();
        std::fs::create_dir_all(tmp.path().join("bsp")).unwrap();
        std::fs::write(tmp.path().join("bsp").join("mill-bsp.json"), b"{}").unwrap();
        std::fs::create_dir_all(tmp.path().join("semanticdb")).unwrap();
        std::fs::write(
            tmp.path().join("semanticdb").join("A.scala.semanticdb"),
            b"x",
        )
        .unwrap();
        let mut index =
            JvmLspInputConverter::new(tmp.path().to_path_buf(), ScalaExecutionProfile::index());
        let bytes = index.to_target_bytes(&input);
        let mut pos = 0;
        let _root = read_section(&bytes, &mut pos);
        let _params = read_section(&bytes, &mut pos);
        let allowed = std::str::from_utf8(read_section(&bytes, &mut pos)).unwrap();
        assert!(allowed.lines().any(|m| m == "textDocument/references"));
        assert!(allowed.lines().any(|m| m == "workspace/symbol"));
        assert!(!allowed.lines().any(|m| m == "textDocument/completion"));
    }

    #[test]
    fn native_converter_is_unchanged_by_the_profile() {
        // The generic native path must stay profile-free: `request_bytes` bytes for the same input
        // do not depend on any Scala profile.
        let tmp = tempfile::tempdir().unwrap();
        let input = scala_input();
        let hash = input.workspace_hash();
        let dir = tmp
            .path()
            .join(format!("{}{hash}", LspInput::WORKSPACE_DIR_PREFIX));
        let native = input.request_bytes(&dir);
        let mut converter = LspInputBytesConverter::new(tmp.path().to_path_buf());
        let via_converter = converter.to_target_bytes(&input);
        assert_eq!(&*via_converter, native.as_slice());
    }
}
