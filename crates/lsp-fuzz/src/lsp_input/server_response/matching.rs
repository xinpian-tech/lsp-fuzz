use std::collections::HashMap;

use crate::lsp::{
    LspMessage, LspMessageMeta, MessageParam,
    json_rpc::{JsonRPCMessage, MessageId, ResponseError},
    message::{LspResponse, MessageDecodeError, lift_localized_json},
};

#[derive(Debug)]
pub struct RequestResponseMatching<'a> {
    pub responses: HashMap<&'a LspMessage, LspResponse>,
    pub errors: HashMap<&'a LspMessage, ResponseError>,
    pub notifications: Vec<LspMessage>,
    pub requests_from_server: Vec<LspMessage>,
}

impl<'a> RequestResponseMatching<'a> {
    pub fn find_notifications<'n, Notification: LspMessageMeta>(
        &'n self,
    ) -> impl Iterator<Item = &'n Notification::Params>
    where
        Notification::Params: MessageParam<Notification> + 'n,
    {
        self.notifications
            .iter()
            .filter_map(|it| Notification::Params::from_message_ref(it))
    }

    #[must_use]
    pub fn find_response_of(&self, request: &LspMessage) -> Option<&LspResponse> {
        self.responses.get(request)
    }

    /// `backdrop_root`, when set (Scala index mode), scopes frozen backdrop-source URI lifting to
    /// that root; the native path passes `None` (workspace/overlay lifting only).
    pub(crate) fn match_messages<'rec>(
        sent_messages: impl Iterator<Item = &'a LspMessage>,
        received_messages: impl Iterator<Item = &'rec JsonRPCMessage>,
        backdrop_root: Option<&str>,
    ) -> Result<Self, MessageDecodeError> {
        let mut responses = HashMap::new();
        let mut notifications = Vec::new();
        let mut requests_from_server = Vec::new();
        let mut errors = HashMap::new();

        let requests: HashMap<_, _> = sent_messages
            .filter(|it| it.is_request())
            .enumerate()
            .map(|(id, msg)| (MessageId::Number(id + 1), msg))
            .collect();

        for recv in received_messages {
            match recv {
                JsonRPCMessage::Request { method, params, .. } => {
                    let mut params = params.clone();
                    lift_localized_json(&mut params, backdrop_root);
                    let request = LspMessage::try_from_json(method, params)?;
                    requests_from_server.push(request);
                }
                JsonRPCMessage::Notification { method, params, .. } => {
                    let mut params = params.clone();
                    lift_localized_json(&mut params, backdrop_root);
                    let notification = LspMessage::try_from_json(method, params)?;
                    notifications.push(notification);
                }
                JsonRPCMessage::Response {
                    id: Some(id),
                    result,
                    error,
                    ..
                } => {
                    if let Some(msg) = requests.get(id).copied() {
                        if let Some(result) = result {
                            let mut result = result.clone();
                            lift_localized_json(&mut result, backdrop_root);
                            let response = LspResponse::try_from_json(msg.method(), result)?;
                            responses.insert(msg, response);
                        } else if let Some(error) = error {
                            errors.insert(msg, error.clone());
                        }
                    }
                }
                JsonRPCMessage::Response { .. } => {}
            }
        }

        Ok(Self {
            responses,
            errors,
            notifications,
            requests_from_server,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RequestResponseMatching;
    use crate::{
        execution::scala_profile::ScalaExecutionProfile,
        file_system::{FileSystemDirectory, FileSystemEntry},
        lsp::{LspMessage, json_rpc::JsonRPCMessage},
        lsp_input::{
            LspInput, WorkspaceEntry,
            materializer::{BackdropOverlayMaterializer, WorkspaceMaterializer},
            messages::LspMessageSequence,
        },
        text_document::TextDocument,
        utf8::Utf8Input,
    };
    use lsp_fuzz_grammars::Language;
    use std::path::Path;

    fn request(method: &str, params: serde_json::Value) -> LspMessage {
        LspMessage::try_from_json(method, params).unwrap()
    }

    fn range() -> serde_json::Value {
        serde_json::json!({ "start": { "line": 0, "character": 0 },
                            "end": { "line": 0, "character": 3 } })
    }

    /// A single-file index-mode input with a dirty overlay `main.scala`.
    fn index_input() -> LspInput {
        let mut doc = TextDocument::new(Language::Scala, "object M:\n  val n = 1\n".into());
        doc.update_metadata();
        LspInput {
            messages: LspMessageSequence::default(),
            workspace: FileSystemDirectory::from([(
                Utf8Input::new("main.scala".to_owned()),
                FileSystemEntry::File(WorkspaceEntry::SourceFile(doc)),
            )]),
        }
    }

    /// A valid frozen backdrop (the markers `validate_backdrop_root` requires + a `sources/` file).
    fn write_frozen_backdrop(root: &Path) {
        std::fs::write(root.join("backdrop-metadata.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("bsp")).unwrap();
        std::fs::write(root.join("bsp").join("mill-bsp.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.join("semanticdb").join("rvdecoderdb").join("src")).unwrap();
        std::fs::write(
            root.join("semanticdb")
                .join("rvdecoderdb")
                .join("src")
                .join("Instruction.scala.semanticdb"),
            b"sdb",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("sources").join("rvdecoderdb").join("src")).unwrap();
        std::fs::write(
            root.join("sources")
                .join("rvdecoderdb")
                .join("src")
                .join("Instruction.scala"),
            b"object Instruction\n",
        )
        .unwrap();
    }

    /// Run a `references` `Location[]` and rename `WorkspaceEdit` (in BOTH `changes` and
    /// `documentChanges` forms) through the PRODUCTION `match_messages` + lifting path — proving the
    /// dirty-buffer→indexed-file URI mapping the Scala index path requires. Crucially, the file:// URIs
    /// are DERIVED
    /// from the actual `BackdropOverlayMaterializer` output (the real localized overlay dir + the
    /// configured backdrop root), not hard-coded layout strings, so this exercises the same
    /// materializer/converter roots JVM fuzzing / cold replay thread into `match_messages`. Every
    /// matched response must serialize with only virtual URIs (`lsp-fuzz://backdrop/sources/...` for
    /// the frozen indexed source, `lsp-fuzz://…` for the dirty overlay) and NO raw host `file://`.
    #[test]
    fn references_and_rename_lift_uris_from_the_real_index_materializer() {
        let tmp = tempfile::tempdir().unwrap();
        let backdrop_root = tmp.path();
        write_frozen_backdrop(backdrop_root);

        // Materialize the index-mode input exactly as the JVM converter does: `ScalaExecutionProfile`
        // index mode selects the `BackdropOverlayMaterializer` (asserted below), and we take the ACTUAL
        // localized overlay dir it produces rather than duplicating the layout with string constants.
        assert_eq!(
            ScalaExecutionProfile::index().mode(),
            crate::execution::scala_profile::ScalaProfileMode::Index
        );
        let materializer = BackdropOverlayMaterializer::new(backdrop_root.to_path_buf());
        let placed = materializer.materialize(&index_input()).unwrap();
        assert!(
            placed.localization_dir.join("main.scala").is_file(),
            "the dirty overlay file must be materialized under the localized dir"
        );

        // URIs the real LS would return: the dirty overlay file (under the materialized localization
        // dir) and a frozen indexed source (under the configured backdrop root's `sources/`).
        let overlay_uri = format!(
            "file://{}/main.scala",
            placed.localization_dir.to_str().unwrap()
        );
        let backdrop_uri = format!(
            "file://{}/sources/rvdecoderdb/src/Instruction.scala",
            backdrop_root.to_str().unwrap()
        );
        // `match_messages` lifts frozen-source URIs scoped to this backdrop root (as cold replay
        // threads `config.backdrop_root`).
        let root = backdrop_root.to_str().unwrap();

        let refs = request(
            "textDocument/references",
            serde_json::json!({
                "textDocument": { "uri": "lsp-fuzz://main.scala" },
                "position": { "line": 0, "character": 0 },
                "context": { "includeDeclaration": true }
            }),
        );
        let rename = request(
            "textDocument/rename",
            serde_json::json!({
                "textDocument": { "uri": "lsp-fuzz://main.scala" },
                "position": { "line": 0, "character": 0 },
                "newName": "Renamed"
            }),
        );

        // Three response shapes, each matched on its own so `match_messages` numbers the request id 1.
        let references_result = serde_json::json!([
            { "uri": backdrop_uri, "range": range() },
            { "uri": overlay_uri, "range": range() }
        ]);
        let rename_changes = serde_json::json!({
            "changes": {
                backdrop_uri.clone(): [ { "range": range(), "newText": "Renamed" } ],
                overlay_uri.clone(): [ { "range": range(), "newText": "Renamed" } ]
            }
        });
        let rename_document_changes = serde_json::json!({
            "documentChanges": [
                { "textDocument": { "uri": backdrop_uri, "version": null },
                  "edits": [ { "range": range(), "newText": "Renamed" } ] },
                { "textDocument": { "uri": overlay_uri, "version": null },
                  "edits": [ { "range": range(), "newText": "Renamed" } ] }
            ]
        });

        for (label, req, result) in [
            ("references", &refs, references_result),
            ("rename changes", &rename, rename_changes),
            ("rename documentChanges", &rename, rename_document_changes),
        ] {
            let received = [JsonRPCMessage::response(Some(1usize), Some(result), None)];
            let sent = [req.clone()];
            let matching =
                RequestResponseMatching::match_messages(sent.iter(), received.iter(), Some(root))
                    .unwrap_or_else(|e| panic!("{label}: match_messages failed: {e:?}"));
            let response = matching
                .find_response_of(req)
                .unwrap_or_else(|| panic!("{label}: response should be matched"));
            let json = serde_json::to_string(response).unwrap();
            assert!(
                json.contains("lsp-fuzz://backdrop/sources/rvdecoderdb/src/Instruction.scala"),
                "{label}: the frozen indexed source URI must lift to the virtual backdrop form: {json}"
            );
            assert!(
                json.contains("lsp-fuzz://") && json.contains("main.scala"),
                "{label}: the dirty overlay URI must lift to the virtual workspace form: {json}"
            );
            assert!(
                !json.contains("file://"),
                "{label}: no raw host file:// URI may remain in the lifted response: {json}"
            );
        }
    }
}
