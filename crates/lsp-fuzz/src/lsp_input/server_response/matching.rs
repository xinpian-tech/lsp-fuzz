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
    use crate::lsp::{LspMessage, json_rpc::JsonRPCMessage};

    const BACKDROP: &str = "/verified-backdrop";
    // A frozen backdrop source (has SemanticDB) and a per-input dirty overlay file, in the exact
    // on-disk layout the BackdropOverlayMaterializer produces under the backdrop root.
    const BACKDROP_LOC: &str = "file:///verified-backdrop/sources/rvdecoderdb/X.scala";
    const OVERLAY_LOC: &str =
        "file:///verified-backdrop/.lsp-fuzz-overlay/lsp-fuzz-workspace_9/main.scala";

    fn request(method: &str, params: serde_json::Value) -> LspMessage {
        LspMessage::try_from_json(method, params).unwrap()
    }

    fn range() -> serde_json::Value {
        serde_json::json!({ "start": { "line": 0, "character": 0 },
                            "end": { "line": 0, "character": 3 } })
    }

    /// End-to-end proof through the production response-matching + lifting path (the same
    /// `match_messages` JVM fuzzing / cold replay uses): a `textDocument/references` `Location[]` and a
    /// `textDocument/rename` `WorkspaceEdit` (keyed by URI in `changes`) that mix a frozen
    /// backdrop-source URI and a per-input overlay URI are matched to their stored requests and lifted
    /// with the backdrop root supplied. Both must surface only virtual URIs
    /// (`lsp-fuzz://backdrop/sources/...` for the indexed file, `lsp-fuzz://...` for the dirty overlay)
    /// with NO raw host `file://` remaining — the dirty-buffer→indexed-file mapping the Scala index
    /// path requires.
    #[test]
    fn references_and_rename_responses_lift_backdrop_and_overlay_uris() {
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
        // Requests are numbered by order (id 1, id 2), matching `match_messages`.
        let refs_response = JsonRPCMessage::response(
            Some(1usize),
            Some(serde_json::json!([
                { "uri": BACKDROP_LOC, "range": range() },
                { "uri": OVERLAY_LOC, "range": range() }
            ])),
            None,
        );
        let rename_response = JsonRPCMessage::response(
            Some(2usize),
            Some(serde_json::json!({
                "changes": {
                    BACKDROP_LOC: [ { "range": range(), "newText": "Renamed" } ],
                    OVERLAY_LOC: [ { "range": range(), "newText": "Renamed" } ]
                }
            })),
            None,
        );

        let sent = [refs.clone(), rename.clone()];
        let received = [refs_response, rename_response];
        let matching =
            RequestResponseMatching::match_messages(sent.iter(), received.iter(), Some(BACKDROP))
                .expect("responses match their stored requests");

        for (label, req) in [("references", &refs), ("rename", &rename)] {
            let response = matching
                .find_response_of(req)
                .unwrap_or_else(|| panic!("{label} response should be matched"));
            let json = serde_json::to_string(response).unwrap();
            assert!(
                json.contains("lsp-fuzz://backdrop/sources/rvdecoderdb/X.scala"),
                "{label}: the frozen backdrop source URI must lift to the virtual backdrop form: {json}"
            );
            assert!(
                json.contains("lsp-fuzz://main.scala"),
                "{label}: the dirty overlay URI must lift to the virtual workspace form: {json}"
            );
            assert!(
                !json.contains("file://"),
                "{label}: no raw host file:// URI may remain in the lifted response: {json}"
            );
        }
    }
}
