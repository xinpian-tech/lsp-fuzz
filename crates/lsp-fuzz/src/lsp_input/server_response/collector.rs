use std::collections::{HashSet, VecDeque};

use lsp_types::notification::PublishDiagnostics;

use super::{
    LspInput,
    matching::RequestResponseMatching,
    metadata::{Diagnostic, LspResponseInfo, ParamFragments, SymbolRange},
};
use crate::lsp::{LspMessage, message::LspResponse};

pub fn collect_response_info(matching: RequestResponseMatching<'_>) -> LspResponseInfo {
    let diagnostics = collect_diagnostics(&matching);
    let mut param_fragments = ParamFragments::default();
    let mut symbol_ranges = HashSet::new();

    let findings = crate::findings::findings_from_json_rpc_errors(
        matching.errors.iter().map(|(req, err)| (req.method(), err)),
    );

    for (req, res) in matching.responses {
        collect_response_fragments(req, res, &mut param_fragments, &mut symbol_ranges);
    }

    LspResponseInfo {
        diagnostics,
        param_fragments,
        symbol_ranges,
        findings,
    }
}

fn collect_diagnostics(matching: &RequestResponseMatching<'_>) -> HashSet<Diagnostic> {
    let mut diagnostics = HashSet::new();

    for pub_diag in matching.find_notifications::<PublishDiagnostics>() {
        let uri = LspInput::lift_uri(&pub_diag.uri);
        for diag_item in &pub_diag.diagnostics {
            diagnostics.insert(Diagnostic {
                uri: uri.as_ref().clone(),
                range: diag_item.range,
            });
        }
    }

    diagnostics
}

fn collect_response_fragments(
    req: &LspMessage,
    res: LspResponse,
    param_fragments: &mut ParamFragments,
    symbol_ranges: &mut HashSet<SymbolRange>,
) {
    match res {
        LspResponse::CodeActionRequest(cas) => {
            param_fragments.collect_code_actions(cas);
        }
        LspResponse::InlayHintRequest(inlay_hints) => {
            param_fragments.collect_inlay_hints(inlay_hints);
        }
        LspResponse::Completion(completion) => {
            param_fragments.collect_completion_items(completion);
        }
        LspResponse::CodeLensRequest(code_lens) => {
            param_fragments.collect_code_lens(code_lens);
        }
        LspResponse::WorkspaceSymbolRequest(Some(lsp_types::WorkspaceSymbolResponse::Nested(
            symbols,
        ))) => {
            param_fragments.collect_workspace_symbols(Some(symbols), symbol_ranges);
        }
        LspResponse::WorkspaceSymbolRequest(Some(lsp_types::WorkspaceSymbolResponse::Flat(
            symbols,
        )))
        | LspResponse::DocumentSymbolRequest(Some(lsp_types::DocumentSymbolResponse::Flat(
            symbols,
        ))) => {
            ParamFragments::collect_flat_symbol_ranges(Some(symbols), symbol_ranges);
        }
        LspResponse::DocumentSymbolRequest(Some(lsp_types::DocumentSymbolResponse::Nested(
            symbols,
        ))) => {
            collect_nested_document_symbols(req, symbols, symbol_ranges);
        }
        LspResponse::TypeHierarchyPrepare(items) => {
            param_fragments.collect_type_hierarchy_items(items);
        }
        LspResponse::CallHierarchyPrepare(items) => {
            param_fragments.collect_call_hierarchy_items(items);
        }
        LspResponse::DocumentLinkRequest(links) => {
            param_fragments.collect_document_links(links);
        }
        _ => {}
    }
}

fn collect_nested_document_symbols(
    req: &LspMessage,
    symbols: Vec<lsp_types::DocumentSymbol>,
    symbol_ranges: &mut HashSet<SymbolRange>,
) {
    if let LspMessage::DocumentSymbolRequest(req) = req {
        let mut queue = VecDeque::from_iter(symbols);
        while let Some(symbol) = queue.pop_front() {
            let mut symbol = symbol.clone();
            if let Some(children) = symbol.children.take() {
                queue.extend(children);
            }
            symbol_ranges.insert(SymbolRange::new(
                req.text_document.uri.clone(),
                symbol.selection_range,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use lsp_types::request::{Completion, HoverRequest, Request};

    use super::*;
    use crate::execution::outcome::OutcomeClass;
    use crate::lsp::json_rpc::ResponseError;

    fn hover_at(uri: &str) -> LspMessage {
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": { "line": 0, "character": 0 },
        });
        LspMessage::try_from_json(HoverRequest::METHOD, params).unwrap()
    }

    fn completion_at(uri: &str) -> LspMessage {
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": { "line": 0, "character": 0 },
        });
        LspMessage::try_from_json(Completion::METHOD, params).unwrap()
    }

    fn err(code: i32, message: &str) -> ResponseError {
        ResponseError {
            code,
            message: message.to_string(),
            data: None,
        }
    }

    #[test]
    fn json_rpc_errors_become_deduped_findings() {
        // Two distinct hover requests fail with the same error (bar the line number), and one
        // completion request fails differently. The oracle must dedup the hover pair into one
        // finding and keep the completion finding, for two distinct findings total.
        let hover_a = hover_at("lsp-fuzz://a.scala");
        let hover_b = hover_at("lsp-fuzz://b.scala");
        let completion = completion_at("lsp-fuzz://a.scala");

        let mut errors = HashMap::new();
        errors.insert(&hover_a, err(-32603, "boom at line 12"));
        errors.insert(&hover_b, err(-32603, "boom at line 88"));
        errors.insert(&completion, err(-32602, "invalid params"));

        let matching = RequestResponseMatching {
            responses: HashMap::new(),
            errors,
            notifications: Vec::new(),
            requests_from_server: Vec::new(),
        };

        let info = collect_response_info(matching);
        assert_eq!(info.findings.len(), 2);
        assert!(
            info.findings
                .iter()
                .all(|f| f.class == OutcomeClass::JsonRpcError)
        );
    }

    #[test]
    fn a_normal_response_is_not_a_finding() {
        let matching = RequestResponseMatching {
            responses: HashMap::new(),
            errors: HashMap::new(),
            notifications: Vec::new(),
            requests_from_server: Vec::new(),
        };
        let info = collect_response_info(matching);
        assert!(info.findings.is_empty());
    }
}
