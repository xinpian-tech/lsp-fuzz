//! Findings: deduplicated records of server-side problems observed while fuzzing.
//!
//! A [`Finding`] captures one distinct problem (its [`OutcomeClass`], the method it was seen on, an
//! optional error code, and a normalized message). A [`FindingSet`] holds a set of findings
//! deduplicated by a signature built from `(class, method, error code, normalized message)`, so that
//! the same defect reproduced many times — across inputs whose only difference is a line number, an
//! offset, or a temp path — collapses to a single finding.

use serde::{Deserialize, Serialize};

use crate::execution::outcome::OutcomeClass;
use crate::lsp::json_rpc::ResponseError;

/// One deduplicated server-side problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// What kind of problem this is.
    pub class: OutcomeClass,
    /// The LSP method the problem was observed on, when known.
    pub method: Option<String>,
    /// The JSON-RPC error code, for [`OutcomeClass::JsonRpcError`] findings.
    pub error_code: Option<i32>,
    /// The volatile-stripped message used for triage and dedup.
    pub normalized_message: String,
}

impl Finding {
    /// Build a finding from a JSON-RPC error response observed on `method`.
    #[must_use]
    pub fn from_json_rpc_error(method: impl Into<String>, error: &ResponseError) -> Self {
        Self {
            class: OutcomeClass::JsonRpcError,
            method: Some(method.into()),
            error_code: Some(error.code),
            normalized_message: normalize_message(&error.message),
        }
    }

    /// The dedup signature: two findings with the same signature are the same finding.
    #[must_use]
    pub fn signature(&self) -> String {
        format!(
            "{:?}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.class,
            self.method.as_deref().unwrap_or(""),
            self.error_code.map_or_else(String::new, |c| c.to_string()),
            self.normalized_message,
        )
    }
}

/// A set of findings, deduplicated by [`Finding::signature`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSet {
    findings: Vec<Finding>,
}

impl FindingSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a finding. Returns `true` if it was new, `false` if an equivalent finding (same
    /// signature) was already present and this one was dropped as a duplicate.
    pub fn record(&mut self, finding: Finding) -> bool {
        let signature = finding.signature();
        if self.findings.iter().any(|f| f.signature() == signature) {
            return false;
        }
        self.findings.push(finding);
        true
    }

    /// The deduplicated findings.
    #[must_use]
    pub fn as_slice(&self) -> &[Finding] {
        &self.findings
    }

    /// The number of distinct findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Iterate over the deduplicated findings.
    pub fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter()
    }
}

/// Build a deduplicated [`FindingSet`] from the JSON-RPC error responses collected during response
/// matching. Each `(method, error)` pair becomes a [`OutcomeClass::JsonRpcError`] finding; identical
/// errors (after message normalization) collapse to one.
#[must_use]
pub fn findings_from_json_rpc_errors<'a, I>(errors: I) -> FindingSet
where
    I: IntoIterator<Item = (&'a str, &'a ResponseError)>,
{
    let mut set = FindingSet::new();
    for (method, error) in errors {
        set.record(Finding::from_json_rpc_error(method, error));
    }
    set
}

/// Strip the volatile parts of a message so that the same defect with different concrete details
/// (line/column numbers, byte offsets, hex addresses, temp paths) dedups to one signature.
///
/// The normalization collapses every run of ASCII digits and every `0x`-prefixed hex literal to a
/// single `#`, and collapses runs of whitespace to a single space. It is deliberately conservative:
/// it never reorders or drops words, so distinct error messages stay distinct.
#[must_use]
pub fn normalize_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let bytes = message.as_bytes();
    let mut i = 0;
    let mut pending_space = false;
    let mut wrote_any = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            pending_space = wrote_any;
            i += 1;
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        // Collapse a `0x`-prefixed hex literal.
        if b == b'0'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
            && i + 2 < bytes.len()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('#');
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            wrote_any = true;
            continue;
        }
        // Collapse a run of decimal digits.
        if b.is_ascii_digit() {
            out.push('#');
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            wrote_any = true;
            continue;
        }
        // Copy one UTF-8 char intact.
        let ch_len = utf8_char_len(b);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(&message[i..end]);
        i = end;
        wrote_any = true;
    }
    out
}

const fn utf8_char_len(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32, message: &str) -> ResponseError {
        ResponseError {
            code,
            message: message.to_string(),
            data: None,
        }
    }

    #[test]
    fn a_json_rpc_error_becomes_one_finding() {
        let mut set = FindingSet::new();
        assert!(set.record(Finding::from_json_rpc_error(
            "textDocument/hover",
            &err(-32603, "internal error")
        )));
        assert_eq!(set.len(), 1);
        let finding = &set.as_slice()[0];
        assert_eq!(finding.class, OutcomeClass::JsonRpcError);
        assert_eq!(finding.method.as_deref(), Some("textDocument/hover"));
        assert_eq!(finding.error_code, Some(-32603));
    }

    #[test]
    fn identical_errors_dedup_to_one() {
        // Same method, same code, messages that differ only in numbers → one finding.
        let errors = [
            (
                "textDocument/hover",
                err(-32603, "boom at line 12 offset 480"),
            ),
            (
                "textDocument/hover",
                err(-32603, "boom at line 77 offset 9001"),
            ),
            (
                "textDocument/hover",
                err(-32603, "boom at line 3 offset 0xDEADBEEF"),
            ),
        ];
        let set = findings_from_json_rpc_errors(errors.iter().map(|(m, e)| (*m, e)));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn distinct_errors_stay_distinct() {
        let errors = [
            ("textDocument/hover", err(-32603, "internal error")),
            ("textDocument/hover", err(-32602, "invalid params")),
            ("textDocument/completion", err(-32603, "internal error")),
        ];
        let set = findings_from_json_rpc_errors(errors.iter().map(|(m, e)| (*m, e)));
        // Distinct by code (first two) and distinct by method (first and third).
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn no_errors_yields_no_findings() {
        let set = findings_from_json_rpc_errors(std::iter::empty());
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn normalize_collapses_volatile_bits() {
        assert_eq!(
            normalize_message("boom at line 12 offset 480"),
            "boom at line # offset #"
        );
        assert_eq!(normalize_message("addr 0xDEADBEEF here"), "addr # here");
        assert_eq!(
            normalize_message("  ragged   whitespace\tand\nnewlines "),
            "ragged whitespace and newlines"
        );
        // Non-ASCII text is preserved intact.
        assert_eq!(normalize_message("错误 42"), "错误 #");
    }
}
