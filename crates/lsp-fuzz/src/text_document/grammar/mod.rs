use core::fmt;
use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use anyhow::bail;
use indexmap::{IndexMap, IndexSet};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

pub mod fragment_extraction;
pub mod tree_sitter;

use super::Language;
/// Represents a terminal symbol in a grammar.
///
/// A terminal symbol is a basic building block in a grammar that cannot be broken
/// down further. These represent the actual tokens or literals in the language.
#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize, derive_more::Display)]
pub enum Terminal {
    /// An immediate terminal with literal bytes.
    #[display("\"{}\"", String::from_utf8_lossy(_0).escape_default())]
    Immediate(Vec<u8>),

    /// A named terminal that refers to a specific token type.
    #[display("[{_0}]")]
    Named(String),

    /// An auxiliary terminal used for special cases or helper tokens.
    #[display("({_0})")]
    Auxiliary(String),
}

/// Represents a symbol in a grammar, which can be either a terminal or non-terminal.
///
/// Symbols are the building blocks of production rules in a grammar. They can be
/// either terminals (which represent actual tokens) or non-terminals (which represent
/// abstractions that can be expanded using production rules).
#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize, derive_more::Display)]
pub enum Symbol {
    /// A terminal symbol that cannot be expanded further
    Terminal(Terminal),

    /// A non-terminal symbol with a name, which can be expanded using production rules
    #[display("<{_0}>")]
    NonTerminal(String),

    /// The end of file symbol, marking the end of input
    #[display("<EOF>")]
    Eof,
}

/// Represents a sequence of symbols in a derivation rule.
///
/// A derivation sequence is the right-hand side of a production rule in a grammar.
/// It consists of a sequence of symbols (terminals and non-terminals) that a
/// non-terminal on the left-hand side can be expanded into.
#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize, derive_more::IntoIterator)]
pub struct DerivationSequence {
    /// The sequence of symbols that make up this derivation
    #[serde(flatten)]
    #[into_iterator(owned, ref, ref_mut)]
    symbols: Vec<Symbol>,
}

impl Display for DerivationSequence {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.symbols.is_empty() {
            write!(f, "ε")
        } else {
            write!(f, "{}", self.symbols.iter().format(" "))
        }
    }
}

impl DerivationSequence {
    #[must_use]
    pub fn new(symbols: Vec<Symbol>) -> Self {
        Self { symbols }
    }

    #[must_use]
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }
}

/// Represents a formal grammar for a programming language.
///
/// A grammar consists of a language identifier, a start symbol, and a collection of
/// derivation rules that define how to generate valid programs in the language.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, derive_more::Constructor)]
pub struct Grammar {
    /// The programming language this grammar represents
    language: Language,
    /// The name of the starting non-terminal symbol for the grammar
    start_symbol: String,
    /// The production rules of the grammar, mapping non-terminal names to their possible derivation sequences
    derivation_rules: IndexMap<String, IndexSet<DerivationSequence>>,
}

impl Display for Grammar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Grammar for {}", self.language)?;
        writeln!(f, "Start symbol: <{}>", self.start_symbol)?;
        writeln!(f, "Production rules:")?;
        for (symbol, derivations) in &self.derivation_rules {
            writeln!(
                f,
                "<{}> ::=\n    {}\n",
                symbol,
                derivations.iter().format("\n  | ")
            )?;
        }
        writeln!(f)?;
        Ok(())
    }
}

impl Grammar {
    #[must_use]
    pub const fn language(&self) -> Language {
        self.language
    }

    #[must_use]
    pub fn start_symbol(&self) -> &str {
        self.start_symbol.as_str()
    }

    #[must_use]
    pub const fn derivation_rules(&self) -> &IndexMap<String, IndexSet<DerivationSequence>> {
        &self.derivation_rules
    }

    /// Validates that every referenced non-terminal has a corresponding production rule.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation references a non-terminal that is not present in
    /// `self.derivation_rules`.
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        for symbol in self.derivation_rules.values().flatten().flatten() {
            match symbol {
                Symbol::NonTerminal(name) if !self.derivation_rules.contains_key(name) => {
                    bail!("Missing rule for non-terminal symbol: {name}");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CreationError {
    #[error("Error occurred in tree-sitter: {0}")]
    TreeSitter(Box<dyn Error + Send + Sync + 'static>),
    #[error("The provided grammar is empty")]
    EmptyGrammar,
    #[error("The grammar is missing a rule")]
    MissingRule,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::text_document::{
        GrammarBasedMutation, TextDocument, grammar::tree_sitter::CapturesIterator,
    };

    #[test]
    fn load_all_derivation_grammars() {
        let languages = [
            Language::C,
            Language::CPlusPlus,
            Language::JavaScript,
            Language::Rust,
            Language::Toml,
            Language::LaTeX,
            Language::BibTeX,
            Language::Solidity,
            Language::Scala,
        ];
        for language in languages {
            let grammar =
                Grammar::from_tree_sitter_grammar_json(language, language.grammar_json()).unwrap();
            eprintln!("{grammar}");
            grammar
                .validate()
                .unwrap_or_else(|_| panic!("Fail to validate grammar for language: {language}"));
        }
    }

    #[test]
    fn capture_rust() {
        const RUST_CODE: &str = r#"
            // Hello
            fn main() {
                println!("Hello, world!");
            }
        "#;
        let doc = TextDocument::new(Language::Rust, RUST_CODE.as_bytes().to_vec());
        let mut capture_iter = CapturesIterator::new(&doc, "comment").unwrap();
        let node = capture_iter.next().expect("There is one comment node");
        let text = &doc.content()[node.byte_range()];
        assert_eq!(text, b"// Hello");
        assert!(dbg!(capture_iter.next()).is_none());

        let mut capture_iter = CapturesIterator::new(&doc, "keyword").unwrap();
        let node = capture_iter.next().expect("There is one keyword node");
        let text = &doc.content()[node.byte_range()];
        assert_eq!(text, b"fn");
        assert!(capture_iter.next().is_none());
    }

    #[test]
    fn capture_scala() {
        const SCALA_CODE: &str = r#"
            // Hello
            object Main:
              def main(args: Array[String]): Unit = println("Hello, world!")
        "#;
        let doc = TextDocument::new(Language::Scala, SCALA_CODE.as_bytes().to_vec());
        let mut capture_iter = CapturesIterator::new(&doc, "comment").unwrap();
        let node = capture_iter.next().expect("There is one comment node");
        let text = &doc.content()[node.byte_range()];
        assert_eq!(text, b"// Hello");
        assert!(capture_iter.next().is_none());

        // `object` is captured as a plain `keyword` by the Scala highlight query.
        let keywords: Vec<&[u8]> = CapturesIterator::new(&doc, "keyword")
            .unwrap()
            .map(|node| &doc.content()[node.byte_range()])
            .collect();
        assert!(
            keywords.contains(&b"object".as_slice()),
            "expected an `object` keyword capture, got {keywords:?}"
        );
    }

    #[test]
    fn scala_language_metadata() {
        assert_eq!(Language::Scala.lsp_language_id(), "scala");
        let exts = Language::Scala.file_extensions();
        assert!(exts.contains(&"scala"));
        assert!(exts.contains(&"sc"));
    }

    /// Scala's highlight query must compile against the Scala grammar, and
    /// `ts_highlight_query()` for Scala must not index out of bounds. Scala is
    /// the last enum variant, so its `QUERIES` index equals `VARIANT_COUNT - 1`;
    /// a stale `VARIANT_COUNT` (still 12) would panic on this call.
    #[test]
    fn scala_highlight_query_compiles() {
        let query = Language::Scala.ts_highlight_query();
        assert!(
            !query.capture_names().is_empty(),
            "Scala highlight query should expose captures"
        );
    }

    /// `ts_highlight_query()` must return for every `Language` variant without panicking or
    /// indexing out of bounds. This walks the full `QUERIES` array (so a stale `VARIANT_COUNT`
    /// smaller than the enum would panic), and covers variants whose bundled query is invalid: a
    /// malformed query degrades to an empty query rather than crashing the fuzzer.
    #[test]
    fn highlight_query_returns_for_every_variant() {
        for language in Language::ALL {
            let query = language.ts_highlight_query();
            let _ = query.pattern_count();
        }
        assert_eq!(
            Language::ALL.len(),
            13,
            "Language::ALL must list every variant"
        );
        for (index, language) in Language::ALL.into_iter().enumerate() {
            assert_eq!(
                language as usize, index,
                "Language::ALL is out of repr order"
            );
        }
    }

    /// Scala source parsed with the wrong grammar must not silently look like
    /// valid Scala: the parse trees differ and the mismatched parse errors.
    #[test]
    fn scala_wrong_grammar_distinct_parse() {
        const SCALA_CODE: &str = "object Main:\n  val x: Int = 1\n";
        let scala = TextDocument::new(Language::Scala, SCALA_CODE.as_bytes().to_vec());
        let as_rust = TextDocument::new(Language::Rust, SCALA_CODE.as_bytes().to_vec());

        let scala_sexp = scala.parse_tree().root_node().to_sexp();
        let rust_sexp = as_rust.parse_tree().root_node().to_sexp();
        assert_ne!(
            scala_sexp, rust_sexp,
            "different grammars must parse differently"
        );
        assert!(
            !scala.parse_tree().root_node().has_error(),
            "valid Scala should parse cleanly with the Scala grammar"
        );
        assert!(
            as_rust.parse_tree().root_node().has_error(),
            "Scala source parsed as Rust should contain error nodes"
        );
    }

    #[test]
    fn malformed_scala_grammar_rejected() {
        // Malformed grammar JSON must be rejected with an error, not accepted.
        assert!(Grammar::from_tree_sitter_grammar_json(Language::Scala, "{ not json").is_err());
        // A well-formed but empty grammar (no rules) must also be rejected with a
        // clean error rather than panicking during preparation.
        assert!(matches!(
            Grammar::from_tree_sitter_grammar_json(
                Language::Scala,
                r#"{"name":"scala","rules":{}}"#
            ),
            Err(CreationError::EmptyGrammar)
        ));
    }
}
