use std::{option::Option, vec::Vec};

use libafl::{HasMetadata, state::HasRand};
use libafl_bolts::rands::Rand;

use super::NodeGenerator;
use crate::text_document::generation::{
    GrammarContext, NamedNodeGenerator, RandomRuleSelectionStrategy,
};

#[derive(Debug, Clone, Copy)]
pub struct EmptyNode;

impl<State> NodeGenerator<State> for EmptyNode {
    const NAME: &'static str = "AnEmptyNode";
    fn generate_node(
        &self,
        _node: tree_sitter::Node<'_>,
        _grammar_context: &GrammarContext,
        _state: &mut State,
    ) -> Option<Vec<u8>> {
        Some(Vec::new())
    }
}

#[derive(Debug)]
pub struct ChooseFromDerivations;

impl<State> NodeGenerator<State> for ChooseFromDerivations
where
    State: HasRand,
{
    const NAME: &'static str = "RandomDerivation";
    fn generate_node(
        &self,
        node: tree_sitter::Node<'_>,
        grammar_context: &GrammarContext,
        state: &mut State,
    ) -> Option<Vec<u8>> {
        let fragments = grammar_context.node_fragments(node.kind());
        state.rand_mut().choose(fragments).map(<[u8]>::to_vec)
    }
}

#[derive(Debug)]
pub struct ExpandGrammar;

impl<State> NodeGenerator<State> for ExpandGrammar
where
    State: HasRand + HasMetadata,
{
    const NAME: &'static str = "RandomGeneration";
    fn generate_node(
        &self,
        node: tree_sitter::Node<'_>,
        grammar_context: &GrammarContext,
        state: &mut State,
    ) -> Option<Vec<u8>> {
        let selection_strategy = RandomRuleSelectionStrategy;
        let generator = NamedNodeGenerator::new(grammar_context, selection_strategy);
        let fragment = generator.generate(node.kind(), state).ok()?;
        Some(fragment)
    }
}

#[derive(Debug)]
pub struct MismatchedNode;

impl<State> NodeGenerator<State> for MismatchedNode
where
    State: HasRand + HasMetadata,
{
    const NAME: &'static str = "MismatchedNode";

    fn generate_node(
        &self,
        node: tree_sitter::Node<'_>,
        grammar_context: &GrammarContext,
        state: &mut State,
    ) -> Option<Vec<u8>> {
        let mismatched_rules = grammar_context
            .grammar
            .derivation_rules()
            .keys()
            .filter(|&it| it != node.kind());
        let node_kind = state.rand_mut().choose(mismatched_rules)?;
        let selection_strategy = RandomRuleSelectionStrategy;
        let generator = NamedNodeGenerator::new(grammar_context, selection_strategy);
        let fragment = generator.generate(node_kind, state).ok()?;
        Some(fragment)
    }
}

#[cfg(test)]
mod tests {
    use libafl::state::HasRand;
    use libafl_bolts::rands::StdRand;
    use lsp_fuzz_grammars::Language;

    use super::{ChooseFromDerivations, GrammarContext, NodeGenerator};
    use crate::text_document::{
        generation::{DerivationFragments, GrammarContextLookup},
        grammar::{Grammar, fragment_extraction::extract_derivation_fragments},
    };

    /// Minimal `HasRand` state so a node generator can be exercised in a unit test.
    struct RandState(StdRand);
    impl HasRand for RandState {
        type Rand = StdRand;
        fn rand(&self) -> &StdRand {
            &self.0
        }
        fn rand_mut(&mut self) -> &mut StdRand {
            &mut self.0
        }
    }

    fn find_node_with_fragments<'t>(
        node: tree_sitter::Node<'t>,
        ctx: &GrammarContext,
    ) -> Option<tree_sitter::Node<'t>> {
        if ctx.node_fragments(node.kind()).len() > 0 {
            return Some(node);
        }
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .find_map(|child| find_node_with_fragments(child, ctx))
    }

    /// A Scala fragment corpus, loaded into a `GrammarContextLookup`, must feed
    /// `ChooseFromDerivations` so a Scala node mutation selects a fragment from that corpus.
    #[test]
    fn choose_from_scala_corpus() {
        const SCALA_SRC: &[u8] =
            b"object Demo:\n  def add(a: Int, b: Int): Int = a + b\n  val xs: List[Int] = List(1, 2, 3)\n";

        let mut parser = Language::Scala.tree_sitter_parser();
        let fragments =
            extract_derivation_fragments(SCALA_SRC, &mut parser).expect("extract fragments");
        assert!(!fragments.is_empty(), "Scala source should yield fragments");

        let grammar =
            Grammar::from_tree_sitter_grammar_json(Language::Scala, Language::Scala.grammar_json())
                .expect("build Scala grammar");
        let ctx = GrammarContext::new(
            grammar,
            DerivationFragments::new(SCALA_SRC.to_vec(), fragments),
        );
        let lookup = GrammarContextLookup::from_iter([ctx]);

        let ctx = lookup
            .get(Language::Scala)
            .expect("lookup must contain the Scala grammar context");

        let tree = ctx.parse_source_code(SCALA_SRC).expect("parse Scala");
        let node = find_node_with_fragments(tree.root_node(), ctx)
            .expect("some node kind should have corpus fragments");
        let kind = node.kind();

        let mut state = RandState(StdRand::with_seed(0));
        let chosen = ChooseFromDerivations
            .generate_node(node, ctx, &mut state)
            .expect("a fragment should be chosen for a node kind with fragments");

        let corpus: Vec<Vec<u8>> = ctx.node_fragments(kind).map(<[u8]>::to_vec).collect();
        assert!(
            corpus.contains(&chosen),
            "chosen fragment must come from the loaded Scala corpus"
        );
    }
}
