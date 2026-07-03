use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::BufWriter,
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::Context;
use itertools::Itertools;
use lsp_fuzz::text_document::{
    generation::DerivationFragments,
    grammar::fragment_extraction::{self, extract_derivation_fragments},
};
use lsp_fuzz_grammars::Language;
use rayon::prelude::*;
use tracing::{info, warn};

use super::GlobalOptions;

/// Extracts derivation fragments from a set of source files
#[derive(Debug, clap::Parser)]
pub(super) struct MineCodeFragments {
    /// The directory to search for source files
    #[clap(long, short)]
    search_directory: PathBuf,

    /// The language to use for parsing the source files
    #[clap(long, short)]
    language: Language,

    /// The output file to write the extracted fragments to
    #[clap(long, short, default_value = "fragments.cbor.zst")]
    output: PathBuf,
}

impl MineCodeFragments {
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn run(self, global_options: GlobalOptions) -> anyhow::Result<()> {
        let MineCodeFragments {
            search_directory,
            language,
            output,
        } = self;
        let zstd_threads = global_options.parallel_workers();
        let source_files = find_source_files(&search_directory, language)?;

        info!("Found {} source files", source_files.len());
        let extracted_fragments: Vec<_> = source_files
            .into_par_iter()
            .inspect(|source_file_path| info!("Parsing: {}", source_file_path.display()))
            .map(|source_file| extract_fragments(&source_file, language))
            .filter_map(Result::transpose)
            .collect::<Result<_, _>>()?;
        let mut code = Vec::new();
        let mut fragments = HashMap::new();

        info!("Merging fragments");
        for (file_content, file_fragments) in extracted_fragments {
            let offset = code.len();
            code.extend(file_content);
            for (node_kind, ranges) in file_fragments {
                let ranges = ranges
                    .into_iter()
                    .map(|range| (range.start + offset)..(range.end + offset));
                fragments
                    .entry(node_kind)
                    .or_insert_with(Vec::new)
                    .extend(ranges);
            }
        }

        info!("Deduplicating fragments");
        fragments.values_mut().par_bridge().for_each(|ranges| {
            ranges.sort_by_key(|it| &code[it.clone()]);
            ranges.dedup_by_key(|it| &code[it.clone()]);
        });

        info!("Serializing fragments");
        let result = DerivationFragments::new(code, fragments);
        write_output(&output, &result, zstd_threads).context("Writing output")?;

        Ok(())
    }
}

fn find_source_files(
    search_directory: &Path,
    language: Language,
) -> Result<Vec<PathBuf>, anyhow::Error> {
    let extensions = language.file_extensions();
    let source_files: Vec<_> = walkdir::WalkDir::new(search_directory)
        .into_iter()
        .filter_ok(|it| {
            it.metadata().is_ok_and(|it| it.is_file())
                && it
                    .path()
                    .extension()
                    .map(|it| it.to_string_lossy())
                    .is_some_and(|ext| extensions.contains(ext.as_ref()))
        })
        .map_ok(walkdir::DirEntry::into_path)
        .try_collect()
        .context("Searching for source file")?;
    Ok(source_files)
}

fn write_output(
    output_path: &Path,
    result: &DerivationFragments,
    zstd_threads: usize,
) -> Result<(), anyhow::Error> {
    let output_file = File::create(output_path).context("Creating output file")?;
    let output_writer = BufWriter::new(output_file);
    let zstd_encoder = {
        let mut enc = zstd::Encoder::new(output_writer, 19).context("Creating zstd encoder")?;
        enc.multithread(u32::try_from(zstd_threads).context("Converting zstd thread count")?)
            .context("Setting zstd encoder threads")?;
        enc.auto_finish()
    };
    ciborium::into_writer(result, zstd_encoder).context("Serializing derivation fragments")?;
    Ok(())
}

type ExtractedFragments<'a> = (Vec<u8>, HashMap<Cow<'a, str>, Vec<Range<usize>>>);

fn extract_fragments<'a>(
    source_file_path: &Path,
    language: Language,
) -> anyhow::Result<Option<ExtractedFragments<'a>>> {
    let file_content = std::fs::read(source_file_path)
        .with_context(|| format!("Reading: {}", source_file_path.display()))?;
    let mut parser = language.tree_sitter_parser();
    match extract_derivation_fragments(&file_content, &mut parser) {
        Ok(fragemnts) => Ok(Some((file_content, fragemnts))),
        Err(fragment_extraction::Error::DotGraphParsing(msg)) => {
            warn!(
                file = % source_file_path.display(),
                "Failed to parse dot graph: {}",
                msg,
            );
            Ok(None)
        }
        Err(e) => Err(e).with_context(|| {
            format!(
                "Extracting derivation fragments from {}",
                source_file_path.display()
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end round trip for Scala: discover a `.scala` file, extract
    /// derivation fragments, serialize them to disk in the on-disk format, and
    /// load them back through the fuzzer's grammar-context loader.
    #[test]
    fn mine_and_load_scala_fragments_round_trip() {
        const SCALA_SRC: &str = r"
object Demo:
  def add(a: Int, b: Int): Int = a + b
  val xs: List[Int] = List(1, 2, 3)
";
        let dir =
            std::env::temp_dir().join(format!("lspfuzz_scala_frag_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let src_path = dir.join("Demo.scala");
        std::fs::write(&src_path, SCALA_SRC).expect("write scala source");

        let files = find_source_files(&dir, Language::Scala).expect("find source files");
        assert_eq!(files.len(), 1, "the .scala file should be discovered");

        let (content, file_fragments) = extract_fragments(&src_path, Language::Scala)
            .expect("extract fragments")
            .expect("Scala source yields fragments");
        assert!(
            !file_fragments.is_empty(),
            "Scala source should produce derivation fragments"
        );

        let mut code = Vec::new();
        let mut fragments = HashMap::new();
        code.extend(content);
        for (node_kind, ranges) in file_fragments {
            fragments
                .entry(node_kind)
                .or_insert_with(Vec::new)
                .extend(ranges);
        }
        let frags = DerivationFragments::new(code, fragments);

        let out = dir.join("scala.frag");
        write_output(&out, &frags, 1).expect("serialize fragments");

        // The fuzzer's load path must accept the mined Scala fragments.
        crate::language_fragments::load_grammar_context(Language::Scala, &out)
            .expect("load grammar context for Scala");

        std::fs::remove_dir_all(&dir).ok();
    }
}
