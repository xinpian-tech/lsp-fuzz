# Plan: Scala LSP Support for LSPFuzz

Status: proposal / not yet implemented.

## 1. Goal & fixed decisions

Add Scala support to LSPFuzz so it can fuzz a real Scala language server with
grey-box coverage feedback. Three decisions are locked in:

| Dimension | Decision |
|---|---|
| **Target LSP** | [`xinpian-tech/scala3-bsp-smantic-ls`](https://github.com/xinpian-tech/scala3-bsp-smantic-ls) (note: repo name is really misspelled "smantic"). Entry point `ls.core.Main` — a JVM stdio server (Java 25 + Scala 3.8.4, Mill 1.1.2) using lsp4j `LSPLauncher`, reading `System.in` / writing stdout. |
| **Coverage instrumentation** | JVM **bytecode** instrumentation (class-load agent, Jazzer/Kelinci-style) writing an AFL-compatible counter map into `__AFL_SHM_ID`. A Scala compiler plugin is **not** the mechanism (see §3); it is only an optional later supplement. |
| **Corpus / workspace** | [`xinpian-tech/zaozi`](https://github.com/xinpian-tech/zaozi) — a Chisel-in-Scala3 eDSL over MLIR/CIRCT. Same toolchain family (Scala 3.7.4, JDK 25, Mill 1.1.2), ~261 `.scala` / ~35k LOC. Used as the fragment-mining source and as a pre-built on-disk workspace the LS indexes. |

## 2. Why this is not "just add a grammar"

LSPFuzz's existing 12 languages all target **native, AFL-compile-time-instrumented**
binaries (rust-analyzer, clangd, texlab, …). The executor (`crates/lsp-fuzz/src/execution/`)
speaks the standard AFL++ fork-server protocol: control/status on fds 198/199,
coverage map via `__AFL_SHM_ID`, shmem input via `__AFL_SHM_FUZZ_ID`, plus
persistent/defer flags. The contract is **protocol-level, not language-level** — any
process implementing it works.

The Scala target is a **JVM** program and relies on JVM-only Java 25 features (FFM
SQLite, `MemorySegment` mmap, AOT cache, compact object headers), so there is **no
GraalVM native-image path** and no AFL native instrumentation. Coverage must therefore
come from a JVM-side mechanism that populates the AFL shared-memory map. This is the
core of the work (route "A", chosen by the user).

## 3. Instrumentation: bytecode agent, not a Scala compiler plugin

The crash-rich surface of this LS is mostly **not** in its own `ls-*` Scala modules:

- `scala3-presentation-compiler_3` — completion/hover/definition; notoriously crashy
  on malformed input.
- `scalameta` SemanticDB parsing, `bsp4j`.
- `lsp4j` / `lsp4j.jsonrpc` — **written in Java**.

A Scala compiler plugin (scoverage-style) only instruments code you recompile with it
(the `ls-*` modules) and cannot touch the published third-party deps or the Java parts.
A **class-load bytecode agent** instruments everything loaded into the JVM without
rebuilding any dependency, and produces exactly the AFL-shaped counter map we need.

Because this project (unlike Metals) is **built from source with Mill**, a scalac
plugin / `scalacOptions` addition becomes a cheap *supplement* for finer, source-aligned
signal on the `ls-*` logic specifically (`LsModule.scalacOptions` in `build.mill`). It
is a supplement, never the backbone.

## 4. End-to-end pipeline

```
                     [ build-time, once ]
zaozi ──Mill + SemanticDB compile──▶ on-disk backdrop (sources + .semanticdb + BSP/Bloop config)
zaozi ──mine-code-fragments────────▶ scala.frag (ChooseFromDerivations corpus)

                     [ fuzzing loop, per input ]
LspInput = { dirty-buffer source file(s) (small, mutable) + LSP message sequence }
   │  grammar-guided mutation (tree-sitter-scala) + message generation
   ▼
serialize init … didOpen … msgs … shutdown  (framed JSON-RPC bytes)
   │  __AFL_SHM_FUZZ_ID (shmem input)
   ▼
LspExecutor / NeoForkServer ◀─ fd198/199 status, __AFL_SHM_ID coverage ─┐
   │                                                                    │
   ▼                                                                    │
persistent JVM (JDK 25, --in-process-pc)                                │
  bytecode agent instruments the whole stack (ls-* + presentation       │
  compiler + scalameta + lsp4j) → edge counters into the AFL map ───────┘
  uses the zaozi backdrop as workspace root; serves dirty-buffer requests
  uncaught exception / Error / hang → process-level crash signal
```

## 5. Two fuzzing régimes (determines bring-up order)

- **Régime 1 — PC paths (first; no BSP needed).** Open a mutated Scala file as a dirty
  buffer, fuzz `completion / hover / signatureHelp / definition / didChange`. Exercises
  scala3-presentation-compiler with no SemanticDB/BSP dependency. Fastest to stand up and
  already a rich crash surface.
- **Régime 2 — index paths (later; needs the zaozi backdrop).** With zaozi pre-compiled
  to SemanticDB and a BSP connection, fuzz the LS's three headline features:
  `workspace/symbol`, whole-repo `textDocument/references`, cross-file `textDocument/rename`.

## 6. Milestones

### M0 — Feasibility smoke (gates everything)
- Pick the bytecode agent (Jazzer preferred; Kelinci/JaCoCo fallback) and prove it emits
  a **non-empty** AFL coverage map for this LS under **JDK 25 + AOT cache + compact object
  headers**. This is risk #1 — do it first.
- Confirm the agent implements/bridges the fork-server contract: fd 198/199 handshake,
  `__AFL_SHM_ID`, `__AFL_SHM_FUZZ_ID`, persistent mode, response to `AFL_DUMP_MAP_SIZE=1`.

### M1 — Grammar-layer integration (pure Rust, independent, do in parallel)
- `crates/lsp-fuzz-grammars/Cargo.toml`: add `tree-sitter-scala`.
- `.../src/lib.rs`: append `Scala` to the `Language` enum (append at end — `#[repr(u8)]`
  order maps to the QUERIES index).
- `.../src/language_data.rs`: add `SCALA` `LanguageInfo` (`extensions ["scala","sc"]`,
  `lsp_language_id "scala"`, grammar_json, highlight query, ts_language_fn).
- `.../src/language.rs`: add the `info()` match arm; bump hardcoded `VARIANT_COUNT` 12→13.
- `.../res/grammar/scala.json`: generate the tree-sitter grammar JSON. Scala has an
  external scanner — verify the self-written generator in `crates/lsp-fuzz/src/stolen/`
  accepts it, else trim.
- Optional `.../res/highlights/scala.scm` if the crate exports no `HIGHLIGHTS_QUERY`.
- Add `Language::Scala` to `load_all_derivation_grammars` in
  `crates/lsp-fuzz/src/text_document/grammar/mod.rs`; run `Grammar::validate()`; add a
  Scala parse smoke test.

### M2 — zaozi corpus & backdrop
- `mine-code-fragments --language Scala --search-directory <zaozi>` → `scala.frag`.
- Build the zaozi backdrop once: Mill compile with SemanticDB (`-Xsemanticdb` / mill
  semanticdb) → `.semanticdb` files + BSP/Bloop config, as a fixed on-disk workspace root.

### M3 — Scala workspace scaffolding (`crates/lsp-fuzz/src/lsp_input/session.rs`)
- Add `Language::Scala => scala_workspace(doc)` to `workspace_for_document`.
- Key adaptation: do **not** rematerialize all ~35k lines of zaozi per iteration. Treat
  the backdrop as a fixed on-disk root (static) and let the mutable part of `LspInput` be
  only a small set of dirty-buffer source files overlaying it. This needs a "static
  workspace root + per-input incremental files" notion in the executor (today
  `request_bytes` materializes the whole virtual FS per input, `session.rs:14`). Régime 1
  can bypass this with a light single-file workspace; régime 2 requires it.

### M4 — JVM coverage-bridge harness (route A core)
- Persistent JVM harness: `fuzzerTestOneInput(byte[])` feeds the shmem byte stream as a
  JSON-RPC stream into an in-process `ls.core.Main` / `ScalaLs` (reuse its existing
  System.in/out lsp4j channel), with `--in-process-pc`.
- **State reset (A1 core engineering point):** reset LS session state each iteration (PC,
  BSP connection, dirty-buffer overlay, index caches) so inputs don't cross-contaminate
  and crashes reproduce.
- Crash semantics: map LS uncaught exceptions / `Error` / deadlock-timeout to a
  process-level crash so `LspExecutor` sees `ExitKind::Crash`.

### M5 — CLI / executor wiring
- Point `fuzz` at the JVM target. `check_binary` detects persistent/defer by scanning the
  ELF for `##SIG_AFL_PERSISTENT##` etc., which a JVM launcher lacks — add
  `--persistent/--defer/--map-size` override flags (`FuzzTargetInfo` already has the
  fields; `fuzz_target.rs:34` only produces defaults), or use a native launcher carrying
  the signatures.
- Wire `--language-fragments Scala=scala.frag` (works via `Language`'s derived `FromStr`).

### M6 — End-to-end validation & wrap-up
- Régime 1 first: generate → execute → observe coverage growth → reproduce a planted crash.
- Then régime 2: zaozi + SemanticDB + BSP; fuzz workspace/symbol, references, rename.
- Optional: add the scalac-plugin / `scalacOptions` supplement for `ls-*` logic.
- `cargo test/clippy/fmt --workspace`, `typos` (add Scala/zaozi/Jazzer/SemanticDB terms to
  `codebook.toml`); update README/AGENTS language table + target-setup docs.

## 7. Risks (priority order)

1. **Bytecode agent on JDK 25** (M0) — if it can't instrument under Java 25 + AOT cache +
   compact object headers, route A needs a different agent or a degraded mode. #1 blocker.
2. **A1 state-reset reproducibility** (M4) — cross-input state pollution in a persistent JVM
   destroys crash reproduction.
3. **Static backdrop + incremental files executor change** (M3) — throughput prerequisite
   for régime 2.
4. **Scala version skew** (zaozi 3.7.4 vs LS 3.8.4) — expected harmless (Scala 3 source
   compatibility, stable SemanticDB format) but must be confirmed by checking the LS indexes
   the backdrop correctly.

## 8. Suggested first steps

M1 is fully independent, pure Rust, and immediately verifiable. M0 (the JDK 25 agent smoke)
gates all of route A and should run in parallel, first. Start with these two.
