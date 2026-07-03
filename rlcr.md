# Plan: Scala LSP Support for LSPFuzz (target `scala3-bsp-smantic-ls`, JVM coverage bridge)

## Goal Description

Add Scala as a supported language to LSPFuzz and make it able to fuzz the JVM language
server `github.com/xinpian-tech/scala3-bsp-smantic-ls` (entry `ls.core.Main`; Java 25 +
Scala 3.8.4; lsp4j stdio) with grey-box coverage feedback. Because the target is a JVM
program with no native-image path, AFL compile-time instrumentation is impossible;
coverage instead comes from a JVM **bytecode** instrumentation agent whose counter map is
surfaced to LSPFuzz through a **new JVM-specific LibAFL executor** (user decision DEC-1 =
Option B). The Scala corpus and index backdrop come from `github.com/xinpian-tech/zaozi`.

The work is delivered across two fuzzing régimes:
- **Régime 1 — presentation-compiler paths** (no BSP): dirty-buffer `completion`, `hover`,
  `signatureHelp`, `definition`, `didChange`.
- **Régime 2 — index paths** (frozen pre-indexed zaozi backdrop, BSP disabled after init):
  `workspace/symbol`, whole-repo `textDocument/references`, cross-file `textDocument/rename`.

## Acceptance Criteria

- AC-1: Scala is a first-class `Language` in `lsp-fuzz-grammars` and parses/mutates via tree-sitter.
  - Positive Tests (expected to PASS):
    - `Grammar::from_tree_sitter_grammar_json(Language::Scala, ...)` succeeds and `validate()` passes in `load_all_derivation_grammars`.
    - A `TextDocument::new(Language::Scala, <valid Scala source>)` parses and a capture smoke test (e.g. `keyword`, `comment`) returns expected nodes.
    - `Language::Scala.file_extensions()` yields `{scala, sc}` and `lsp_language_id()` yields `scala`.
  - Negative Tests (expected to FAIL / be rejected):
    - Building a `TextDocument` with the wrong grammar for Scala source produces a different/empty parse (not silently treated as valid Scala).
    - An empty or malformed `scala.json` grammar is rejected by `validate()` rather than accepted.
  - AC-1.1: `VARIANT_COUNT` in `language.rs` matches the enum cardinality after adding Scala.
    - Positive: `ts_highlight_query()` for every variant (including Scala) returns without panic/index-out-of-bounds.
    - Negative: leaving `VARIANT_COUNT` at 12 causes a test/asserted failure (proves the bump is verified, not incidental).

- AC-2: The bytecode agent produces stable, non-empty AFL-shaped coverage for the real LS under JDK 25.
  - Positive Tests:
    - Running the agent against `scala3-bsp-smantic-ls` for an `initialize`→`didOpen`→one semantic request→`shutdown` cycle yields a non-empty counter map that includes edges in presentation-compiler / scalameta packages (not only jsonrpc transport).
    - 1000 identical inputs in one worker epoch yield stable coverage (bounded variance), bounded heap / thread / file-descriptor counts, and no response desynchronization.
  - Negative Tests:
    - A run that instruments nothing (agent disabled) yields an all-zero map and is detected as a misconfiguration, not accepted as "0 new coverage".
    - Coverage that keeps growing across identical inputs (instability from un-quiesced background threads) is flagged as an instability signal, not counted as real coverage.
  - AC-2.1: Determinism knobs (DEC-3) — AOT cache and compact object headers can be disabled for the fuzzing configuration.
    - Positive: with AOT cache + compact headers disabled, the 1000-identical-input stability test passes.
    - Negative: if a knob materially destabilizes coverage, the harness surfaces it rather than silently degrading.

- AC-3: A JVM-specific LibAFL executor (Option B) drives a persistent JVM worker with epoch restart and coverage copy-out.
  - Positive Tests:
    - The executor sends a serialized `LspInput`, the worker resets state, runs, and the executor reads back the coverage map + an outcome status; a custom Observer/Feedback consumes that map for coverage-guided scheduling.
    - After a timeout/OOM/instability signal, the executor kills and restarts the worker epoch and continues fuzzing without deadlocking the fuzzer loop.
  - Negative Tests:
    - A worker that hangs on one input does not permanently stall the campaign (the epoch is killed + restarted within the timeout budget).
    - The executor does NOT depend on ELF AFL signatures or `AFL_DUMP_MAP_SIZE` (those are Option-A-only); Option B bypasses `check_binary`.
  - AC-3.1: Per-iteration coverage lifecycle is specified and enforced: reset map → run → quiesce (await outstanding lsp4j futures + background threads to a deadline) → copy map → detect late coverage.
    - Positive: on a planted background-thread task, quiescence waits or the epoch is restarted; coverage attributed to an iteration excludes post-iteration late writes.
    - Negative: late coverage written after the logical iteration is NOT silently merged into the next input's map.

- AC-4: An outcome-classification oracle distinguishes all outcome classes, and findings include LSP JSON-RPC error responses (DEC-2).
  - Positive Tests:
    - Planted cases for each class are classified correctly: normal success, JSON-RPC error response, expected cancellation, uncaught foreground exception, uncaught background exception, logged fatal, JVM fatal (e.g. SIGSEGV), OOM/StackOverflow, timeout/deadlock, protocol desync.
    - JSON-RPC error responses ARE recorded as findings (per DEC-2), with triage/dedup so error-response noise is grouped rather than flooding the corpus.
  - Negative Tests:
    - A normal successful response is NOT recorded as a finding.
    - A single crash reproduced N times does not create N distinct findings (dedup works).

- AC-5: Every finding is cold-replayable and fully provenanced.
  - Positive Tests:
    - A finding replays from a cold JVM through the shipped `ls.core.Main` stdio entrypoint (DEC-5) and reproduces the same outcome class.
    - Finding metadata includes: serialized input, zaozi backdrop commit/hash, SemanticDB/BSP artifact hash, LS commit, JDK flags, agent config/version, classpath hash, native SQLite/FFM artifact hash, and timeout budget — enough for a one-command cold replay.
  - Negative Tests:
    - A finding that cannot be replayed through the shipped entrypoint is explicitly labelled "in-process-harness-only" rather than presented as a confirmed server crash.
    - A finding missing provenance fields is rejected by the finding-export path.

- AC-6: The generic virtual-workspace model stays intact; Scala backdrop/overlay behavior is isolated behind a materializer / execution profile.
  - Positive Tests:
    - Existing (non-Scala) languages still generate/execute unchanged (existing tests pass).
    - Régime 2 uses an immutable pre-indexed backdrop root + per-input dirty-buffer overlay + URI localization, selected via an execution profile, without baking Scala-specific filesystem behavior into `LspInput`.
  - Negative Tests:
    - The whole ~35k-line zaozi backdrop is NOT re-materialized per input (per-input cost is bounded to the overlay files).
    - Removing the Scala execution profile does not break the generic virtual-FS path.

- AC-7: Coverage actually reaches semantic paths in each régime (guards against "transport-only" fuzzing).
  - Positive Tests:
    - Régime 1 coverage includes presentation-compiler edges after warmup.
    - Régime 2 coverage includes SemanticDB / index / BSP-related edges on the frozen backdrop (validates DEC-6 "frozen + BSP-disabled-after-init" is not shallow).
  - Negative Tests:
    - If Régime 2 coverage stays confined to jsonrpc transport (index paths never reached), the frozen-BSP mode is rejected and the plan falls back to mock/replay or live BSP.

- AC-8: A Scala fragment corpus is mined from zaozi and usable by the fuzzer.
  - Positive Tests:
    - `mine-code-fragments --language Scala --search-directory <zaozi>` produces a non-empty `scala.frag`.
    - `--language-fragments Scala=scala.frag` loads and feeds `ChooseFromDerivations`.
  - Negative Tests:
    - Pointing the miner at a non-Scala directory yields no Scala fragments rather than garbage.

> Note on the throughput bar (DEC-4): the target is **~1 input/sec (loose, directional)** — it is an optimization direction, not a hard gate. A régime is "viable" if it sustains roughly this order of magnitude after warmup; falling short triggers investigation, not automatic failure.

## Path Boundaries

### Upper Bound (Maximum Acceptable Scope)
Both régimes fully working: Scala grammar integrated; a JVM-specific LibAFL executor (Option B)
driving a persistent, epoch-restarting JVM worker with a proven per-iteration state-reset and
coverage-lifecycle; an outcome oracle covering all classes (including JSON-RPC error responses)
with triage/dedup; a materializer/execution-profile abstraction for the frozen zaozi backdrop +
dirty-buffer overlay; cold replay through the shipped `ls.core.Main`; full provenance metadata;
coverage demonstrably reaching presentation-compiler and SemanticDB/index paths; optional scalac
`scalacOptions`/plugin supplement for finer `ls-*` signal; docs and CI updated.

### Lower Bound (Minimum Acceptable Scope)
Régime 1 only, standing on a small fixed synthetic Scala workspace with no BSP: Scala grammar
integrated (AC-1); bytecode agent producing stable non-empty coverage on the real LS (AC-2); the
Option-B executor with epoch restart and the coverage lifecycle (AC-3); the outcome oracle for the
crash/hang/uncaught classes plus JSON-RPC error responses (AC-4); cold replay + provenance (AC-5);
generic model kept intact (AC-6); presentation-compiler coverage reached (AC-7 Régime 1); zaozi
fragment corpus mined (AC-8). Régime 2 (index paths / frozen backdrop) may be deferred but its
design must not be precluded.

### Allowed Choices
- Can use: a JVM bytecode instrumentation agent (Jazzer-derived, Kelinci-style, or a custom agent) as the coverage source; a new LibAFL `Executor` + `Observer`/`Feedback` (Option B) with a bespoke control protocol; an in-process LS harness with controlled per-iteration streams; epoch-based JVM restart; disabling AOT cache / compact object headers for determinism; a scalac `scalacOptions`/plugin supplement for `ls-*` only.
- Cannot use: a Scala **compiler plugin as the coverage backbone** (misses presentation-compiler / scalameta / Java lsp4j — supplement only); GraalVM native-image / AFL native compile-time instrumentation (no native-image path); faking an AFL fork-server child lifecycle by `fork()`-ing a warmed JVM (Option A is only permitted as the explicit native-supervisor alternative if DEC-1 is revisited); baking Scala-specific filesystem behavior into the generic `LspInput`/`request_bytes`.

> Deterministic-design note: DEC-1 fixes the executor architecture to Option B, so the executor path is a narrow constraint (new LibAFL executor, not the AFL forkserver executor). The coverage mechanism is fixed to a bytecode agent. These are not open choices.

## Feasibility Hints and Suggestions

> Reference only — one possible path, not prescriptive.

### Conceptual Approach
```
[ build-time, once ]
zaozi ──Mill + SemanticDB compile (pinned versions)──▶ frozen backdrop (sources + .semanticdb + BSP/Bloop config)
zaozi ──mine-code-fragments────────────────────────▶ scala.frag

[ fuzzing loop, per input, Option B ]
LspInput { dirty-buffer file(s) + LSP message sequence }
   │ grammar-guided mutation (tree-sitter-scala) + message generation (reuse invalid position/range injection)
   ▼
new LibAFL Executor ──control protocol──▶ persistent JVM worker (JDK 25, --in-process-pc, agent-instrumented)
   │  send serialized LspInput → reset state → run → quiesce → read coverage map + outcome
   ▼
custom Observer/Feedback consumes the copied-out map (coverage-guided scheduling)
outcome oracle classifies result; JSON-RPC errors + crashes/hangs/uncaught = findings (deduped)
timeout/OOM/instability → kill + restart worker epoch
finding → provenance bundle → cold replay through shipped ls.core.Main
```

### Relevant References
- `crates/lsp-fuzz-grammars/src/{lib.rs,language.rs,language_data.rs}` — `Language` enum, `info()` match, `VARIANT_COUNT`, `LanguageInfo` consts.
- `crates/lsp-fuzz-grammars/res/grammar/*.json` — tree-sitter grammar JSON format; add `scala.json`.
- `crates/lsp-fuzz/src/stolen/` — self-written tree-sitter grammar generator (must accept Scala's external scanner).
- `crates/lsp-fuzz/src/text_document/grammar/mod.rs` — `load_all_derivation_grammars` test + `Grammar::validate()`.
- `crates/lsp-fuzz/src/lsp_input/session.rs` — `workspace_for_document`, `message_sequence`, `request_bytes` (whole-FS materialization to a temp dir).
- `crates/lsp-fuzz/src/execution/mod.rs` — `LspExecutor` impl of LibAFL `Executor` (sibling extension point for Option B); `FuzzInput`/shmem input.
- `crates/lsp-fuzz/src/execution/fork_server.rs` — AFL forkserver protocol (Option A only).
- `crates/lsp-fuzz/src/fuzz_target.rs` + `crates/lsp-fuzz-cli/src/cli/fuzz.rs` — `check_binary` ELF-signature scan + `AFL_DUMP_MAP_SIZE` (Option B bypasses these).
- `crates/lsp-fuzz-cli/src/cli/mine_code_fragments.rs` — fragment mining.
- Target: `scala3-bsp-smantic-ls` `ls.core.Main` (`--in-process-pc`, `--forked-pc`, graceful degrade without BSP); corpus: `zaozi`.

## Dependencies and Sequence

### Milestones
1. **M0 — Feasibility gate (front-loaded; blocks the route).**
   - Phase A (M0a): trivial instrumented JVM target under JDK 25 → stable non-empty coverage, LSPFuzz-sized inputs, distinct crash reporting, clean restart after timeout, 1000-identical-input stability, bounded resources, cold replay. Spike the Option-B control-protocol shape.
   - Phase B (M0b): the REAL `scala3-bsp-smantic-ls` classpath with the agent — launch, `initialize`, `didOpen` a Scala file, ≥1 real semantic request, `shutdown`, repeat across epochs; must show coverage reaching presentation-compiler/scalameta packages. Produces the discovery outputs: grammar source/version, external-scanner behavior, coverage map size, counter model, thread-safety strategy, and the proven state-reset boundary.
2. **M1 — Grammar-layer integration (pure Rust; parallel with M0).** `Language::Scala`; `SCALA` `LanguageInfo`; `info()` match + `VARIANT_COUNT` 12→13; `res/grammar/scala.json` (external scanner handled); optional `scala.scm`; add to `load_all_derivation_grammars` + `validate`; parse/capture smoke test.
3. **M2 — zaozi corpus + frozen backdrop.** Mine `scala.frag`; build zaozi SemanticDB backdrop once with pinned versions; produce BSP/Bloop config + immutable snapshot; handle Scala 3.7.4↔3.8.4 skew explicitly.
4. **M3 — Workspace materializer / execution profile.** Immutable backdrop root + per-input dirty-buffer overlay + URI localization behind an execution profile; generic virtual-FS path unchanged. Régime 1 may use a light single-file workspace before the full abstraction lands.
5. **M4 — JVM coverage-bridge harness (Option B core).** In-process LS with controlled streams; per-iteration state reset; coverage lifecycle + quiescence; epoch restart; outcome oracle (incl. JSON-RPC error findings + dedup); timeout kill+restart; coverage copy-out to Observer.
6. **M5 — CLI/executor wiring (Option B).** New LibAFL executor + Observer/Feedback; execution-profile selection; `--language-fragments Scala=`; bypass `check_binary`. (Option-A forkserver override flags are NOT part of Option B.)
7. **M6 — End-to-end validation.** Régime 1 first (coverage growth + planted-crash cold replay via shipped entrypoint), then Régime 2 (frozen backdrop; verify AC-7 semantic coverage reach). Optional scalac supplement; docs/CI/`codebook.toml` updates.

Dependencies (relative, not temporal): M0 gates M4/M5. M1 is independent. M2 feeds M3 and M6-Régime2. M3 underpins Régime 2. M4 depends on M0 (architecture + reset boundary) and M1 (inputs). M5 depends on M4. M6 depends on all.

## Task Breakdown

| Task ID | Description | Target AC | Tag | Depends On |
|---------|-------------|-----------|-----|------------|
| task1 | Research/pin tree-sitter-scala source + version; confirm the `stolen/` generator accepts Scala's external scanner (or define trim) | AC-1 | analyze | - |
| task2 | Add `Scala` to `Language` enum, `SCALA` `LanguageInfo`, `info()` match, bump `VARIANT_COUNT`; add `res/grammar/scala.json` (+ optional `scala.scm`) | AC-1, AC-1.1 | coding | task1 |
| task3 | Add Scala to `load_all_derivation_grammars`; add parse/capture smoke tests | AC-1 | coding | task2 |
| task4 | Evaluate JVM bytecode agents (Jazzer-derived / Kelinci-style / custom) for JDK 25 + AOT cache + compact object headers compatibility; decide agent + instrumentation include/exclude scoping | AC-2, AC-2.1 | analyze | - |
| task5 | M0a spike: trivial instrumented JVM target — non-empty stable map, LSPFuzz-sized inputs, crash/timeout/restart, 1000-identical-input stability; prototype Option-B control protocol | AC-2, AC-3 | coding | task4 |
| task6 | M0b gate: instrument real `scala3-bsp-smantic-ls`; init→didOpen→semantic request→shutdown across epochs; measure coverage reaches PC/scalameta; document state-reset boundary, map size, counter model, thread-safety | AC-2, AC-3.1, AC-7 | coding | task5 |
| task7 | Design per-iteration coverage lifecycle + quiescence + late-coverage detection spec | AC-3.1 | analyze | task6 |
| task8 | Implement new JVM-specific LibAFL `Executor` + `Observer`/`Feedback` (Option B), control protocol, epoch restart, timeout kill+restart, coverage copy-out; bypass `check_binary` | AC-3, AC-3.1 | coding | task6, task7 |
| task9 | Implement in-process LS harness with controlled per-iteration streams; per-iteration state reset | AC-3.1, AC-5 | coding | task6 |
| task10 | Implement outcome-classification oracle (all classes; JSON-RPC error responses as findings) + triage/dedup | AC-4 | coding | task9 |
| task11 | Implement finding provenance bundle + cold replay through shipped `ls.core.Main` + in-process/shipped equivalence check | AC-5 | coding | task9, task10 |
| task12 | Define + implement the Scala execution profile (initialize params, client capabilities, language id, extensions, per-régime LSP method allowlist, intentional invalid-message generation) | AC-4, AC-6 | coding | task2 |
| task13 | Implement workspace materializer / execution-profile abstraction (immutable backdrop root + per-input overlay + URI localization) keeping generic model intact | AC-6 | coding | task12 |
| task14 | Build the frozen zaozi backdrop once (pinned Scala/SemanticDB/Mill/Bloop versions, snapshot, BSP config); handle 3.7.4↔3.8.4 skew | AC-5, AC-7 | coding | - |
| task15 | Mine Scala fragment corpus from zaozi; wire `--language-fragments Scala=` | AC-8 | coding | task2, task14 |
| task16 | Validate DEC-6: measure Régime 2 coverage reaches SemanticDB/index/BSP paths on the frozen backdrop; fall back to mock/replay or live BSP if it does not | AC-7 | analyze | task13, task14 |
| task17 | End-to-end validation: Régime 1 (coverage growth + planted-crash cold replay), then Régime 2; planted failures per outcome class | AC-4, AC-5, AC-7 | coding | task8, task11, task13, task15 |
| task18 | Update README/AGENTS language table + target-setup docs; add Scala/zaozi/agent/SemanticDB terms to `codebook.toml`; run `cargo test/clippy/fmt --workspace` + `typos` | AC-1..AC-8 | coding | task17 |
| task19 | (Optional) scalac `scalacOptions`/plugin supplement for finer `ls-*` signal + map-collision report | AC-7 | coding | task16 |

## Claude-Codex Deliberation

### Agreements
- Coverage must come from a JVM bytecode agent, not a Scala compiler plugin (plugin can only supplement `ls-*`).
- The AFL fork-server model is the wrong mental model for a warmed JVM; the executor concern is separate from the coverage concern.
- Harness feasibility must be front-loaded (M0 before deep Scala work); Régime 1 before Régime 2/BSP.
- Persistent-JVM determinism requires epoch restart + an explicit state-reset spec + a 1000-identical-input stability gate.
- Outcome classification, timeout=kill+restart, in-process controlled streams, backdrop-as-materializer, instrumentation scoping, provenance pinning, and version-skew handling are all required.

### Resolved Disagreements
- **Jazzer as an AFL forkserver**: Codex corrected that Jazzer is libFuzzer-based and does not implement LSPFuzz's forkserver/shmem protocol. Resolution: coverage agent and AFL-bridge are separate; executor architecture chosen via DEC-1 = Option B (new LibAFL executor), so Jazzer/agent is a coverage source only.
- **M0 strength**: Codex required M0 to also gate on the real LS classpath (M0b), not just a trivial JVM. Adopted.
- **Executor wiring mixing Option A/B concerns**: Codex required splitting by DEC-1. Adopted — Option B bypasses `check_binary`/ELF signatures/`AFL_DUMP_MAP_SIZE`.
- **Frozen-BSP shallowness**: Codex required an explicit "coverage reaches semantic paths" check (AC-7) before accepting DEC-6's frozen mode. Adopted with fallback to mock/replay or live BSP.
- **In-process drift from shipped entrypoint**: Codex required a cold-replay/equivalence check through `ls.core.Main`. Adopted (AC-5, task11).

### Convergence Status
- Final Status: `converged` (Codex round 2: no REQUIRED_CHANGES, no DISAGREE, CONVERGED=yes). Codex passes executed: 1 first-pass analysis + 2 convergence review rounds.

## Pending User Decisions

- DEC-1: Coverage-bridge / executor architecture.
  - Claude Position: Option B (new JVM-specific LibAFL executor).
  - Codex Position: Option B preferred (native supervisor Option A only if strict AFL-forkserver reuse is mandatory).
  - Tradeoff Summary: Option B is cleaner and avoids faking `fork()` on a threaded JVM; Option A reuses the existing forkserver path but must emulate the AFL child lifecycle.
  - Decision Status: **RESOLVED — Option B** (JVM-specific LibAFL executor).
- DEC-2: Do JSON-RPC error responses count as findings?
  - Claude Position: only crashes/hangs/uncaught failures.
  - Codex Position: N/A — open question.
  - Tradeoff Summary: including error responses catches "should-succeed-but-errored" semantic bugs at the cost of noise (needs triage/dedup).
  - Decision Status: **RESOLVED — include LSP error responses as findings** (with triage/dedup).
- DEC-3: Disable AOT cache + compact object headers for determinism until the harness is stable?
  - Claude Position: yes (re-enable once stable).
  - Codex Position: agrees (determinism until harness is stable).
  - Tradeoff Summary: determinism vs fidelity to the production configuration.
  - Decision Status: `PENDING` (Claude+Codex aligned default: disable until stable).
- DEC-4: Minimum useful throughput bar.
  - Claude Position: ~10/sec (PC), directional.
  - Codex Position: N/A — asked for a numeric bar.
  - Tradeoff Summary: higher bars force more aggressive harness optimization and risk.
  - Decision Status: **RESOLVED — ~1/sec, loose/directional** (investigation trigger, not a hard gate).
- DEC-5: Exercise `ls.core.Main` over stdio as shipped, or instantiate LS internals in-process?
  - Claude Position: in-process for the fuzzing loop + cold replay through the shipped entrypoint.
  - Codex Position: agrees (in-process acceptable only with an equivalence/cold-replay check).
  - Tradeoff Summary: in-process throughput/control vs drift from shipped behavior.
  - Decision Status: `PENDING` (Claude+Codex aligned default: in-process + shipped cold-replay check).
- DEC-6: BSP strategy for Régime 2.
  - Claude Position: frozen pre-indexed backdrop, BSP disabled after init (if AC-7 coverage-reach passes).
  - Codex Position: must be one of live / mock-replay / proven pre-indexed, validated by coverage reach.
  - Tradeoff Summary: frozen mode is most deterministic but risks shallow/error-only paths unless coverage reach is proven.
  - Decision Status: **RESOLVED — frozen pre-indexed + BSP disabled after init, contingent on AC-7** (fall back to mock/replay or live BSP if coverage reach fails).

## Implementation Notes

### Code Style Requirements
- Implementation code and comments MUST NOT contain plan-specific workflow terminology such as "AC-", "Milestone", "Phase", "Step", "Régime", "task1", "DEC-", or similar markers. These belong only in this plan document.
- Use descriptive, domain-appropriate naming in code (e.g. `scala_workspace`, `JvmWorkerExecutor`, `CoverageMapObserver`, `OutcomeClass`, an execution-profile type), not workflow labels.
- Reference code by path only, never by line number.

## Output File Convention

This plan is the main output file (`rlcr.md`). No translated language variant is generated
(`alternative_plan_language` resolved to empty/disabled). Identifiers (`AC-*`, task IDs, file
paths, API names, command flags) are language-neutral and remain unchanged.

--- Original Design Draft Start ---

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

--- Original Design Draft End ---
