# Frozen zaozi SemanticDB/BSP backdrop

The Scala index features of the target LS — `workspace/symbol`, whole-repo
`textDocument/references`, cross-file `textDocument/rename` — read SemanticDB. Fuzzing those paths
needs a pre-indexed, immutable workspace: a real `github.com/xinpian-tech/zaozi` checkout compiled
with SemanticDB, plus a BSP connection file, pinned to exact versions/hashes so a finding can be
cold-replayed against the byte-identical backdrop.

`jvm-coverage-agent/build-zaozi-backdrop.sh` builds and provenances that backdrop; it is
**fail-closed** — a backdrop is only accepted if SemanticDB output exists, the BSP config is
present, and the recorded snapshot hash matches on re-verification.

## How the LS decides SemanticDB is available

The LS derives its SemanticDB configuration from a build target's scalac options, not from a
filesystem scan. `ls.bsp.SemanticdbFlags.extract` enables the index régime **iff the BSP
`buildTarget/scalacOptions` response contains `-Xsemanticdb` or `-Ysemanticdb`**; the SemanticDB
targetroot is the `-semanticdb-target` value, or otherwise the reported class directory, and the
sourceroot is `-sourceroot` or the workspace root. Without an enable flag the target is
`IndexUnavailable` and the global index features are disabled.

Two consequences shaped this tooling:

- **Producing SemanticDB.** Mill's plain `compile` does not retain `.semanticdb` in the class
  directory even with `-Xsemanticdb` in `scalacOptions`. The built-in `<module>.semanticDbData`
  task is the emit path: it writes `META-INF/semanticdb/**.scala.semanticdb` under
  `out/<module>/semanticDbDataDetailed.dest/`. It works on the vanilla `build.mill` with no source
  patching. (`semanticDbEnabled` is not an overridable member in Mill 1.1.2 — overriding it fails
  the meta-build.)
- **Activation is a live-BSP property.** Mill's BSP server injects the SemanticDB flag into its
  `buildTarget/scalacOptions` response at session time. So whether the LS actually lights up the
  index against this backdrop (the `has no SemanticDB output; ... disabled` note disappearing) is
  measured by driving the real LS↔Mill BSP session — that is the Régime-2 reach measurement, not a
  static property of the frozen files.

## What the script builds

```
BACKDROP_OUT/
  sources/<module>/…            # the indexed module's Scala sources (frozen)
  semanticdb/**.scala.semanticdb # generated SemanticDB (genuine symbol data)
  bsp/mill-bsp.json             # the BSP connection file
  backdrop-metadata.json        # pinned provenance (below)
```

`backdrop-metadata.json` records: zaozi repo + commit, Scala version, Mill version, the LS's Scala
version, the SemanticDB schema/producer, the indexed modules, the BSP server name/version and file
hash, a classpath hash (`mill show <module>.compileClasspath`), the SemanticDB file count, the
location-independent snapshot hash, and the version-skew handling.

### Version skew (zaozi 3.7.4 vs LS 3.8.4)

zaozi compiles with Scala 3.7.4; the LS bundles the Scala 3.8.4 presentation compiler. SemanticDB
uses the stable schema-4 format shared across Scala 3.7 and 3.8, so the LS's scalameta reader
consumes the 3.7.4-produced SemanticDB unchanged. If the LS ever rejects it, recompile the backdrop
with the module's Scala pinned to 3.8.4. This is recorded in `version_skew` in the metadata.

## Usage

```bash
# Build (inside nothing special — the script enters zaozi's own devshell for the Mill toolchain):
ZAOZI_REPO=<path-to-zaozi-checkout> ZAOZI_COMMIT=<expected-sha> \
  BACKDROP_MODULES="rvdecoderdb" BACKDROP_OUT=<dir> \
  ./jvm-coverage-agent/build-zaozi-backdrop.sh

# Re-verify an existing backdrop against its recorded metadata (fail-closed, no build):
BACKDROP_OUT=<dir> VERIFY_ONLY=1 ./jvm-coverage-agent/build-zaozi-backdrop.sh

# Prove the verifier is genuinely fail-closed (missing SemanticDB / missing BSP / content drift):
BACKDROP_OUT=<dir> ./jvm-coverage-agent/check-backdrop-failclosed.sh
```

`rvdecoderdb` is the default indexed module: it is pure Scala (only Maven deps), so it builds with
just JDK 25 + Mill and yields genuine zaozi SemanticDB in ~15s. zaozi's FFM modules
(`mlirlib`/`circtlib`/`zaozi`) additionally need the CIRCT/MLIR/jextract natives that zaozi's flake
provisions; pass them via `BACKDROP_MODULES` once that toolchain is available to widen the indexed
surface.

## Verified

- `build-zaozi-backdrop.sh` against zaozi `fefb58e9` (Scala 3.7.4, Mill 1.1.2): 15 SemanticDB files
  for `rvdecoderdb`, BSP config present, metadata complete, self-verify OK.
- The SemanticDB payloads are genuine (e.g. `Instruction.scala.semanticdb` carries 657
  `org/chipsalliance/rvdecoderdb/…` symbol occurrences), not empty stubs.
- `check-backdrop-failclosed.sh`: rejects missing-SemanticDB, missing-BSP, and content-drift;
  accepts an intact copy at a different path (the snapshot hash is location-independent).

## Next

- Régime-2 reach (plan task16): drive the real LS against this backdrop over BSP and confirm the
  index features reach SemanticDB/index/BSP classes (not just transport), then wire the
  frozen/BSP-disabled-after-init mode.
