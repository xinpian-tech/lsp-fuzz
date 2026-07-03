#!/usr/bin/env bash
# Build the frozen zaozi SemanticDB/BSP backdrop deterministically and record provenance.
#
# The Scala index régime of the target LS (workspace/symbol, references, rename) is disabled
# unless the workspace exposes SemanticDB output. This script builds a real zaozi checkout with
# SemanticDB emitted (Mill's built-in `<module>.semanticDbData` task — no build file patching),
# installs the BSP connection file, then freezes and provenances the result so a finding can be
# cold-replayed against the exact same indexed backdrop.
#
# It is FAIL-CLOSED: the backdrop is only accepted if SemanticDB output exists, the BSP config is
# present, and (in verify mode) the recomputed snapshot hash matches the recorded metadata.
#
# Usage (build):
#   ZAOZI_REPO=<path-to-zaozi-checkout> [ZAOZI_COMMIT=<sha>] [BACKDROP_MODULES="rvdecoderdb"] \
#   [BACKDROP_OUT=<dir>] ./build-zaozi-backdrop.sh
# Usage (verify an existing backdrop against its metadata; no build):
#   BACKDROP_OUT=<dir> VERIFY_ONLY=1 ./build-zaozi-backdrop.sh
#
# Mill needs zaozi's own toolchain (JDK 25 + Mill + the CIRCT/MLIR/jextract natives for the FFM
# modules). Pure-Scala modules such as `rvdecoderdb` build with only the JDK+Mill+Maven deps. The
# script runs Mill inside `nix develop <ZAOZI_REPO>#default` so the toolchain is provisioned
# reproducibly; set MILL_ON_PATH=1 to skip the wrapper when `mill` is already available.
set -euo pipefail

die() { echo "FAIL: $*" >&2; exit 1; }
log() { echo ">> $*" >&2; }

BACKDROP_OUT="${BACKDROP_OUT:-$(pwd)/zaozi-backdrop}"
BACKDROP_MODULES="${BACKDROP_MODULES:-rvdecoderdb}"
META="$BACKDROP_OUT/backdrop-metadata.json"

# Deterministic content hash over the frozen fileset (sources + generated SemanticDB). Paths are
# taken RELATIVE to the backdrop root and content-hashed, so the digest is independent of the
# absolute install location, mtimes, and directory-walk order — a backdrop verifies wherever it is
# replayed.
snapshot_hash() {
  local root="$1"
  ( cd "$root" &&
    { find sources -type f -name '*.scala' 2>/dev/null
      find sources -type f -name 'package.mill' 2>/dev/null
      find semanticdb -type f -name '*.semanticdb' 2>/dev/null
      [ -f build.mill ] && echo build.mill; } | LC_ALL=C sort |
      while IFS= read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done
  ) | sha256sum | cut -d' ' -f1
}

# Fail-closed acceptance checks shared by build and verify.
assert_backdrop() {
  local root="$1"
  [ -d "$root" ] || die "backdrop dir missing: $root"
  local sdb; sdb=$(find "$root/semanticdb" -type f -name '*.semanticdb' 2>/dev/null | wc -l)
  [ "$sdb" -gt 0 ] || die "no SemanticDB output in backdrop (index régime would be disabled)"
  [ -f "$root/bsp/mill-bsp.json" ] || die "BSP config absent: $root/bsp/mill-bsp.json"
  [ -f "$META" ] || die "metadata absent: $META"
  local recorded computed bsp_recorded bsp_computed
  recorded=$(jq -r '.snapshot.sha256' "$META")
  computed=$(snapshot_hash "$root")
  [ "$recorded" = "$computed" ] || die "snapshot hash mismatch: recorded=$recorded computed=$computed"
  # BSP config is the live SemanticDB-activation channel and part of the pinned provenance, so its
  # frozen content must match the recorded hash — not merely exist. (It carries machine-absolute
  # launcher paths, so it is pinned exactly rather than folded into the portable snapshot hash.)
  bsp_recorded=$(jq -r '.bsp.sha256' "$META")
  bsp_computed=$(sha256sum "$root/bsp/mill-bsp.json" | cut -d' ' -f1)
  [ "$bsp_recorded" = "$bsp_computed" ] || die "BSP config hash mismatch: recorded=$bsp_recorded computed=$bsp_computed"
  log "backdrop OK: $sdb SemanticDB files; BSP config hash matches; snapshot hash $computed"
}

if [ -n "${VERIFY_ONLY:-}" ]; then
  log "verify-only mode against $BACKDROP_OUT"
  assert_backdrop "$BACKDROP_OUT"
  echo "OK (verify): frozen zaozi backdrop matches recorded provenance"
  exit 0
fi

: "${ZAOZI_REPO:?set ZAOZI_REPO to a zaozi checkout}"
ZAOZI_REPO="$(cd "$ZAOZI_REPO" && pwd)"
command -v jq >/dev/null || die "jq required"

commit=$(git -C "$ZAOZI_REPO" rev-parse HEAD)
if [ -n "${ZAOZI_COMMIT:-}" ] && [ "$ZAOZI_COMMIT" != "$commit" ]; then
  die "zaozi commit mismatch: expected $ZAOZI_COMMIT got $commit"
fi
scala_version=$(grep -oE 'val scala\s*=\s*"[^"]+"' "$ZAOZI_REPO/build.mill" | grep -oE '[0-9][^"]+')
mill_version=$(grep -oE 'mill-version:\s*[0-9.]+' "$ZAOZI_REPO/build.mill" | grep -oE '[0-9.]+')
log "zaozi commit=$commit scala=$scala_version mill=$mill_version modules='$BACKDROP_MODULES'"

# One devshell entry runs every Mill step (re-entering per call reinstalls the Ivy cache).
mill_steps='set -euo pipefail; cd "'"$ZAOZI_REPO"'"
mill mill.bsp.BSP/install
for m in '"$BACKDROP_MODULES"'; do mill "$m".semanticDbData >&2; done
for m in '"$BACKDROP_MODULES"'; do mill show "$m".compileClasspath; done'
if [ -n "${MILL_ON_PATH:-}" ]; then
  cp_json=$(cd "$ZAOZI_REPO" && bash -c "$mill_steps")
else
  # Enter the devshell from within the repo: zaozi's shellHook runs Mill against the current dir.
  cp_json=$(cd "$ZAOZI_REPO" && nix develop "$ZAOZI_REPO"#default --command bash -c "$mill_steps")
fi
# `mill show` emits one JSON array per module; hash the concatenation for a stable classpath id.
classpath_hash=$(printf '%s' "$cp_json" | sha256sum | cut -d' ' -f1)

[ -f "$ZAOZI_REPO/.bsp/mill-bsp.json" ] || die "mill.bsp.BSP/install produced no .bsp/mill-bsp.json"
bsp_version=$(jq -r '.bspVersion // .version // "unknown"' "$ZAOZI_REPO/.bsp/mill-bsp.json")
bsp_name=$(jq -r '.name // "unknown"' "$ZAOZI_REPO/.bsp/mill-bsp.json")

# Freeze: copy indexed-module sources + generated SemanticDB + the BSP config into BACKDROP_OUT.
rm -rf "$BACKDROP_OUT"; mkdir -p "$BACKDROP_OUT/sources" "$BACKDROP_OUT/semanticdb" "$BACKDROP_OUT/bsp"
sdb_count=0
for m in $BACKDROP_MODULES; do
  [ -d "$ZAOZI_REPO/$m" ] && cp -r "$ZAOZI_REPO/$m" "$BACKDROP_OUT/sources/"
  # semanticDbData writes META-INF/semanticdb/**.scala.semanticdb under its dest.
  while IFS= read -r f; do
    rel=${f#*/META-INF/semanticdb/}
    mkdir -p "$BACKDROP_OUT/semanticdb/$(dirname "$rel")"
    cp "$f" "$BACKDROP_OUT/semanticdb/$rel"
    sdb_count=$((sdb_count + 1))
  done < <(find "$ZAOZI_REPO/out/$m/semanticDbDataDetailed.dest/data/META-INF/semanticdb" \
             -type f -name '*.semanticdb' 2>/dev/null)
done
[ "$sdb_count" -gt 0 ] || die "no SemanticDB files were generated for modules: $BACKDROP_MODULES"
# Freeze the top-level build.mill too, so a throwaway single-module workspace can be materialized
# entirely from verified artifacts (the Régime-2 reach gate needs it + the module sources).
cp "$ZAOZI_REPO/build.mill" "$BACKDROP_OUT/build.mill"
cp "$ZAOZI_REPO/.bsp/mill-bsp.json" "$BACKDROP_OUT/bsp/mill-bsp.json"
bsp_hash=$(sha256sum "$BACKDROP_OUT/bsp/mill-bsp.json" | cut -d' ' -f1)

snap=$(snapshot_hash "$BACKDROP_OUT")
jq -n \
  --arg commit "$commit" --arg scala "$scala_version" --arg mill "$mill_version" \
  --arg modules "$BACKDROP_MODULES" --arg cph "$classpath_hash" --arg snap "$snap" \
  --arg bspv "$bsp_version" --arg bspn "$bsp_name" --arg bsph "$bsp_hash" --argjson sdb "$sdb_count" \
  --arg ls_scala "3.8.4" \
  '{
    zaozi: { repo: "github.com/xinpian-tech/zaozi", commit: $commit },
    versions: { scala: $scala, mill: $mill, ls_scala: $ls_scala,
                semanticdb: { schema: 4, producer: ("scala3 " + $scala + " (Mill semanticDbData)") } },
    indexed_modules: ($modules | split(" ")),
    bsp: { file: "bsp/mill-bsp.json", server: $bspn, bspVersion: $bspv, sha256: $bsph },
    classpath: { sha256: $cph },
    semanticdb: { count: $sdb, root: "semanticdb" },
    snapshot: { root: ".", files: "build.mill + sources/**.{scala,package.mill} + semanticdb/**.semanticdb", sha256: $snap },
    version_skew: {
      note: "zaozi compiles with Scala \($scala); the target LS bundles the Scala 3.8.4 presentation compiler.",
      handling: "SemanticDB uses the stable schema-4 format shared across Scala 3.7 and 3.8, so the LS scalameta reader consumes the 3.7.4-produced SemanticDB unchanged. If the LS ever rejects it, recompile the backdrop with BACKDROP scala pinned to 3.8.4."
    }
  }' > "$META"

assert_backdrop "$BACKDROP_OUT"
echo "OK (build): frozen zaozi backdrop at $BACKDROP_OUT ($sdb_count SemanticDB files; commit ${commit:0:12}; snapshot $snap)"
