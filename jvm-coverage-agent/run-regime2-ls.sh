#!/usr/bin/env bash
# Scala index-mode reach gate: prove the agent-instrumented LS reaches SemanticDB/index/BSP code AND
# that the index methods (workspace/symbol, textDocument/references, textDocument/rename) actually
# succeed against the frozen zaozi backdrop.
#
# It starts from the provenance-verified frozen backdrop (build-zaozi-backdrop.sh), materializes a
# THROWAWAY single-module live-BSP workspace from the verified artifacts (never mutating any source
# checkout), drives compile -> reindex -> symbol -> references -> rename, and passes only when:
#   * bootstrap reached readiness, the BSP compile completed non-error, reindex ingested docs>0, and
#     no target is IndexUnavailable;
#   * workspace/symbol returns a hit under the workspace, references returns a non-empty array, and
#     rename returns a non-empty WorkspaceEdit (JSON-RPC errors fail the gate);
#   * coverage reaches >=1 ls.semanticdb.* (the LS's own SemanticDB reader) AND >=1 server index
#     namespace (ls.index/postings/rename/sqlite). (This LS does not load scala.meta.* on the index
#     path; scala.meta is only reported for information.)
#
# A single module keeps the BSP compile within the LS's 30s request timeout. references/rename are
# driven against the on-disk indexed file (no unsaved buffer — the LS excludes unsaved-buffer symbols
# from global references/rename). The LS runs on its own pinned JDK (a foreign openjdk-25 build
# segfaults its FFM SQLite binding).
#
# Run inside a shell providing Mill (the BSP server the LS spawns) + jq, e.g. lsp-fuzz's .#jvm or
# zaozi's .#default:
#   LS_JAR=<...jar> BACKDROP_OUT=<dir built by build-zaozi-backdrop.sh> [COV_AGENT=1] \
#   ( nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/run-regime2-ls.sh )
set -euo pipefail

cd "$(dirname "$0")"
here="$(pwd)"
: "${LS_JAR:?set LS_JAR to the built scala3-bsp-semantic-ls.jar}"
: "${BACKDROP_OUT:?set BACKDROP_OUT to a backdrop built by build-zaozi-backdrop.sh}"
BACKDROP_OUT="$(cd "$BACKDROP_OUT" && pwd)"
MODULE="${BACKDROP_MODULE:-rvdecoderdb}"
COV_AGENT="${COV_AGENT:-1}"
command -v mill >/dev/null || { echo "FAIL: mill not on PATH — run inside a shell with Mill (e.g. nix develop .#jvm)"; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq required"; exit 1; }
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"

# The LS must run on its own pinned JDK (derived from its launcher wrapper); a foreign openjdk-25
# build segfaults its FFM SQLite binding. Mill (BSP server) uses whatever the shell provides.
LS_PKG_ROOT="$(dirname "$(dirname "$(dirname "$LS_JAR")")")"
LS_WRAPPER=$(ls "$LS_PKG_ROOT"/bin/* 2>/dev/null | head -1)
LS_JAVA=""
[ -n "$LS_WRAPPER" ] && [ -f "$LS_WRAPPER" ] && LS_JAVA=$(grep -aoE '/nix/store/[a-z0-9]+-openjdk[^/ ]*/bin/java' "$LS_WRAPPER" | head -1)
[ -n "$LS_JAVA" ] && [ -x "$LS_JAVA" ] || LS_JAVA="$(command -v java)"
export JAVA_HOME="$(dirname "$(dirname "$LS_JAVA")")"
if [ -z "${LS_SQLITE_LIB:-}" ]; then
  LS_SQLITE_LIB=$(nix-store -qR "$LS_JAR" 2>/dev/null | grep -iE 'sqlite-[0-9]' | head -1 | sed 's#$#/lib/libsqlite3.so#')
fi
[ -n "${LS_SQLITE_LIB:-}" ] && [ -e "$LS_SQLITE_LIB" ] || { echo "FAIL: LS_SQLITE_LIB not resolved"; exit 1; }
export LS_SQLITE_LIB
echo ">> LS JDK: $LS_JAVA"
echo ">> LS_SQLITE_LIB: $LS_SQLITE_LIB"

# 1. Verify the frozen backdrop provenance before consuming it (fail-closed).
echo ">> verifying frozen backdrop provenance"
BACKDROP_OUT="$BACKDROP_OUT" VERIFY_ONLY=1 ./build-zaozi-backdrop.sh >/dev/null
[ -d "$BACKDROP_OUT/sources/$MODULE" ] || { echo "FAIL: backdrop has no sources/$MODULE"; exit 1; }
[ -f "$BACKDROP_OUT/build.mill" ] || { echo "FAIL: backdrop has no frozen build.mill"; exit 1; }

# 2. Materialize a throwaway single-module live-BSP workspace from the VERIFIED artifacts only.
WS=$(mktemp -d)
trap 'rm -rf "$WS"' EXIT
cp "$BACKDROP_OUT/build.mill" "$WS/build.mill"
cp -r "$BACKDROP_OUT/sources/$MODULE" "$WS/$MODULE"
# Enable SemanticDB in the BSP-reported scalac options (the LS enables its index only when the BSP
# scalacOptions carry -Xsemanticdb); patch ONLY this throwaway copy.
python3 - "$WS/build.mill" "$WS" <<'PY'
import re, sys
p, root = sys.argv[1], sys.argv[2]
s = open(p).read()
want = 'super.scalacOptions() ++ Seq("-java-output-version", "25", "-Xsemanticdb", "-sourceroot", "%s")' % root
# Robust to a pristine build.mill or one already carrying -Xsemanticdb/-sourceroot: rewrite the
# whole scalacOptions expression so SemanticDB is on and the sourceroot points at THIS workspace.
pat = re.compile(r'super\.scalacOptions\(\) \+\+ Seq\("-java-output-version", "25"[^)]*\)')
assert pat.search(s), "ZaoziScalaModule scalacOptions block not found in frozen build.mill"
open(p, "w").write(pat.sub(lambda _: want, s, count=1))
PY
echo ">> throwaway workspace: $WS (module $MODULE)"

# 3. Build the coverage agent jar (same recipe as run-real-ls.sh).
ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
rm -rf out agentjar agent.jar r2-map.bin r2-classes.txt r2-out.log r2-resp.log
mkdir -p out agentjar
# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )
# fuzzing-determinism flags (stable coverage across identical inputs): disable compact object
# headers, disable the AOT/CDS archive, single-threaded GC. See docs/jvm-coverage-agent.md.
flags=(-XX:-UseCompactObjectHeaders -Xshare:off -XX:+UseSerialGC --enable-native-access=ALL-UNNAMED)
[ "$COV_AGENT" = 1 ] && flags=(-javaagent:"$here/agent.jar" "${flags[@]}")

# 4. Install BSP in the throwaway (single module -> BSP compile fits the LS's 30s request timeout).
( cd "$WS" && mill mill.bsp.BSP/install >/dev/null 2>&1 )
[ -f "$WS/.bsp/mill-bsp.json" ] || { echo "FAIL: mill.bsp.BSP/install produced no .bsp/mill-bsp.json"; exit 1; }

uri_of() { printf 'file://%s' "$(jq -Rr 'split("/")|map(@uri)|join("/")' <<<"$1")"; }
root_uri=$(uri_of "$WS")
send_obj() { local json; json=$(jq -nc "$@"); jq -e . >/dev/null 2>&1 <<<"$json"; printf 'Content-Length: %d\r\n\r\n%s' "${#json}" "$json" >&3; }
wait_log() { local f="$1" p="$2" t="$3" i=0; while [ "$i" -lt "$t" ]; do [ -f "$f" ] && grep -qE "$p" "$f" && return 0; sleep 1; i=$((i+1)); done; return 1; }
wait_resp() { wait_log "$here/r2-resp.log" "\"id\":$1[,}]" "$2"; }
# Extract the JSON-RPC message with the given id from the framed response stream (stdout).
resp() { python3 "$here/lsp_extract.py" "$here/r2-resp.log" "$1"; }

# 5. Launch the agent-instrumented LS (pinned JDK) against the throwaway workspace.
echo ">> launching LS (COV_AGENT=$COV_AGENT) against $root_uri"
dir=$(mktemp -d); ctl="$dir/ctl"; mkfifo "$ctl"
( cd "$WS" && COV_MAP_PATH="$here/r2-map.bin" COV_CLASSES_PATH="$here/r2-classes.txt" \
    "$LS_JAVA" "${flags[@]}" -jar "$LS_JAR" < "$ctl" > "$here/r2-resp.log" 2> "$here/r2-out.log" ) &
lspid=$!
exec 3>"$ctl"
send_obj --argjson id 1 --arg root "$root_uri" '{jsonrpc:"2.0",id:$id,method:"initialize",params:{processId:null,rootUri:$root,workspaceFolders:[{uri:$root,name:"ws"}],capabilities:{}}}'
send_obj '{jsonrpc:"2.0",method:"initialized",params:{}}'
ready=0; wait_log "$here/r2-out.log" 'bootstrap finished: ready' "${LS_BSP_READY_TIMEOUT:-300}" && ready=1
send_obj --argjson id 10 '{jsonrpc:"2.0",id:$id,method:"workspace/executeCommand",params:{command:"scala3SemanticLs.compile",arguments:[]}}'
wait_resp 10 "${LS_COMPILE_TIMEOUT:-120}" || true
send_obj --argjson id 11 '{jsonrpc:"2.0",id:$id,method:"workspace/executeCommand",params:{command:"scala3SemanticLs.reindex",arguments:[]}}'
wait_resp 11 "${LS_REINDEX_TIMEOUT:-180}" || true
send_obj --argjson id 12 --arg q "${LS_SYMBOL_QUERY:-Instruction}" '{jsonrpc:"2.0",id:$id,method:"workspace/symbol",params:{query:$q}}'
wait_resp 12 60 || true
# Pick a real indexed location from the symbol result (a workspace file), then drive
# references/rename at that on-disk position (no unsaved buffer).
loc=$(resp 12 | jq -c --arg ws "$root_uri" 'try (.result // [] | map(select(.location.uri|type=="string" and startswith($ws))) | .[0].location) catch empty' 2>/dev/null || true)
tgt_uri=$(jq -r '.uri // empty' <<<"$loc" 2>/dev/null || true)
tgt_line=$(jq -r '.range.start.line // empty' <<<"$loc" 2>/dev/null || true)
tgt_char=$(jq -r '.range.start.character // empty' <<<"$loc" 2>/dev/null || true)
if [ -n "$tgt_uri" ] && [ -n "$tgt_line" ] && [ -n "$tgt_char" ]; then
  send_obj --argjson id 13 --arg uri "$tgt_uri" --argjson ln "$tgt_line" --argjson ch "$tgt_char" \
    '{jsonrpc:"2.0",id:$id,method:"textDocument/references",params:{textDocument:{uri:$uri},position:{line:$ln,character:$ch},context:{includeDeclaration:true}}}'
  wait_resp 13 90 || true
  send_obj --argjson id 14 --arg uri "$tgt_uri" --argjson ln "$tgt_line" --argjson ch "$tgt_char" \
    '{jsonrpc:"2.0",id:$id,method:"textDocument/rename",params:{textDocument:{uri:$uri},position:{line:$ln,character:$ch},newName:"RenamedByFuzzGate"}}'
  wait_resp 14 120 || true
fi
sleep "${LS_SETTLE:-5}"
send_obj --argjson id 2 '{jsonrpc:"2.0",id:$id,method:"shutdown",params:null}'
send_obj '{jsonrpc:"2.0",method:"exit",params:null}'
exec 3>&-
( sleep 60; kill "$lspid" 2>/dev/null ) & guard=$!
wait "$lspid" 2>/dev/null || true
kill "$guard" 2>/dev/null || true
rm -rf "$dir"

# 6. Evaluate hard predicates.
crashed=$(grep -cE 'SIGSEGV|A fatal error has been detected' "$here/r2-out.log" 2>/dev/null || true)
if [ "${crashed:-0}" -gt 0 ]; then
  echo "FAIL: LS crashed (see r2-out.log). If SIGSEGV in sqlite3Malloc, the JDK is wrong (must be the LS's pinned build)."; exit 3
fi
indexunavail=$(grep -c 'IndexUnavailable' "$here/r2-out.log" 2>/dev/null || true)
compile_ok=$(resp 10 | jq -e '(.error|not) and (((.result//"")|tostring)|test("unavailable|not ready|not initialized|timed out")|not)' >/dev/null 2>&1 && echo 1 || echo 0)
reindex_docs=$(resp 11 | jq -r 'try ((.result|tostring)|capture("(?<n>[0-9]+) docs").n) catch empty' 2>/dev/null || true)
reindex_ok=$(resp 11 | jq -e '.error|not' >/dev/null 2>&1 && echo 1 || echo 0)
sym_hits=$(resp 12 | jq -r --arg ws "$root_uri" 'try (.result//[]|map(select(.location.uri|type=="string" and startswith($ws)))|length) catch 0' 2>/dev/null || echo 0)
ref_ok=$(resp 13 | jq -e 'try ((.error|not) and ((.result//[])|length>0)) catch false' >/dev/null 2>&1 && echo 1 || echo 0)
ref_n=$(resp 13 | jq -r 'try ((.result//[])|length) catch 0' 2>/dev/null || echo 0)
rename_ok=$(resp 14 | jq -e 'try ((.error|not) and (((.result.changes//{})|length>0) or ((.result.documentChanges//[])|length>0))) catch false' >/dev/null 2>&1 && echo 1 || echo 0)

# SemanticDB-reach signal is the LS's OWN SemanticDB reader (ls.semanticdb.ProtoReader/SdbDocument/
# FreshnessCheck/Md5/Normalizer), NOT the scalameta library — this LS parses SemanticDB protobuf
# itself and does not load scala.meta.* on the index path (scala.meta is reported for information).
sdb=$(grep -cE '^ls\.semanticdb\.' r2-classes.txt 2>/dev/null || true)
srv_index=$(grep -cE '^(ls\.index|ls\.postings|ls\.rename|ls\.sqlite)\.' r2-classes.txt 2>/dev/null || true)
meta=$(grep -cE '^scala\.meta\.' r2-classes.txt 2>/dev/null || true)
bsp=$(grep -cE '^ls\.bsp\.' r2-classes.txt 2>/dev/null || true)
pc=$(grep -cE '^ls\.pc\.' r2-classes.txt 2>/dev/null || true)
dotty=$(grep -cE '^dotty\.tools\.' r2-classes.txt 2>/dev/null || true)
transport=$(grep -cE '^org\.eclipse\.lsp4j' r2-classes.txt 2>/dev/null || true)

echo "=== predicates: ready=$ready compile_ok=$compile_ok reindex_ok=$reindex_ok reindex_docs='${reindex_docs:-0}' IndexUnavailable=$indexunavail symbol_hits=$sym_hits references_ok=$ref_ok(n=$ref_n) rename_ok=$rename_ok ==="
echo "=== coverage: ls.semanticdb=$sdb server-index=$srv_index ls.bsp=$bsp ls.pc=$pc scala.meta=$meta dotty.tools=$dotty transport=$transport ==="

if [ "$COV_AGENT" != 1 ]; then
  echo "NOTE (COV_AGENT=0): index-mechanism run without coverage; predicates above are the evidence."
fi

fail=0
[ "$ready" = 1 ] || { echo "MISS: bootstrap readiness"; fail=1; }
[ "$compile_ok" = 1 ] || { echo "MISS: compile response (non-error, not timed-out/unavailable)"; fail=1; }
[ "$reindex_ok" = 1 ] && [ "${reindex_docs:-0}" -gt 0 ] || { echo "MISS: reindex non-error with docs>0"; fail=1; }
[ "${indexunavail:-1}" -eq 0 ] || { echo "MISS: an IndexUnavailable target is present"; fail=1; }
[ "${sym_hits:-0}" -gt 0 ] || { echo "MISS: workspace/symbol hit under the workspace"; fail=1; }
[ "$ref_ok" = 1 ] || { echo "MISS: textDocument/references non-empty non-error"; fail=1; }
[ "$rename_ok" = 1 ] || { echo "MISS: textDocument/rename non-empty WorkspaceEdit"; fail=1; }
if [ "$COV_AGENT" = 1 ]; then
  [ "${sdb:-0}" -gt 0 ] || { echo "MISS: no ls.semanticdb.* (SemanticDB reader) coverage"; fail=1; }
  [ "${srv_index:-0}" -gt 0 ] || { echo "MISS: no server index-namespace coverage"; fail=1; }
fi

if [ "$fail" -eq 0 ]; then
  echo "OK (regime2): index methods succeed on the frozen backdrop (symbol=$sym_hits, references=$ref_n, rename OK; reindex ${reindex_docs} docs) and coverage reaches SemanticDB/index paths (ls.semanticdb=$sdb, server-index=$srv_index, transport=$transport) — NOT shallow."
  exit 0
fi
echo "FAIL (regime2): one or more hard predicates missed — see r2-out.log / r2-resp.log."
exit 2
