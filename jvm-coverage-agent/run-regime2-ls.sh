#!/usr/bin/env bash
# Measure Régime-2 (index-path) coverage reach: drive the agent-instrumented LS against a real
# BSP-backed Scala workspace and classify which LS classes the index methods reach.
#
# Régime-2 features (workspace/symbol, textDocument/references, textDocument/rename) read SemanticDB
# through a live BSP session. Empirically (and per the LS's own real-BSP integration test) the index
# only fills after (a) the build's BSP-reported scalac options carry `-Xsemanticdb` and (b) a compile
# is REQUESTED OVER BSP followed by a reindex — Mill 1.1.2 BSP evaluates into `.bsp/out`, so a plain
# CLI compile does not populate the BSP targetroots. This script drives that exact flow and then
# checks that coverage reaches the index/SemanticDB/BSP classes (`ls.index`, `ls.sqlite`,
# `ls.postings`, `ls.bsp`, `ls.rename`, `scala.meta`) beyond JSON-RPC transport and the `ls.pc`
# facade. If reach stays shallow, Régime-2's frozen mode is rejected in favor of live BSP.
#
# Run inside zaozi's dev shell so Mill (the BSP server the LS spawns) and JDK 25 are present:
#   LS_JAR=<.../scala3-bsp-semantic-ls.jar> ZAOZI_REPO=<zaozi-checkout> [BACKDROP_MODULE=rvdecoderdb] \
#   [LS_SQLITE_LIB=<libsqlite3.so>] \
#   ( cd <zaozi> && nix develop .#default -c /abs/path/to/run-regime2-ls.sh )
set -euo pipefail

cd "$(dirname "$0")"
: "${LS_JAR:?set LS_JAR to the built scala3-bsp-semantic-ls.jar}"
: "${ZAOZI_REPO:?set ZAOZI_REPO to a zaozi checkout}"
ZAOZI_REPO="$(cd "$ZAOZI_REPO" && pwd)"
BACKDROP_MODULE="${BACKDROP_MODULE:-rvdecoderdb}"
command -v mill >/dev/null || { echo "FAIL: mill not on PATH — run inside zaozi's 'nix develop .#default'"; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq required"; exit 1; }
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"
# The LS must run on the EXACT JDK it was built against: its FFM SQLite binding segfaults on a
# different openjdk-25 build (e.g. the zaozi dev shell's JDK) even at the same version. Derive the
# pinned JDK from the LS launcher wrapper; Mill (the BSP server the LS spawns) still uses the dev
# shell toolchain via the .bsp/mill-bsp.json argv.
LS_PKG_ROOT="$(dirname "$(dirname "$(dirname "$LS_JAR")")")"
LS_WRAPPER=$(ls "$LS_PKG_ROOT"/bin/* 2>/dev/null | head -1)
LS_JAVA=""
[ -n "$LS_WRAPPER" ] && [ -f "$LS_WRAPPER" ] && LS_JAVA=$(grep -aoE '/nix/store/[a-z0-9]+-openjdk[^/ ]*/bin/java' "$LS_WRAPPER" | head -1)
[ -n "$LS_JAVA" ] && [ -x "$LS_JAVA" ] || LS_JAVA="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}/bin/java"
export JAVA_HOME="$(dirname "$(dirname "$LS_JAVA")")"
echo ">> LS JDK: $LS_JAVA"
# The FFM SQLite binding requires the exact libsqlite3 the LS was built against (an ABI-mismatched
# system/other-version library segfaults in sqlite3Malloc). The LS launcher wrapper sets
# LS_SQLITE_LIB by default; running the bare jar bypasses it, so derive it from the jar's Nix
# closure when unset.
if [ -z "${LS_SQLITE_LIB:-}" ]; then
  LS_SQLITE_LIB=$(nix-store -qR "$LS_JAR" 2>/dev/null | grep -iE 'sqlite-[0-9]' | head -1 | sed 's#$#/lib/libsqlite3.so#')
fi
[ -n "${LS_SQLITE_LIB:-}" ] && [ -e "$LS_SQLITE_LIB" ] || { echo "FAIL: LS_SQLITE_LIB not resolved (set it to the LS's pinned libsqlite3.so)"; exit 1; }
export LS_SQLITE_LIB
echo ">> LS_SQLITE_LIB=$LS_SQLITE_LIB"

# --- Build the coverage agent jar (same recipe as run-real-ls.sh). ---
ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
rm -rf out agentjar agent.jar r2-map.bin r2-classes.txt r2-out.log
mkdir -p out agentjar
# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )
here="$(pwd)"
# Production-like JVM flags (match the LS launcher wrapper). Run on the LS's pinned JDK (above): the
# LS's FFM SQLite binding segfaults in sqlite3Malloc on a foreign openjdk-25 build, so the JDK — not
# the coverage agent or the sqlite version — is what must match. On the pinned JDK the agent
# instruments the index path cleanly. COV_AGENT=1 (default) attaches the coverage agent; COV_AGENT=0
# measures the index mechanism (BSP compile + reindex + symbol/references/rename) without coverage.
COV_AGENT="${COV_AGENT:-1}"
flags=(-XX:+UseCompactObjectHeaders --enable-native-access=ALL-UNNAMED)
[ "$COV_AGENT" = 1 ] && flags=(-javaagent:"$here/agent.jar" "${flags[@]}")

# --- Prepare the backdrop so BSP reports -Xsemanticdb (enables the index régime). ---
# Idempotently add `-Xsemanticdb -sourceroot <repo>` to the shared ZaoziScalaModule scalac options.
python3 - "$ZAOZI_REPO/build.mill" "$ZAOZI_REPO" <<'PY'
import sys
p, root = sys.argv[1], sys.argv[2]
s = open(p).read()
plain = 'super.scalacOptions() ++ Seq("-java-output-version", "25")'
want  = 'super.scalacOptions() ++ Seq("-java-output-version", "25", "-Xsemanticdb", "-sourceroot", "%s")' % root
if '-Xsemanticdb' not in s:
    assert plain in s, "ZaoziScalaModule scalacOptions block not found"
    open(p, "w").write(s.replace(plain, want, 1))
    print("injected -Xsemanticdb -sourceroot into scalacOptions")
else:
    print("scalacOptions already carry -Xsemanticdb")
PY
echo ">> installing BSP + compiling $BACKDROP_MODULE over the CLI (BSP compile is driven later)"
( cd "$ZAOZI_REPO" && mill mill.bsp.BSP/install >/dev/null 2>&1 && mill "$BACKDROP_MODULE".compile >/dev/null 2>&1 )
[ -f "$ZAOZI_REPO/.bsp/mill-bsp.json" ] || { echo "FAIL: no .bsp/mill-bsp.json after install"; exit 1; }

# A representative source + a symbol in it to query symbol/references/rename against.
doc_rel="$BACKDROP_MODULE/src/Instruction.scala"
[ -f "$ZAOZI_REPO/$doc_rel" ] || doc_rel=$(cd "$ZAOZI_REPO" && find "$BACKDROP_MODULE" -name '*.scala' | head -1)
doc_uri="file://$(jq -Rr 'split("/")|map(@uri)|join("/")' <<<"$ZAOZI_REPO/$doc_rel")"
root_uri="file://$(jq -Rr 'split("/")|map(@uri)|join("/")' <<<"$ZAOZI_REPO")"
doc_text=$(cat "$ZAOZI_REPO/$doc_rel")

send_obj() { local json; json=$(jq -nc "$@"); jq -e . >/dev/null 2>&1 <<<"$json"; printf 'Content-Length: %d\r\n\r\n%s' "${#json}" "$json" >&3; }
wait_log() { local f="$1" p="$2" t="$3" i=0; while [ "$i" -lt "$t" ]; do [ -f "$f" ] && grep -qE "$p" "$f" && return 0; sleep 1; i=$((i+1)); done; return 1; }

echo ">> launching agent-instrumented LS against $root_uri"
dir=$(mktemp -d); ctl="$dir/ctl"; mkfifo "$ctl"
( cd "$ZAOZI_REPO" && COV_MAP_PATH="$here/r2-map.bin" COV_CLASSES_PATH="$here/r2-classes.txt" \
    "$JAVA_HOME/bin/java" "${flags[@]}" -jar "$LS_JAR" < "$ctl" > "$here/r2-out.log" 2>&1 ) &
lspid=$!
exec 3>"$ctl"
send_obj --argjson id 1 --arg root "$root_uri" '{jsonrpc:"2.0",id:$id,method:"initialize",params:{processId:null,rootUri:$root,workspaceFolders:[{uri:$root,name:"ws"}],capabilities:{}}}'
send_obj '{jsonrpc:"2.0",method:"initialized",params:{}}'
wait_log "$here/r2-out.log" 'bootstrap finished: ready' "${LS_BSP_READY_TIMEOUT:-300}" || echo "WARN: readiness not observed in time"
# Editor-session flow: compile over BSP, then reindex the produced SemanticDB.
send_obj --argjson id 10 '{jsonrpc:"2.0",id:$id,method:"workspace/executeCommand",params:{command:"scala3SemanticLs.compile",arguments:[]}}'
wait_log "$here/r2-out.log" '"id":10' "${LS_COMPILE_TIMEOUT:-300}" || true
send_obj --argjson id 11 '{jsonrpc:"2.0",id:$id,method:"workspace/executeCommand",params:{command:"scala3SemanticLs.reindex",arguments:[]}}'
wait_log "$here/r2-out.log" '"id":11' "${LS_REINDEX_TIMEOUT:-180}" || true
# Index methods.
send_obj --argjson id 12 --arg q "$(basename "$doc_rel" .scala)" '{jsonrpc:"2.0",id:$id,method:"workspace/symbol",params:{query:$q}}'
send_obj --arg uri "$doc_uri" --arg text "$doc_text" '{jsonrpc:"2.0",method:"textDocument/didOpen",params:{textDocument:{uri:$uri,languageId:"scala",version:1,text:$text}}}'
sleep 3
send_obj --argjson id 13 --arg uri "$doc_uri" '{jsonrpc:"2.0",id:$id,method:"textDocument/references",params:{textDocument:{uri:$uri},position:{line:0,character:8},context:{includeDeclaration:true}}}'
send_obj --argjson id 14 --arg uri "$doc_uri" '{jsonrpc:"2.0",id:$id,method:"textDocument/rename",params:{textDocument:{uri:$uri},position:{line:0,character:8},newName:"Renamed1"}}'
sleep "${LS_SETTLE:-8}"
send_obj --argjson id 2 '{jsonrpc:"2.0",id:$id,method:"shutdown",params:null}'
send_obj '{jsonrpc:"2.0",method:"exit",params:null}'
exec 3>&-
( sleep 60; kill "$lspid" 2>/dev/null ) & guard=$!
wait "$lspid" 2>/dev/null || true
kill "$guard" 2>/dev/null || true
rm -rf "$dir"

# --- Report. ---
crashed=$(grep -cE 'SIGSEGV|A fatal error has been detected' "$here/r2-out.log" 2>/dev/null || true)
ready=$(grep -cE 'bootstrap finished: ready' "$here/r2-out.log" 2>/dev/null || true)
reindex_resp=$(grep -oE '\{"jsonrpc":"2\.0","id":11[^}]*\}' "$here/r2-out.log" | head -1 || true)
symbol_resp=$(grep -oE '\{"jsonrpc":"2\.0","id":12[^}]*\}' "$here/r2-out.log" | head -1 || true)
reindex_docs=$(grep -oiE '[0-9]+ docs' "$here/r2-out.log" | head -1 || true)
unavailable=$(grep -c 'IndexUnavailable' "$here/r2-out.log" 2>/dev/null || true)
echo "=== index-régime signals: ready=$ready reindex_docs='${reindex_docs:-none}' IndexUnavailable=$unavailable ==="
echo "reindex resp: ${reindex_resp:-<none>}"
echo "symbol resp:  ${symbol_resp:-<none>}"

if [ "$COV_AGENT" = 1 ]; then
  if [ "${crashed:-0}" -gt 0 ] && { [ ! -s r2-classes.txt ] || ! grep -qE '^(ls\.index|scala\.meta)\.' r2-classes.txt; }; then
    echo "FAIL: the LS crashed (SIGSEGV in sqlite3Malloc via MetaStore.open) before the index ran. This is almost always the WRONG JDK — the LS must run on its own pinned openjdk build (see the '>> LS JDK' line), not the dev shell's. Verify LS_JAVA and LS_SQLITE_LIB. See r2-out.log."
    exit 3
  fi
  idx=$(grep -cE '^(ls\.index|ls\.sqlite|ls\.postings|ls\.rename|scala\.meta)\.' r2-classes.txt 2>/dev/null || true)
  transport=$(grep -cE '^org\.eclipse\.lsp4j' r2-classes.txt 2>/dev/null || true)
  pc=$(grep -cE '^ls\.pc\.' r2-classes.txt 2>/dev/null || true)
  echo "=== Régime-2 coverage reach: index/semanticdb=$idx pc(facade)=$pc transport=$transport ==="
  if [ "${idx:-0}" -gt 0 ]; then
    echo "OK (regime2): index methods reach SemanticDB/index classes ($idx) beyond transport ($transport)/facade ($pc) — Régime-2 index paths are NOT shallow"
    exit 0
  fi
  echo "SHALLOW (regime2): index-path classes not reached (idx=0) despite running — adopt the live-BSP fallback. See r2-out.log."
  exit 2
fi

# COV_AGENT=0: no coverage, measure the index MECHANISM reach (does the LS light up the index?).
if [ "${crashed:-0}" -gt 0 ]; then echo "FAIL: LS crashed even without the agent — see r2-out.log"; exit 1; fi
if [ "${ready:-0}" -gt 0 ] && { [ -n "$reindex_docs" ] || [ -n "$symbol_resp" ]; }; then
  echo "OK (regime2 mechanism, no agent): LS reached bootstrap-ready over live BSP against the zaozi backdrop and the index methods responded (reindex='${reindex_docs:-?}'). The index régime is reachable; coverage instrumentation is blocked on the agent<->FFM fix."
  exit 0
fi
echo "SHALLOW/INCOMPLETE (regime2 mechanism): readiness=$ready reindex='${reindex_docs:-none}' — index not confirmed populated; see r2-out.log."
exit 2
