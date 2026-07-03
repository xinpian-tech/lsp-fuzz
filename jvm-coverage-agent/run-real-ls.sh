#!/usr/bin/env bash
# Attach the coverage agent to the real scala3-bsp-smantic-ls jar and measure coverage reach by
# driving an LSP session over stdio. All LSP payloads are built and validated with jq.
#
#   * NEGATIVE/CONTROL (no BSP, always run): the agent attaches and produces a non-empty,
#     near-deterministic map reaching the server's own layers (ls.pc.* facade) while the compiler
#     internals stay unreached and the LS logs "PC is disabled".
#   * POSITIVE (BSP-backed, when LS_BSP_WORKSPACE is a workspace prepared by setup-bsp-workspace.sh):
#     the LS establishes BSP; after a driven compile the run must reach dotty.tools.*/scala.meta.*.
#
# Requires the built LS jar (see docs/jvm-target.md):
#   LS_JAR=<.../scala3-bsp-semantic-ls.jar> [LS_SQLITE_LIB=<libsqlite3.so>] [LS_BSP_WORKSPACE=<dir>] \
#   nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/run-real-ls.sh
set -euo pipefail

cd "$(dirname "$0")"
: "${LS_JAR:?set LS_JAR to the built scala3-bsp-semantic-ls.jar}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"
[ -n "${LS_SQLITE_LIB:-}" ] && export LS_SQLITE_LIB
export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"

ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
rm -rf out agentjar agent.jar ls-map-*.bin ls-classes-*.txt ls-out-*.log zero.bin
mkdir -p out agentjar
# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )

head -c 65536 /dev/zero > zero.bin
here="$(pwd)"
agent="$here/agent.jar"
flags=(-javaagent:"$agent" -XX:-UseCompactObjectHeaders -Xshare:off -XX:+UseSerialGC --enable-native-access=ALL-UNNAMED)
java="$JAVA_HOME/bin/java"
edges() { cmp -l "$1" zero.bin 2>/dev/null | wc -l; }

# send_obj builds one JSON-RPC object with jq (proper encoding), validates it, and frames it on fd 3.
send_obj() {
  local json
  json=$(jq -nc "$@")
  jq -e . >/dev/null 2>&1 <<<"$json"
  printf 'Content-Length: %d\r\n\r\n%s' "${#json}" "$json" >&3
}

# run_epoch <n> <cwd> <wsRoot|""> <docUri> <docText> <driveCompile:0|1>
run_epoch() {
  local n="$1" cwd="$2" wsRoot="$3" docUri="$4" docText="$5" driveCompile="$6"
  local dir ctl; dir=$(mktemp -d); ctl="$dir/ctl"; mkfifo "$ctl"
  ( cd "$cwd" && COV_MAP_PATH="$here/ls-map-$n.bin" COV_CLASSES_PATH="$here/ls-classes-$n.txt" \
      "$java" "${flags[@]}" -jar "$LS_JAR" < "$ctl" > "$here/ls-out-$n.log" 2>&1 ) &
  local lspid=$!
  exec 3>"$ctl"
  if [ -z "$wsRoot" ]; then
    send_obj --argjson id 1 '{jsonrpc:"2.0",id:$id,method:"initialize",params:{processId:null,rootUri:null,capabilities:{}}}'
  else
    send_obj --argjson id 1 --arg root "file://$wsRoot" '{jsonrpc:"2.0",id:$id,method:"initialize",params:{processId:null,rootUri:$root,workspaceFolders:[{uri:$root,name:"ws"}],capabilities:{}}}'
  fi
  send_obj '{jsonrpc:"2.0",method:"initialized",params:{}}'
  send_obj --arg uri "$docUri" --arg text "$docText" '{jsonrpc:"2.0",method:"textDocument/didOpen",params:{textDocument:{uri:$uri,languageId:"scala",version:1,text:$text}}}'
  if [ "$driveCompile" = 1 ]; then
    send_obj --argjson id 10 '{jsonrpc:"2.0",id:$id,method:"workspace/executeCommand",params:{command:"scala3SemanticLs.compile",arguments:[]}}'
    sleep "${LS_COMPILE_SLEEP:-90}" # let BSP compile + classpath resolve so the PC can answer
  fi
  send_obj --argjson id 2 --arg uri "$docUri" '{jsonrpc:"2.0",id:$id,method:"textDocument/completion",params:{textDocument:{uri:$uri},position:{line:2,character:11}}}'
  sleep "${LS_SESSION_SLEEP:-30}"
  send_obj --argjson id 3 '{jsonrpc:"2.0",id:$id,method:"shutdown",params:null}'
  send_obj '{jsonrpc:"2.0",method:"exit",params:null}'
  exec 3>&-
  ( sleep 45; kill "$lspid" 2>/dev/null ) & local guard=$!
  wait "$lspid" 2>/dev/null || true
  kill "$guard" 2>/dev/null || true
  rm -rf "$dir"
}

fail=0
# --- Negative / control gate (no BSP) ---
ctrl_text=$'object Demo:\n  def add(a: Int, b: Int): Int = a + b\n  val y = ad\n'
run_epoch 1 "$here" "" "file:///tmp/Demo.scala" "$ctrl_text" 0
run_epoch 2 "$here" "" "file:///tmp/Demo.scala" "$ctrl_text" 0
if [ ! -s ls-classes-1.txt ] || cmp -s ls-map-1.bin zero.bin; then
  echo "FAIL (control): agent produced no/empty coverage"; fail=1
else
  e1=$(edges ls-map-1.bin); e2=$(edges ls-map-2.bin); delta=$(( e1 > e2 ? e1 - e2 : e2 - e1 ))
  pc=$(grep -cE '^ls\.pc\.' ls-classes-1.txt || true)
  compiler=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-1.txt || true)
  cmp -s ls-classes-1.txt ls-classes-2.txt && cdet=identical || cdet=DIFFERED
  if [ "$pc" -gt 0 ] && [ "$compiler" -eq 0 ] && [ "$cdet" = identical ] && [ "$delta" -le 32 ] \
     && grep -q 'PC is disabled' ls-out-1.log; then
    echo "OK (control): agent attaches to real LS; non-empty (~$e1 edges, delta $delta); class set identical; reaches ls.pc.* ($pc); compiler unreached ($compiler); 'PC is disabled' — expected without BSP"
  else
    echo "FAIL (control): expected PC-disabled + ls.pc>0 + compiler==0 + identical set + delta<=32 (e=$e1/$e2 pc=$pc compiler=$compiler set=$cdet)"; fail=1
  fi
fi

# --- Positive gate (BSP-backed) ---
if [ -n "${LS_BSP_WORKSPACE:-}" ]; then
  ws="$(cd "$LS_BSP_WORKSPACE" && pwd)"
  doc="file://$ws/app/src/Foo.scala"
  pos_text=$'object Foo:\n  def greet(name: String): String = "hi " + name\n  val z = gre\n'
  run_epoch 3 "$ws" "$ws" "$doc" "$pos_text" 1
  run_epoch 4 "$ws" "$ws" "$doc" "$pos_text" 1
  bsp_ok=$(grep -c 'BSP server started' ls-out-3.log || true)
  jsonerr=$(grep -icE 'invalid.*json|jsonrpc.*(parse|invalid)|Unrecognized|MalformedJson' ls-out-3.log || true)
  e3=$(edges ls-map-3.bin); e4=$(edges ls-map-4.bin); pdelta=$(( e3 > e4 ? e3 - e4 : e4 - e3 ))
  c3=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-3.txt 2>/dev/null || true)
  c4=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-4.txt 2>/dev/null || true)
  cmp -s ls-classes-3.txt ls-classes-4.txt && pset=identical || pset=DIFFERED
  # The compiler path runs many background/JIT threads, so raw edge counts vary more than the
  # no-BSP control; the deterministic signal is the identical covered-class set. Allow ~10% edge
  # drift (pdelta*10 <= e3) and require large non-empty maps + compiler-class reach in both epochs.
  if [ "${c3:-0}" -gt 0 ] && [ "${c4:-0}" -gt 0 ] && [ "$e3" -gt 0 ] && [ "$e4" -gt 0 ] \
     && [ "$pset" = identical ] && [ $((pdelta * 10)) -le "$e3" ] && [ "$bsp_ok" -gt 0 ] && [ "$jsonerr" -eq 0 ]; then
    echo "OK (positive): BSP-backed run reaches compiler/scalameta ($c3/$c4 classes; edges $e3/$e4 delta $pdelta ~$(( pdelta * 100 / e3 ))%; class set $pset)"
  else
    echo "FAIL (positive): BSP=$bsp_ok jsonerr=$jsonerr compiler=$c3/$c4 edges=$e3/$e4 delta=$pdelta set=$pset — compiler reach not yet proven"; fail=1
  fi
else
  echo "SKIP (positive): set LS_BSP_WORKSPACE (prepared with setup-bsp-workspace.sh) to require dotty.tools/scala.meta coverage"
fi
exit $fail
