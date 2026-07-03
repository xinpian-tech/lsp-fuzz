#!/usr/bin/env bash
# Attach the coverage agent to the real scala3-bsp-smantic-ls jar and measure coverage reach by
# driving an LSP initialize/didOpen/completion/shutdown session over stdio.
#
# This LS disables the presentation compiler without a BSP connection, so there are two gates:
#   * NEGATIVE/CONTROL (no BSP, always run): confirms the agent attaches and produces a non-empty,
#     near-deterministic map reaching the server's own layers (ls.pc.* facade etc.) while the
#     compiler internals stay unreached and the LS logs "PC is disabled".
#   * POSITIVE (BSP-backed, run only when LS_BSP_WORKSPACE is a BSP-installed workspace): the LS
#     establishes BSP and the run must reach dotty.tools.*/scala.meta.*. Prepare the workspace with
#     setup-bsp-workspace.sh first.
#
# Requires the built LS jar (see docs/jvm-target.md):
#   LS_JAR=<.../scala3-bsp-semantic-ls.jar> [LS_SQLITE_LIB=<libsqlite3.so>] \
#   [LS_BSP_WORKSPACE=<dir>] nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/run-real-ls.sh
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
agent="$here/agent.jar" # absolute: the LS may run with a different cwd (BSP workspace root)
flags=(-javaagent:"$agent" -XX:-UseCompactObjectHeaders -Xshare:off -XX:+UseSerialGC --enable-native-access=ALL-UNNAMED)
java="$JAVA_HOME/bin/java"

# run_epoch <n> <cwd> <rootUri> <docUri> <docText> [extra LS args...]
run_epoch() {
  local n="$1" cwd="$2" rootUri="$3" docUri="$4" docText="$5"; shift 5
  local dir ctl; dir=$(mktemp -d); ctl="$dir/ctl"; mkfifo "$ctl"
  ( cd "$cwd" && COV_MAP_PATH="$here/ls-map-$n.bin" COV_CLASSES_PATH="$here/ls-classes-$n.txt" \
      "$java" "${flags[@]}" -jar "$LS_JAR" "$@" < "$ctl" > "$here/ls-out-$n.log" 2>&1 ) &
  local lspid=$!
  exec 3>"$ctl"
  send() { printf 'Content-Length: %d\r\n\r\n%s' "${#1}" "$1" >&3; }
  send "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"processId\":null,\"rootUri\":$rootUri,\"capabilities\":{}}}"
  send '{"jsonrpc":"2.0","method":"initialized","params":{}}'
  send "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/didOpen\",\"params\":{\"textDocument\":{\"uri\":\"$docUri\",\"languageId\":\"scala\",\"version\":1,\"text\":\"$docText\"}}}"
  send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"textDocument/completion\",\"params\":{\"textDocument\":{\"uri\":\"$docUri\"},\"position\":{\"line\":2,\"character\":11}}}"
  sleep "${LS_SESSION_SLEEP:-35}"
  send '{"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}'
  send '{"jsonrpc":"2.0","method":"exit","params":null}'
  exec 3>&-
  ( sleep 45; kill "$lspid" 2>/dev/null ) & local guard=$!
  wait "$lspid" 2>/dev/null || true
  kill "$guard" 2>/dev/null || true
  rm -rf "$dir"
}

edges() { cmp -l "$1" zero.bin 2>/dev/null | wc -l; }

fail=0
# --- Negative / control gate (no BSP) ---
ctrl_text='object Demo:\n  def add(a: Int, b: Int): Int = a + b\n  val y = ad\n'
run_epoch 1 "$here" null "file:///tmp/Demo.scala" "$ctrl_text"
run_epoch 2 "$here" null "file:///tmp/Demo.scala" "$ctrl_text"
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
  ws="$LS_BSP_WORKSPACE"
  doc="file://$ws/app/src/Foo.scala"
  pos_text='object Foo:\n  def greet(name: String): String = "hi " + name\n  val z = gre\n'
  LS_SESSION_SLEEP="${LS_SESSION_SLEEP:-90}"
  run_epoch 3 "$ws" "\"file://$ws\"" "$doc" "$pos_text"
  run_epoch 4 "$ws" "\"file://$ws\"" "$doc" "$pos_text"
  bsp_ok=$(grep -c 'BSP server started' ls-out-3.log || true)
  c3=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-3.txt 2>/dev/null || true)
  cmp -s ls-classes-3.txt ls-classes-4.txt && pset=identical || pset=DIFFERED
  if [ "${c3:-0}" -gt 0 ] && [ "$pset" = identical ] && ! cmp -s ls-map-3.bin zero.bin; then
    echo "OK (positive): BSP-backed run reaches compiler/scalameta ($c3 classes, class set $pset)"
  else
    echo "FAIL (positive): BSP connected=$bsp_ok but compiler reach=$c3 (set=$pset). PC completion returned no results; needs compile-readiness before completion (see docs)."; fail=1
  fi
else
  echo "SKIP (positive): set LS_BSP_WORKSPACE (prepared with setup-bsp-workspace.sh) to require dotty.tools/scala.meta coverage"
fi
exit $fail
