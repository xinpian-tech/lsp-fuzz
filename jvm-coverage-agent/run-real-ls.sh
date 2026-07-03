#!/usr/bin/env bash
# Attach the coverage agent to the real scala3-bsp-smantic-ls jar and measure coverage reach by
# driving an LSP initialize/didOpen/completion/shutdown session over stdio.
#
# This LS disables the presentation compiler without a BSP connection, so there are two gates:
#   * NEGATIVE/CONTROL (no BSP, always run): confirms the agent attaches and produces a non-empty,
#     deterministic map reaching the server's own layers (ls.pc.* facade etc.) while the compiler
#     internals (dotty.tools.*/scala.meta.*) stay unreached and the LS logs "PC is disabled".
#   * POSITIVE (BSP-backed, run only when LS_BSP_WORKSPACE is set): requires dotty.tools.*/
#     scala.meta.* classes to actually execute. Pending the frozen zaozi BSP/SemanticDB backdrop.
#
# Requires the built LS jar (see docs/jvm-target.md: `nix build .#default` in the target repo):
#   LS_JAR=<.../scala3-bsp-semantic-ls.jar> [LS_SQLITE_LIB=<libsqlite3.so>] \
#   [LS_BSP_WORKSPACE=<dir>] nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/run-real-ls.sh
set -euo pipefail

cd "$(dirname "$0")"
: "${LS_JAR:?set LS_JAR to the built scala3-bsp-semantic-ls.jar}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"
[ -n "${LS_SQLITE_LIB:-}" ] && export LS_SQLITE_LIB

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
flags=(-javaagent:agent.jar -XX:-UseCompactObjectHeaders -Xshare:off -XX:+UseSerialGC --enable-native-access=ALL-UNNAMED)
java="${JAVA_HOME:+$JAVA_HOME/bin/}java"
uri="file:///tmp/Demo.scala"
text='object Demo:\n  def add(a: Int, b: Int): Int = a + b\n  val y = ad\n'

# Drive a minimal LSP session over a FIFO so the presentation compiler actually runs before exit.
drive_ls() {
  exec 3>"$1"
  send() { printf 'Content-Length: %d\r\n\r\n%s' "${#1}" "$1" >&3; }
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"processId":null,"rootUri":null,"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"initialized","params":{}}'
  send "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/didOpen\",\"params\":{\"textDocument\":{\"uri\":\"$uri\",\"languageId\":\"scala\",\"version\":1,\"text\":\"$text\"}}}"
  send "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"textDocument/completion\",\"params\":{\"textDocument\":{\"uri\":\"$uri\"},\"position\":{\"line\":2,\"character\":12}}}"
  sleep 35 # let the Scala 3 presentation compiler initialize and answer
  send '{"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}'
  send '{"jsonrpc":"2.0","method":"exit","params":null}'
  exec 3>&-
}

run_epoch() { # $1=epoch-number  $2=optional workspace root arg for the LS
  local n="$1" ; shift
  local dir ctl
  dir=$(mktemp -d); ctl="$dir/ctl"; mkfifo "$ctl"
  COV_MAP_PATH="ls-map-$n.bin" COV_CLASSES_PATH="ls-classes-$n.txt" \
    "$java" "${flags[@]}" -jar "$LS_JAR" "$@" < "$ctl" > "ls-out-$n.log" 2>&1 &
  local lspid=$!
  drive_ls "$ctl"
  ( sleep 30; kill "$lspid" 2>/dev/null ) & local guard=$!
  wait "$lspid" 2>/dev/null || true
  kill "$guard" 2>/dev/null || true
  rm -rf "$dir"
}

fail=0
# --- Negative / control gate (no BSP) ---
run_epoch 1
run_epoch 2
for n in 1 2; do
  if [ ! -s "ls-classes-$n.txt" ] || cmp -s "ls-map-$n.bin" zero.bin; then
    echo "FAIL (control epoch $n): agent produced no/empty coverage"; fail=1
  fi
done
if [ "$fail" -eq 0 ]; then
  edges1=$(cmp -l ls-map-1.bin zero.bin 2>/dev/null | wc -l)
  edges2=$(cmp -l ls-map-2.bin zero.bin 2>/dev/null | wc -l)
  pc=$(grep -cE '^ls\.pc\.' ls-classes-1.txt || true)
  compiler=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-1.txt || true)
  cmp -s ls-classes-1.txt ls-classes-2.txt && cdet="identical" || cdet="DIFFERED"
  # The whole-LS map is only near-deterministic across epochs: the LS is multi-threaded, so
  # background scheduling perturbs a few edges. (Byte-identical per-input maps are guaranteed at
  # the worker level via reset+quiesce; see the fixture harness's 1000-identical-input gate.) So
  # here we require the covered-class set to be identical and the edge counts to match within a
  # small tolerance, not byte identity.
  edge_delta=$(( edges1 > edges2 ? edges1 - edges2 : edges2 - edges1 ))
  if [ "$pc" -gt 0 ] && [ "$compiler" -eq 0 ] && [ "$cdet" = identical ] && [ "$edge_delta" -le 32 ] \
     && [ "$edges1" -gt 0 ] && grep -q 'PC is disabled' ls-out-1.log; then
    echo "OK (control): agent attaches to real LS; non-empty (~$edges1 edges, delta $edge_delta across epochs); covered-class set identical; reaches ls.pc.* ($pc classes); compiler internals unreached ($compiler) with 'PC is disabled' — expected without BSP"
  else
    echo "FAIL (control): expected PC-disabled + non-empty + ls.pc>0 + compiler==0 + identical class set + edge delta<=32 (edges=$edges1/$edges2 delta=$edge_delta pc=$pc compiler=$compiler classes=$cdet)"
    fail=1
  fi
fi

# --- Positive gate (BSP-backed) ---
if [ -n "${LS_BSP_WORKSPACE:-}" ]; then
  run_epoch 3 "$LS_BSP_WORKSPACE"
  compiler=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' ls-classes-3.txt 2>/dev/null || true)
  if [ "${compiler:-0}" -gt 0 ] && ! cmp -s ls-map-3.bin zero.bin; then
    echo "OK (positive): BSP-backed run reaches compiler/scalameta ($compiler classes)"
  else
    echo "FAIL (positive): BSP-backed run did not reach dotty.tools/scala.meta ($compiler)"
    fail=1
  fi
else
  echo "SKIP (positive): set LS_BSP_WORKSPACE to a BSP-backed workspace to require dotty.tools/scala.meta coverage (pending the frozen zaozi BSP/SemanticDB backdrop)"
fi
exit $fail
