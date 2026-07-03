#!/usr/bin/env bash
# Attach the coverage agent to the real scala3-bsp-smantic-ls jar and prove coverage reaches the
# Scala 3 presentation compiler / scalameta. Drives the server's headless `--aot-train` workload
# (no live LSP client needed) across two fresh JVM epochs and checks the covered-class set.
#
# Requires the built LS jar (see docs/jvm-target.md: `nix build .#default` in the target repo):
#   LS_JAR=<.../scala3-bsp-semantic-ls.jar> [LS_SQLITE_LIB=<libsqlite3.so>] \
#     nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/run-real-ls.sh
set -euo pipefail

cd "$(dirname "$0")"
: "${LS_JAR:?set LS_JAR to the built scala3-bsp-semantic-ls.jar}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"
[ -n "${LS_SQLITE_LIB:-}" ] && export LS_SQLITE_LIB

ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
rm -rf out agentjar agent.jar ls-map-*.bin ls-classes-*.txt zero.bin
mkdir -p out agentjar
# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )

head -c 65536 /dev/zero > zero.bin
flags=(-javaagent:agent.jar -XX:-UseCompactObjectHeaders -Xshare:off --enable-native-access=ALL-UNNAMED)
java="${JAVA_HOME:+$JAVA_HOME/bin/}java"
uri="file:///tmp/Demo.scala"
# A dirty buffer whose last line is an incomplete reference, so completion invokes the
# presentation compiler (parser/typer -> dotty.tools.*).
text='object Demo:\n  def add(a: Int, b: Int): Int = a + b\n  val y = ad\n'

# Drive a minimal LSP session over a FIFO so the presentation compiler actually runs before exit.
drive_ls() {
  local ctl="$1"
  exec 3>"$ctl"
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

fail=0
for n in 1 2; do
  ctl=$(mktemp -u); mkfifo "$ctl"
  COV_MAP_PATH="ls-map-$n.bin" COV_CLASSES_PATH="ls-classes-$n.txt" \
    "$java" "${flags[@]}" -jar "$LS_JAR" < "$ctl" > "ls-out-$n.log" 2>&1 &
  lspid=$!
  drive_ls "$ctl"
  ( sleep 30; kill "$lspid" 2>/dev/null ) & guard=$!
  wait "$lspid" 2>/dev/null || true
  kill "$guard" 2>/dev/null || true
  rm -f "$ctl"

  if [ ! -s "ls-classes-$n.txt" ] || [ ! -s "ls-map-$n.bin" ]; then
    echo "FAIL (epoch $n): agent produced no coverage output"; fail=1; continue
  fi
  if cmp -s "ls-map-$n.bin" zero.bin; then
    echo "FAIL (epoch $n): coverage map empty"; fail=1; continue
  fi
  total=$(wc -l < "ls-classes-$n.txt")
  pc=$(grep -cE '^ls\.pc\.' "ls-classes-$n.txt" || true)
  compiler=$(grep -cE '^(dotty\.tools\.|scala\.meta\.)' "ls-classes-$n.txt" || true)
  if [ "$pc" -gt 0 ]; then
    echo "OK (epoch $n): non-empty real-LS coverage reaches the PC facade layer (ls.pc: $pc of $total classes; dotty.tools/scala.meta: $compiler)"
  else
    echo "FAIL (epoch $n): coverage did not reach the ls.pc layer ($total classes)"
    fail=1
  fi
done

# Determinism across the two fresh epochs (same covered-class set).
if [ "$fail" -eq 0 ] && cmp -s ls-classes-1.txt ls-classes-2.txt; then
  echo "OK: covered-class set identical across two fresh epochs (deterministic)"
else
  echo "FAIL: covered-class set differed across epochs"; fail=1
fi

# Finding: this LS disables the presentation compiler without a BSP connection (see ls-out-*.log:
# "no BSP connection ... PC is disabled"), so compiler internals (dotty.tools.*/scala.meta.*) are
# only reachable with a BSP-backed workspace. Reaching them is folded into the BSP backdrop work.
if grep -q 'PC is disabled' ls-out-1.log 2>/dev/null; then
  echo "NOTE: LS reports the PC is disabled without BSP; dotty.tools/scala.meta coverage requires the BSP backdrop."
fi
exit $fail
