#!/usr/bin/env bash
# Build the minimal ASM bytecode-coverage agent + trivial fixture and prove the coverage map is
# non-empty, deterministic (identical input -> identical map), and input-sensitive.
#
# Run inside the JVM dev shell:  nix develop .#jvm -c ./jvm-coverage-agent/build-and-check.sh
# (JDK 25 + Mill from the flake; ASM 9.8 is fetched via nixpkgs coursier.)
#
# This is the task5 first increment for the JVM coverage bridge (docs/jvm-coverage-agent.md).
# Later rounds widen the instrumentation scope and read the map from shared memory per iteration.
set -euo pipefail

cd "$(dirname "$0")"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"

ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
echo "ASM: $ASM_JAR"

rm -rf out agentjar agent.jar map*.bin zero.bin in1 in1b in2
mkdir -p out agentjar

# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')

# Assemble a self-contained agent jar (cov classes + bundled ASM).
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )

head -c 65536 /dev/zero > zero.bin
# Distinct lengths -> distinct code paths in the fixture (len%3): in1/in1b len 3 (pathA),
# in2 len 1 (pathB), so their coverage maps must differ.
printf 'abc' > in1
printf 'abc' > in1b
printf 'z'   > in2

FLAGS="-XX:-UseCompactObjectHeaders -Xshare:off -XX:+UseSerialGC --enable-native-access=ALL-UNNAMED"
COV_MAP_PATH=map1.bin  java $FLAGS -javaagent:agent.jar -cp out target.Target < in1
COV_MAP_PATH=map1b.bin java $FLAGS -javaagent:agent.jar -cp out target.Target < in1b
COV_MAP_PATH=map2.bin  java $FLAGS -javaagent:agent.jar -cp out target.Target < in2

fail=0
if cmp -s map1.bin zero.bin; then echo "FAIL: coverage map is empty"; fail=1; else
  echo "OK: non-empty map ($(cmp -l map1.bin zero.bin | wc -l) non-zero bytes)"; fi
if cmp -s map1.bin map1b.bin; then echo "OK: deterministic (identical input -> identical map)"; else
  echo "FAIL: identical input produced different maps"; fail=1; fi
if cmp -s map1.bin map2.bin; then echo "FAIL: different input produced identical map"; fail=1; else
  echo "OK: input-sensitive (different input -> different map)"; fi
exit $fail
