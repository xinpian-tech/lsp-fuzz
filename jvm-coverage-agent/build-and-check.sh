#!/usr/bin/env bash
# Build the ASM bytecode-coverage agent + persistent worker + fixture, then run the harness
# which asserts: saturating counters, non-empty/deterministic/input-sensitive basic-block coverage,
# a 1000-identical-input stability gate, outcome classification (normal/crash/hang-timeout+restart),
# and cold replay from a fresh JVM. See docs/jvm-coverage-agent.md.
#
# Run inside the JVM dev shell:  nix develop .#jvm -c ./jvm-coverage-agent/build-and-check.sh
set -euo pipefail

cd "$(dirname "$0")"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.jvm-cache}"

ASM_JAR=$(nix shell nixpkgs#coursier -c cs fetch org.ow2.asm:asm:9.8 2>/dev/null | grep 'asm-9.8.jar' | head -1)
echo "ASM: $ASM_JAR"

rm -rf out agentjar agent.jar map-latest.bin
mkdir -p out agentjar

# shellcheck disable=SC2046
javac -cp "$ASM_JAR" -d out $(find src -name '*.java')

# Self-contained agent jar: cov agent classes + bundled ASM + Premain-Class manifest.
cp -r out/cov agentjar/
( cd agentjar && jar xf "$ASM_JAR" org )
mkdir -p agentjar/META-INF
printf 'Premain-Class: cov.CoverageAgent\nCan-Retransform-Classes: true\n' > agentjar/META-INF/MANIFEST.MF
( cd agentjar && jar cfm ../agent.jar META-INF/MANIFEST.MF cov org )

# The harness spawns agent-instrumented worker JVMs and asserts every coverage gate.
java -cp out cov.Harness
