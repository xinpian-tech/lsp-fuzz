#!/usr/bin/env bash
# Create a minimal BSP-backed Scala 3 workspace so the real LS establishes a BSP connection and
# enables the presentation compiler (without BSP the LS logs "PC is disabled"). Uses a tiny Mill
# project + `mill mill.bsp.BSP/install` to write `.bsp/mill-bsp.json`.
#
# Usage (inside the JVM dev shell):
#   nix develop /path/to/lsp-fuzz#jvm -c ./jvm-coverage-agent/setup-bsp-workspace.sh <dir>
# then pass <dir> as LS_BSP_WORKSPACE to run-real-ls.sh.
set -euo pipefail

WS="${1:?usage: setup-bsp-workspace.sh <workspace-dir>}"
mkdir -p "$WS/app/src"
cat > "$WS/build.mill" <<'EOF'
//| mill-version: 1.1.2
//| mill-jvm-version: system
package build
import mill.*
import mill.scalalib.*
object app extends ScalaModule {
  def scalaVersion = "3.3.4"
  // The current LS requires every source to be compiled with `-Xsemanticdb`; without it the server
  // rejects requests ("has no SemanticDB output") and the compile is "skipped: no indexable targets",
  // so the presentation compiler never engages. Emitting SemanticDB makes the BSP compile indexable
  // and lets the PC serve completion/hover, reaching `dotty.tools.pc.*`.
  def scalacOptions = Seq("-Xsemanticdb")
}
EOF
cat > "$WS/app/src/Foo.scala" <<'EOF'
object Foo:
  def greet(name: String): String = "hi " + name
  val n: Int = greet("x").length
EOF

export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
( cd "$WS" && mill mill.bsp.BSP/install )
echo "BSP connection file:"; cat "$WS"/.bsp/*.json
