# Building and launching the Scala LSP fuzz target

The Scala fuzz target is `scala3-bsp-smantic-ls` (`ls.core.Main`), a JVM stdio language
server (Java 25 + Scala 3.8.4, built with Mill). It has **no** GraalVM native-image path, so
grey-box coverage must come from a JVM bytecode agent (see `docs/scala-lsp-fuzzing-plan.md`,
route "Option B"). This document records how the target is provisioned reproducibly via Nix.

## Toolchain (from this repo)

```bash
nix develop .#jvm    # JDK 25 + Mill + SQLite, JAVA_HOME preset
java -version         # openjdk 25
```

The base machine has no `java`/`mill` on `PATH`; always enter the shell (or the target's own
flake). This mirrors the Rust side, which runs under `nix develop` (default shell) — see the
`BL-20260703-nix-develop-compile-cache` note.

## Building the target LS

The target has its own flake that pins Mill 1.1.2 + its ivy lock; build it there:

```bash
git clone <scala3-bsp-smantic-ls>          # private xinpian-tech repo
cd scala3-bsp-smantic-ls
nix build .#default                         # -> result/bin/scala3-bsp-semantic-ls
./result/bin/scala3-bsp-semantic-ls --version
# scala3-bsp-semantic-ls 0.1.0
```

Verified on this environment: `nix build .#default` compiles the LS with Nix-provided JDK 25,
and the launcher runs `ls.core.Main` (`--version` prints `scala3-bsp-semantic-ls 0.1.0`). This
confirms the "no JVM toolchain" blocker is lifted — the JVM route is buildable here.

## Launch flags relevant to fuzzing

- `--in-process-pc` (default): the presentation compiler runs in this JVM, so a bytecode agent
  can instrument it. Use this for fuzzing (avoid `--forked-pc`).
- The server speaks stdio JSON-RPC via lsp4j `LSPLauncher` (reads `System.in`, writes stdout).

## Next (later rounds)

The JVM coverage bridge (bytecode agent → AFL-shaped map → a new JVM-specific LibAFL executor)
builds on this provisioned target; see `docs/scala-lsp-fuzzing-plan.md` M0/M4/M5.
