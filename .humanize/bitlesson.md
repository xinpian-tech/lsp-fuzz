# BitLesson Knowledge Base

This file is project-specific. Keep entries precise and reusable for future rounds.

## Entry Template (Strict)

Use this exact field order for every entry:

```markdown
## Lesson: <unique-id>
Lesson ID: <BL-YYYYMMDD-short-name>
Scope: <component/subsystem/files>
Problem Description: <specific failure mode with trigger conditions>
Root Cause: <direct technical cause>
Solution: <exact fix that resolved the problem>
Constraints: <limits, assumptions, non-goals>
Validation Evidence: <tests/commands/logs/PR evidence>
Source Rounds: <round numbers where problem appeared and was solved>
```

## Entries

## Lesson: nix-develop-compile-cache
Lesson ID: BL-20260703-nix-develop-compile-cache
Scope: build/dev workflow — Nix flake (flake.nix, nix/lsp-fuzz/default.nix), cargo, working-tree target/ cache
Problem Description: Iterating on Rust changes by repeatedly running `nix build .#lsp-fuzz` recompiles the whole workspace (LibAFL, tree-sitter, etc.) from scratch every time (~6 min per run), because each build runs in a fresh sandbox with no incremental cargo cache. This wastes minutes per edit during development.
Root Cause: `nix build` vendors deps and full-compiles in an isolated sandbox; it never reuses an incremental cargo `target/`. The base machine also has no cargo/rustc/java on PATH, so ad-hoc `cargo` is not available outside the flake.
Solution: Do development inside the flake dev shell — run `nix develop` (or `nix develop -c cargo <cmd>`) so cargo builds against the persistent working-tree `target/`, giving incremental compilation cache (e.g. re-running tests compiled in ~37s vs ~6 min for a full `nix build`). Reserve `nix build` only for final reproducible packaging / release verification, not for the edit-compile-test loop.
Constraints: Only git-tracked files are visible to `nix build` (flake source = git tree), so newly created files (e.g. res/grammar/scala.json) must be `git add`-ed before `nix build` sees them; the dev shell's cargo, by contrast, sees the live working tree including untracked files. New crates.io deps enter Cargo.lock with a checksum (no flake change); new git deps need an `outputHashes` entry in nix/lsp-fuzz/default.nix.
Validation Evidence: M1 (Scala grammar) — `nix develop -c cargo test -p lsp-fuzz grammar::tests` compiled incrementally in 37.45s and passed capture_scala + load_all_derivation_grammars; a full `nix build .#lsp-fuzz` took ~6m07s. A `nix build` also failed first with `include_str!` unable to find an untracked scala.json until it was `git add`-ed.
Source Rounds: pre-RLCR M1 bring-up (rlcr.md plan)
