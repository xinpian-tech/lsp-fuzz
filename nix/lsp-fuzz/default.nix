# SPDX-License-Identifier: Apache-2.0
{
  lib,
  rustPlatform,
  pkg-config,
  stdenv,
}:

rustPlatform.buildRustPackage {
  pname = "lsp-fuzz";
  version = "0.1.0";

  src =
    with lib.fileset;
    toSource {
      root = ./../..;
      fileset = unions [
        ./../../Cargo.toml
        ./../../Cargo.lock
        ./../../rust-toolchain.toml
        ./../../crates
      ];
    };

  cargoLock = {
    lockFile = ./../../Cargo.lock;
    # Git dependencies are not in the vendored registry, so their source trees
    # must be pinned by output hash. Refresh with `nix-prefetch-git` when a
    # revision in Cargo.lock changes.
    outputHashes = {
      "lsp-types-0.97.0" = "sha256-Qt1RWG3H7wJfP8gP4LdZhI+QcqbLvwEWjOwNf9bxkLI=";
      "tree-sitter-bibtex-0.0.1" = "sha256-t86X70TXmN6CMjkIgJNMb+5ucYM9T1uBw3zc/pfqZdw=";
      "tree-sitter-latex-0.3.0" = "sha256-PGM+qcol2pdVXUGBjlHWCRyG8JpR1zoV/NyWUpNFPf4=";
      "tree-sitter-mlir-0.0.1" = "sha256-rXkidLfjVULaTmvvNZ+YGpLff5oQ0PbFklYRqZbG0f4=";
      "tree-sitter-qmljs-0.2.0" = "sha256-i11qrsYDIqL+zVdL+JMPovymrrqR8H/3fHe5lgBgWSU=";
    };
  };

  nativeBuildInputs = [ pkg-config ];

  # The workspace tests exercise a running LSP target binary and absolute
  # toolchain paths that are unavailable in the sandbox; run them in the dev
  # shell instead of the package build.
  doCheck = false;

  meta = {
    description = "Grey-box hybrid fuzzer for Language Server Protocol servers";
    mainProgram = "lsp-fuzz-cli";
  };
}
