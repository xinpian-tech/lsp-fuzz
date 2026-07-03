# SPDX-License-Identifier: Apache-2.0
{
  description = "LSPFuzz: a grey-box hybrid fuzzer for Language Server Protocol servers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    let
      overlay = import ./nix/overlay.nix;
    in
    {
      # System-independent attrs
      inherit inputs;
      overlays.default = overlay;
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          overlays = [ overlay ];
          inherit system;
        };
      in
      {
        formatter = pkgs.nixpkgs-fmt;
        legacyPackages = pkgs;
        packages = {
          default = pkgs.lsp-fuzz;
          lsp-fuzz = pkgs.lsp-fuzz;
        };
        devShells.default = pkgs.mkShell {
          # Rust toolchain (rust-toolchain.toml pins stable + rustfmt + clippy)
          # plus a C/C++ compiler for the tree-sitter grammar build scripts.
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            pkg-config
            typos
            nixd
          ];
          env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };

        # Toolchain for the JVM fuzz target (scala3-bsp-smantic-ls): JDK 25 +
        # Mill + SQLite. The target itself is built from its own flake
        # (`nix build` in that repo), which pins Mill 1.1.2 and its ivy lock;
        # this shell provides the runtime + agent-development tools around it.
        # See docs/jvm-target.md.
        devShells.jvm = pkgs.mkShell {
          packages = with pkgs; [
            jdk25
            mill
            sqlite
          ];
          env.JAVA_HOME = "${pkgs.jdk25}";
        };
      }
    );
}
