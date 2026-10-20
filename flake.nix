{
  description = "dCBOR development with bounded-collection standard library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-fork = {
      url = "github:usrbinkat/rust/feat/bounded-collection-access";
      flake = false;
    };
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      rust-fork,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          # Matches the fork's db8f076 compiler base, as in kappa-registry.
          nightly = pkgs.rust-bin.nightly."2026-10-04";
          forkedRustSrc = pkgs.runCommand "dcbor-rust-src-bounded-collections" { } ''
            cp -R --no-preserve=mode,ownership ${nightly.rust-src} $out
            cp -R --no-preserve=mode,ownership ${rust-fork}/library/. \
              $out/lib/rustlib/src/rust/library/
          '';
          toolchain =
            (nightly.default.override {
              extensions = [
                "rust-analyzer"
                "clippy"
                "rustfmt"
              ];
            }).overrideAttrs
              (old: {
                paths = old.paths ++ [ "${forkedRustSrc}" ];
              });
          target = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          # A real executable also works with `nix develop --command cargo`.
          # External subcommands must receive build flags themselves: Cargo's
          # leading --config arguments are not forwarded by cargo-clippy.
          cargo = pkgs.writeShellScriptBin "cargo" ''
            if [ "''${1:-}" = clippy ]; then
              shift
              exec ${toolchain}/bin/cargo clippy \
                -Zbuild-std=std,panic_abort --target ${target} "$@"
            fi
            exec ${toolchain}/bin/cargo \
              --config 'unstable.build-std=["std","panic_abort"]' \
              --config 'build.target="${target}"' "$@"
          '';
          customShell = pkgs.mkShell {
            nativeBuildInputs = [
              cargo
              toolchain
              pkgs.pkg-config
              pkgs.cmake
            ];
            RUSTC = "${toolchain}/bin/rustc";
            RUSTDOC = "${toolchain}/bin/rustdoc";
            RUSTFMT = "${toolchain}/bin/rustfmt";
            shellHook = ''
              export PATH="${cargo}/bin:${toolchain}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
          };
          stable = pkgs.rust-bin.stable."1.98.1".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };
        in
        {
          default = customShell;
          custom-std = customShell;
          stable = pkgs.mkShell {
            nativeBuildInputs = [
              stable
              pkgs.pkg-config
              pkgs.cmake
            ];
            RUSTC = "${stable}/bin/rustc";
            RUSTDOC = "${stable}/bin/rustdoc";
            RUSTFMT = "${stable}/bin/rustfmt";
            shellHook = ''
              export PATH="${stable}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
          };
        }
      );
    };
}
