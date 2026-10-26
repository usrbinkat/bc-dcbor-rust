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
          # Matches the fork's db8f076 compiler base.
          nightlyDate = "2026-10-04";
          nightly = pkgs.rust-bin.nightly.${nightlyDate};
          stableVersion = "1.98.1";
          # Read the dependency pin itself so configuration evidence cannot
          # silently name a different fork from the one Cargo builds.
          hashbrownRevision = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).dependencies.hashbrown.rev;
          treePatch = ./nix/btree-in-place.patch;
          dependencyIdentity = "hashbrown@${hashbrownRevision} rust-overlay@${rust-overlay.rev} nixpkgs@${nixpkgs.rev}";
          forkedRustSrc = pkgs.runCommand "dcbor-rust-src-bounded-collections" { } ''
            cp -R --no-preserve=mode,ownership ${nightly.rust-src} $out
            cp -R --no-preserve=mode,ownership ${rust-fork}/library/. \
              $out/lib/rustlib/src/rust/library/
            ${pkgs.patch}/bin/patch --batch --fuzz=0 -d $out/lib/rustlib/src/rust -p1 < ${treePatch}
          '';
          toolchain =
            (nightly.default.override {
              # miri: tests/miri-owned.sh runs on this toolchain, its
              # sysroot built from the forked library below.
              extensions = [
                "rust-analyzer"
                "clippy"
                "rustfmt"
                "miri"
              ];
            }).overrideAttrs
              (old: {
                paths = old.paths ++ [ "${forkedRustSrc}" ];
              });
          target = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          # Hardware counters (cycles, instructions, branch-misses, cache and
          # TLB misses) for the bounded-scan and encoding benchmarks; perf is
          # Linux-only, so darwin shells omit it.
          profiling = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.perf ];
          # A real executable also works with `nix develop --command cargo`.
          # External subcommands must receive build flags themselves: Cargo's
          # leading --config arguments are not forwarded by cargo-clippy.
          cargo = pkgs.writeShellScriptBin "cargo" ''
            if [ "''${1:-}" = miri ]; then
              shift
              exec ${toolchain}/bin/cargo miri "$@"
            fi
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
              pkgs.cargo-mutants
              pkgs.python3
            ]
            ++ profiling;
            RUSTC = "${toolchain}/bin/rustc";
            RUSTDOC = "${toolchain}/bin/rustdoc";
            RUSTFMT = "${toolchain}/bin/rustfmt";
            # The configuration every recorded trace and tightness record
            # names: the toolchain and the standard library it builds against.
            DCBOR_CONFIGURATION = "rust-nightly-${nightlyDate} ${target} library usrbinkat/rust@${rust-fork.rev} btree-patch-sha256:${builtins.hashFile "sha256" treePatch} ${dependencyIdentity}";
            shellHook = ''
              export PATH="${cargo}/bin:${toolchain}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
          };
          stable = pkgs.rust-bin.stable.${stableVersion}.default.override {
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
              pkgs.cargo-mutants
              pkgs.python3
            ]
            ++ profiling;
            RUSTC = "${stable}/bin/rustc";
            RUSTDOC = "${stable}/bin/rustdoc";
            RUSTFMT = "${stable}/bin/rustfmt";
            DCBOR_CONFIGURATION = "rust-${stableVersion} ${target} library rust-src-${stableVersion} ${dependencyIdentity}";
            shellHook = ''
              export PATH="${stable}/bin:$PATH:''${CARGO_HOME:-$HOME/.cargo}/bin"
            '';
          };
        }
      );
    };
}
