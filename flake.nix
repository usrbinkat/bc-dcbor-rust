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
    # Kani, the model checker the proof harnesses run under (`cargo kani`,
    # tests/gate/src/proofs.rs): the flake of model-checking/kani#5098, open
    # upstream, pinned by revision. Its `kani` is the published release bundle
    # fetched by hash, linked to its own rust-overlay toolchain.
    kani = {
      url = "github:lalvesl/kani/c0eb2af3ac4279ef51512d9a16a2d1b0d78c7186";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      rust-fork,
      kani,
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
            ${pkgs.lib.getExe pkgs.patch} --batch --fuzz=0 -d $out/lib/rustlib/src/rust -p1 < ${treePatch}
          '';
          toolchain =
            (nightly.default.override {
              # miri: tests/miri-owned.sh runs on this toolchain, its
              # sysroot built from the forked library below.
              # llvm-tools: llvm-cov and llvm-profdata of the compiler's own
              # LLVM, which read the coverage the reach map records
              # (tests/reach-map.sh); cargo-llvm-cov finds them in the sysroot.
              extensions = [
                "rust-analyzer"
                "clippy"
                "rustfmt"
                "miri"
                "llvm-tools"
              ];
            }).overrideAttrs
              (old: {
                paths = old.paths ++ [ "${forkedRustSrc}" ];
              });
          target = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          # The profile runtime of instrumented test binaries, built with the
          # forked std (`profiler_builtins`), from the compiler-rt of the
          # compiler's own LLVM: the `src/llvm-project` the compiler's commit
          # (db8f076, LLVM 23.1.1) pins, so the raw profiles it writes are the
          # format that compiler's llvm-profdata reads.
          compilerRtProfile = pkgs.fetchgit {
            url = "https://github.com/rust-lang/llvm-project";
            rev = "1b9c0d5ff9bbe7634aead059efe6b11a7eeba145";
            sparseCheckout = [
              "compiler-rt/lib/profile"
              "compiler-rt/include"
            ];
            hash = "sha256-3rr7K4bnJ3XVO8E25QNBga60v3AMbAoT4Pc3fBipikk=";
          };
          # cargo-mutants from upstream main (6c720ae: struct-field deletions
          # honour --re and --exclude-re, #634) with --mutate-unsafe, which
          # generates mutants inside `unsafe fn` bodies
          # (nix/cargo-mutants-mutate-unsafe.patch).
          cargoMutants = pkgs.cargo-mutants.overrideAttrs (
            old:
            let
              src = pkgs.fetchFromGitHub {
                owner = "sourcefrog";
                repo = "cargo-mutants";
                rev = "6c720ae82a1784b84cfa06066f7b0d59ed1798d0";
                hash = "sha256-QOUnMNkEfFpsfmtwH7kh7Tce5HA3QjjOPMVdND5BqS0=";
              };
            in
            {
              version = "27.1.0-unstable-2026-10-19";
              inherit src;
              patches = (old.patches or [ ]) ++ [ ./nix/cargo-mutants-mutate-unsafe.patch ];
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                inherit src;
                hash = "sha256-1r4p2toNnOcZqUULEdOUSMiz3NUHGyNMPe2uLoUPaME=";
              };
              # nixpkgs disables the checks because its integration tests
              # (tests/) need the network. The unit tests of the binary run
              # offline and hold the patch's own (options::mutate_unsafe_*,
              # visit::mutate_unsafe_fn_when_enabled), so the build runs them.
              doCheck = true;
              cargoTestFlags = [
                "--bin"
                "cargo-mutants"
              ];
            }
          );
          # cargo-llvm-cov built and tested with this shell's own toolchain.
          # Its tests instrument fixture crates and read their profiles: with
          # nixpkgs' rustc (codegen LLVM 21, a profile runtime writing raw
          # format 11) and nixpkgs' LLVM 22 tools (reading format 10) the
          # fixtures crash and their profiles are refused. The nightly's
          # profile runtime, llvm-cov and llvm-profdata are one LLVM's (23.1,
          # the llvm-tools component), the set the reach map uses.
          nightlyRustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          llvmTools = "${toolchain}/lib/rustlib/${target}/bin";
          cargoLlvmCov =
            (pkgs.cargo-llvm-cov.override { rustPlatform = nightlyRustPlatform; }).overrideAttrs
              (_old: {
                # Replace the package's LLVM environment without evaluating
                # its rustc.llvmPackages lookup: rust-overlay supplies these
                # tools as a sysroot component instead of that passthru.
                env = {
                  LLVM_COV = "${llvmTools}/llvm-cov";
                  LLVM_PROFDATA = "${llvmTools}/llvm-profdata";
                };
              });
          # Hardware counters (cycles, instructions, branch-misses, cache and
          # TLB misses) for the bounded-scan and encoding benchmarks; perf is
          # Linux-only, so darwin shells omit it.
          profiling = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.perf ];
          # A real executable also works with `nix develop --command cargo`.
          # External subcommands must receive build flags themselves: Cargo's
          # leading --config arguments are not forwarded by cargo-clippy.
          toolchainCargo = pkgs.lib.getExe' toolchain "cargo";
          # DCBOR_PROFILER=1 builds the profile runtime with the forked std,
          # for instrumented test binaries (tests/reach-map.sh); unset, the
          # standard set. Any other value is refused, never ignored.
          cargo = pkgs.writeShellApplication {
            name = "cargo";
            text = ''
              case "''${DCBOR_PROFILER:-}" in
              "")
                crates=std,panic_abort
                ;;
              1)
                crates=std,panic_abort,profiler_builtins
                ;;
              *)
                printf 'DCBOR_PROFILER=%s: set it to 1 to build the profile runtime, or unset it\n' \
                  "$DCBOR_PROFILER" >&2
                exit 2
                ;;
              esac
              # Cargo looks up an external subcommand (cargo-clippy,
              # cargo-miri, cargo-fmt) in its home's bin before PATH unless
              # that directory is already on PATH (cargo's
              # search_directories, rust-lang/cargo#11020); a rustup proxy
              # there runs another toolchain's clippy against this shell's
              # sysroot. Listed last, the toolchain's own come first. The
              # home is cargo's: CARGO_HOME, relative to the working
              # directory, else ~/.cargo.
              home="''${CARGO_HOME:-$HOME/.cargo}"
              case "$home" in
              /*) ;;
              *) home="$PWD/$home" ;;
              esac
              export PATH="$PATH:$home/bin"
              if [ "''${1:-}" = miri ]; then
                shift
                exec ${toolchainCargo} miri "$@"
              fi
              if [ "''${1:-}" = clippy ]; then
                shift
                exec ${toolchainCargo} clippy \
                  "-Zbuild-std=$crates" --target ${target} "$@"
              fi
              exec ${toolchainCargo} \
                --config "unstable.build-std=[\"''${crates//,/\",\"}\"]" \
                --config 'build.target="${target}"' "$@"
            '';
          };
          # What maintaining the project runs besides the toolchain: the
          # proof harnesses (Kani, on its own pinned toolchain), the
          # mutation campaign, the reach map's coverage (cargo-llvm-cov), the
          # Miri gate's per-test memory and duration (GNU time), the fuzz
          # campaign (fuzz/qualify.sh, fuzz/smoke.sh), and the check of the
          # gate scripts, which launch the gate tool (tests/gate), built by
          # the toolchain itself.
          maintenance = [
            kani.packages.${system}.kani
            cargoMutants
            cargoLlvmCov
            pkgs.cargo-fuzz
            pkgs.shellcheck
            pkgs.time
          ];
          customShell = pkgs.mkShell {
            nativeBuildInputs = [
              cargo
              toolchain
              pkgs.pkg-config
              pkgs.cmake
            ]
            ++ maintenance
            ++ profiling;
            RUSTC = pkgs.lib.getExe' toolchain "rustc";
            RUSTDOC = pkgs.lib.getExe' toolchain "rustdoc";
            RUSTFMT = pkgs.lib.getExe' toolchain "rustfmt";
            # profiler_builtins' build script compiles the profile runtime from
            # this compiler-rt (library/profiler_builtins/build.rs).
            RUST_COMPILER_RT_FOR_PROFILER = "${compilerRtProfile}/compiler-rt";
            # The configuration every recorded trace and tightness record
            # names: the toolchain and the standard library it builds against.
            DCBOR_CONFIGURATION = "rust-nightly-${nightlyDate} ${target} library usrbinkat/rust@${rust-fork.rev} btree-patch-sha256:${builtins.hashFile "sha256" treePatch} ${dependencyIdentity}";
            # The wrapper precedes the toolchain's own cargo; nothing outside
            # the shell is put on the path.
            shellHook = ''
              export PATH="${cargo}/bin:${toolchain}/bin:$PATH"
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
            ]
            ++ maintenance
            ++ profiling;
            RUSTC = pkgs.lib.getExe' stable "rustc";
            RUSTDOC = pkgs.lib.getExe' stable "rustdoc";
            RUSTFMT = pkgs.lib.getExe' stable "rustfmt";
            DCBOR_CONFIGURATION = "rust-${stableVersion} ${target} library rust-src-${stableVersion} ${dependencyIdentity}";
            # The toolchain first; nothing outside the shell is put on the
            # path.
            shellHook = ''
              export PATH="${stable}/bin:$PATH"
            '';
          };
        }
      );
    };
}
