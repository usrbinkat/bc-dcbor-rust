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
          # Kani as the proof gate runs it: the flake's release bundle (its
          # compiler and libraries, on the release's own toolchain) with its
          # driver rebuilt from the release's source and
          # nix/kani-driver-loop-bounds.patch, which adds `--loop-bounds`:
          # harness-scoped loop bounds resolved against each harness's
          # instrumented goto binary immediately before CBMC checks it
          # (kani-driver/src/loop_bounds.rs), and its CBMC tools rebuilt from
          # the release's CBMC source with nix/cbmc-value-set-offset-guard.patch
          # (`kaniCbmc`). The overlay's release set is
          # the one the flake's `kani` package is (`kaniReleases.latest`), so
          # the source tag and the toolchain follow the bundle's version.
          # Both patches are maintained as branches of forks and regenerated
          # from them: the Kani patch is `git diff kani-0.68.0..dcbor/loop-bounds
          # -- Cargo.lock kani-driver` of github.com/usrbinkat/kani, the CBMC
          # patch `git diff cbmc-6.11.0..dcbor/value-set-offset-guard -- src
          # unit` of github.com/usrbinkat/cbmc. A release bump rebases both
          # branches onto the new tags.
          kaniPkgs = import nixpkgs {
            inherit system;
            overlays = [ kani.overlays.default ];
          };
          kaniRelease = kaniPkgs.kaniReleases.latest;
          kaniDriverPatch = ./nix/kani-driver-loop-bounds.patch;
          # The release's workspace, with the Charon checkout its
          # kani-compiler member names as a path dependency (the `charon`
          # submodule at the release's pinned revision), so Cargo can load
          # the workspace to build its driver.
          kaniSource = pkgs.runCommand "kani-${kaniRelease.version}-source" { } ''
            cp -R --no-preserve=mode,ownership ${
              pkgs.fetchFromGitHub {
                owner = "model-checking";
                repo = "kani";
                tag = "kani-${kaniRelease.version}";
                hash = "sha256-6BT2BGgrkeZ5yoLj6ra01kECqbGVJfbkoch1ns7HXH0=";
              }
            } $out
            mkdir -p $out/charon
            cp -R --no-preserve=mode,ownership ${
              pkgs.fetchFromGitHub {
                owner = "AeneasVerif";
                repo = "charon";
                rev = "b250680abd40ff1aaa07081d0497dc2755ed112e";
                hash = "sha256-J/of5Bdj3fUFud7XPxVZXNtdUx1rMDiqS8fsptQVfQg=";
              }
            }/. $out/charon/
            # The driver patch, its Cargo.lock change included, applied once
            # here: the crates are vendored from, and the driver built from,
            # this one patched source.
            ${pkgs.lib.getExe pkgs.patch} --batch --fuzz=0 -d $out -p1 < ${kaniDriverPatch}
          '';
          kaniRustPlatform = pkgs.makeRustPlatform {
            cargo = kaniRelease.rust-toolchain;
            rustc = kaniRelease.rust-toolchain;
          };
          kaniDriver = kaniRustPlatform.buildRustPackage {
            pname = "kani-driver";
            inherit (kaniRelease) version;
            src = kaniSource;
            cargoHash = "sha256-pVGpQcCk+r74XUeMOo3ly9PtpY2PKTHGpFo1XFOXKtQ=";
            cargoBuildFlags = [
              "--package"
              "kani-driver"
            ];
            # The driver's unit tests, the patch's own among them
            # (loop_bounds::tests, args::tests::check_loop_bounds_*).
            cargoTestFlags = [
              "--package"
              "kani-driver"
            ];
            # session.rs reads the toolchain's name at compile time
            # (`toolchain_shorthand`); rustup sets it, this build does not.
            env.RUSTUP_TOOLCHAIN = kaniRelease.toolchainChannel;
          };
          # The policies the install check runs the bundle under: POLICY's
          # function scope and harness entries, each empty unless given, and
          # a deadline of each harness of nix/kani-loop-bounds.rs. Each
          # harness's CBMC run takes under a second (a loop of at most three
          # iterations, a formula of a few hundred steps); a minute is the
          # guard of a run gone wrong, not an expectation the check measures.
          kaniPolicy =
            name: policy:
            (pkgs.formats.json { }).generate "kani-loop-bounds-${name}.json" (
              pkgs.lib.recursiveUpdate {
                loops = [ ];
                harnesses = [ ];
                deadlines =
                  map
                    (harness: {
                      inherit harness;
                      milliseconds = 60000;
                      reason = "a loop of at most three iterations, verified in under a second";
                    })
                    [
                      "counts_to_its_limit"
                      "sums_without_a_local_bound"
                    ];
              } policy
            );
          # A policy of one harness entry, bounding LOOPS of HARNESS.
          kaniLoopBounds =
            name: harness: loops:
            kaniPolicy name { harnesses = [ { inherit harness loops; } ]; };
          # sum_to's loop, bounded in the function scope: a property of
          # sum_to under every caller's n <= 3.
          sumTo = {
            function = "sum_to";
            file = "bounds.rs";
            loops_in_function = 1;
            loop = 0;
            bound = 4;
            reason = "sum_to's loop takes its backward goto once per body execution, at most three times under its callers' n <= 3, and CBMC stops at the arrival whose count reaches the bound: bound 4 lets the third backedge reach the exit evaluation, and the unwinding assertion checks no fourth is taken";
          };
          countUp =
            fields:
            pkgs.lib.recursiveUpdate {
              function = "count_up";
              file = "bounds.rs";
              loops_in_function = 1;
              loop = 0;
              bound = 4;
              reason = "count_up's loop takes its backward goto once per body execution, at most three times under the harness's n <= 3, and CBMC stops at the arrival whose count reaches the bound: bound 4 lets the third backedge reach the exit evaluation, and the unwinding assertion checks no fourth is taken";
            } fields;
          # CBMC as the bundle runs it: the release's CBMC, the overlay's
          # source build of exactly the version the bundle ships, with
          # nix/cbmc-value-set-offset-guard.patch. A value-set candidate at a
          # constant offset of an allocation is selected only when the
          # dereferenced pointer has that offset
          # (src/pointer-analysis/value_set_dereference.cpp,
          # `build_reference_to`); without it two candidates of one
          # allocation at different constant offsets both hold, and whichever
          # is tested first is read or written for both. Its check builds
          # CBMC's unit suite, the patch's regression among it
          # (unit/pointer-analysis/value_set_dereference.cpp), and runs it
          # with CBMC's CORE regression suite.
          kaniCbmc = kaniRelease.cbmc.overrideAttrs (old: {
            patches = (old.patches or [ ]) ++ [ ./nix/cbmc-value-set-offset-guard.patch ];
            doCheck = true;
            # The unit tests of the memory analyzer and the SMT2 back end
            # launch gdb and z3 from PATH.
            nativeCheckInputs = (old.nativeCheckInputs or [ ]) ++ [
              pkgs.gdb
              pkgs.z3
            ];
            # Resolve the subprocess test's absolute echo path into the build closure.
            # Run the dereference regression explicitly, then the complete unit and
            # CORE regression selections.
            postPatch = (old.postPatch or "") + ''
              substituteInPlace unit/util/piped_process.cpp \
                --replace-fail '"/bin/echo"' '"${pkgs.lib.getExe' pkgs.coreutils "echo"}"'
            '';
            checkPhase = ''
              runHook preCheck
              command -v gcc
              ${pkgs.lib.getExe' pkgs.gdb "gdb"} --version
              ${pkgs.lib.getExe pkgs.z3} --version
              ${pkgs.lib.getExe' pkgs.coreutils "echo"} "The Jabberwocky"
              cmake --build . --target unit --parallel "$NIX_BUILD_CORES"
              ctest -N -R '^(unit|unit-xfail|cbmc-CORE)$'
              bin/unit '[value_set_dereference]'
              ctest --output-on-failure --parallel "$NIX_BUILD_CORES" \
                -R '^(unit|unit-xfail)$'
              # The CORE regression suite has CBMC preprocess its C programs
              # with `gcc -E`. The cc-wrapper's fortify hardening adds
              # `-O2 -D_FORTIFY_SOURCE`, which swaps glibc's printf, memcpy and
              # memset for their checked wrappers and changes those tests'
              # verdicts. The wrapper derives its per-target set from
              # NIX_HARDENING_ENABLE at each call (nix-support/add-flags.sh);
              # the set is filtered in this subshell alone, so CBMC's build,
              # its unit tests and the later hooks keep the original one, and
              # CORE's programs are preprocessed as upstream's are.
              (
                kept=()
                for flag in $NIX_HARDENING_ENABLE; do
                  [[ $flag == fortify || $flag == fortify3 ]] || kept+=("$flag")
                done
                export NIX_HARDENING_ENABLE="''${kept[*]}"
                echo "NIX_HARDENING_ENABLE=$NIX_HARDENING_ENABLE"

                if macros="$(gcc -E -dM - </dev/null)"; then
                  printf '%s\n' "$macros"
                else
                  status=$?
                  echo "gcc macro probe failed: exit $status" >&2
                  exit "$status"
                fi

                while IFS= read -r definition; do
                  case "$definition" in
                    "#define _FORTIFY_SOURCE "*)
                      echo "gcc -E still defines _FORTIFY_SOURCE: $definition" >&2
                      exit 1
                      ;;
                  esac
                done <<<"$macros"

                ctest --output-on-failure --parallel "$NIX_BUILD_CORES" \
                  -R '^cbmc-CORE$'
              )
              runHook postCheck
            '';
          });
          kaniBundle = kaniRelease.kani.overrideAttrs (old: {
            # The driver and the CBMC tools the bundle runs, replacing the
            # release's prebuilt ones in `lib/kani/bin`, which its wrappers
            # put first on PATH.
            postInstall = (old.postInstall or "") + ''
              install -m 0755 ${pkgs.lib.getExe' kaniDriver "kani-driver"} $out/lib/kani/bin/kani-driver
              for tool in cbmc goto-analyzer goto-cc goto-instrument; do
                rm $out/lib/kani/bin/$tool
                ln -s ${kaniCbmc}/bin/$tool $out/lib/kani/bin/$tool
              done
            '';
            # The installed driver, its goto-instrument and its CBMC, on a
            # real harness. Each case's exit status, report, policy and loop-
            # bound evidence are kept in the package
            # (share/kani-checks/loop-bounds/CASE) and its report printed
            # into the build log, whatever the outcome; a case is accepted on
            # its exit status, the report lines that establish it, and its
            # evidence: a case that reaches CBMC records counts_to_its_limit's
            # launch, a policy refused for it records none; a refusal is the
            # harness's own, so the other harness of bounds.rs is verified
            # all the same.
            postInstallCheck = (old.postInstallCheck or "") + ''
              export HOME=$TMPDIR
              cp ${./nix/kani-loop-bounds.rs} bounds.rs
              checks=$out/share/kani-checks/loop-bounds
              mkdir -p $checks
              refuse() {
                echo "loop bounds, $1: $2" >&2
                exit 1
              }
              # verify NAME STATUS EXPECTED-LINES LAUNCHED POLICY: kani on
              # bounds.rs, under POLICY unless it is `-`; LAUNCHED is `yes`
              # when CBMC must have been launched under the policy.
              verify() {
                local name=$1 status=$2 expected_lines=$3 launched=$4 policy=$5
                local case=$checks/$name found=0
                mkdir $case
                local options=(-Z unstable-options)
                if [[ $policy != - ]]; then
                  cp $policy $case/policy.json
                  mkdir $case/evidence
                  options+=(--loop-bounds $case/policy.json --loop-bounds-evidence $case/evidence)
                fi
                $out/bin/kani bounds.rs "''${options[@]}" >$case/report.log 2>&1 || found=$?
                echo "$found" >$case/exit
                echo "=== loop bounds, $name: exit $found"
                cat $case/report.log
                [[ $found == "$status" ]] || refuse $name "exit $found, expected $status"
                local expected
                while IFS= read -r expected; do
                  [[ -z $expected ]] && continue
                  grep -F -q -- "$expected" $case/report.log ||
                    refuse $name "no line containing '$expected'"
                done <<<"$expected_lines"
                [[ $policy == - ]] && return
                local attempt=$case/evidence/counts_to_its_limit/solver.attempt
                if [[ $launched == yes ]]; then
                  [[ -f $attempt ]] || refuse $name "no recorded solver launch"
                  grep -F -q 'CBMC launch attempt: counts_to_its_limit' $case/report.log ||
                    refuse $name "no reported solver launch"
                else
                  [[ ! -e $attempt ]] || refuse $name "a refused policy recorded a solver launch"
                  ! grep -F -q 'CBMC launch attempt: counts_to_its_limit' $case/report.log ||
                    refuse $name "a refused policy reported a solver launch"
                fi
              }
              verify harness-bound 0 'VERIFICATION:- SUCCESSFUL' no -
              # Bound 4: every property of the harness holds.
              verify sufficient 0 $'Loop bounds artifact: \nLoop bound: count_up loop 0 of 1 at bounds.rs:\nunwound to 4\n ** 0 of 3 failed\nVERIFICATION:- SUCCESSFUL' \
                yes ${kaniLoopBounds "sufficient" "counts_to_its_limit" [ (countUp { }) ]}
              # Bound 3: the one failure is count_up's unwinding assertion.
              verify insufficient 1 $'unwound to 3\nCheck 3: count_up.unwind.0\n ** 1 of 3 failed\nFailed Checks: unwinding assertion loop 0\nVERIFICATION:- FAILED' \
                yes ${kaniLoopBounds "insufficient" "counts_to_its_limit" [ (countUp { bound = 3; }) ]}
              verify absent 1 'has 0 loop(s) in the instrumented binary' \
                no ${kaniLoopBounds "absent" "counts_to_its_limit" [ (countUp { function = "absent"; }) ]}
              verify miscounted 1 'has 1 loop(s) in the instrumented binary, the policy declares 2' \
                no ${
                  kaniLoopBounds "miscounted" "counts_to_its_limit" [
                    (countUp {
                      loops_in_function = 2;
                    })
                  ]
                }
              verify unknown-harness 1 'names harnesses this run does not verify' \
                no ${kaniLoopBounds "unknown-harness" "absent" [ (countUp { }) ]}
              # A function-scoped bound of sum_to's loop, no harness entry:
              # it applies in the harness whose binary holds sum_to.
              verify function-scoped 0 $'Loop bound: sum_to loop 0 of 1 at bounds.rs:\nunwound to 4\nVERIFICATION:- SUCCESSFUL' \
                yes ${kaniPolicy "function-scoped" { loops = [ sumTo ]; }}
              # A deadline CBMC cannot meet: counts_to_its_limit's run is
              # killed at 1 ms and has no verdict; the other harness, under its
              # own deadline, verifies all the same.
              verify deadline-breach 1 $'CBMC exceeded its deadline of 1 ms\nComplete - 1 successfully verified harnesses, 1 failures, 2 total.' \
                yes ${
                  kaniPolicy "deadline-breach" {
                    deadlines = [
                      {
                        harness = "counts_to_its_limit";
                        milliseconds = 1;
                        reason = "below CBMC's start-up: the run cannot meet it";
                      }
                      {
                        harness = "sums_without_a_local_bound";
                        milliseconds = 60000;
                        reason = "a loop of at most three iterations, verified in under a second";
                      }
                    ];
                  }
                }
              # A policy that dates one harness and not the other is refused
              # before any solver runs.
              verify undated 1 'gives no deadline to harnesses this run verifies: ["sums_without_a_local_bound"]' \
                no ${
                  kaniPolicy "undated" {
                    deadlines = [
                      {
                        harness = "counts_to_its_limit";
                        milliseconds = 60000;
                        reason = "a loop of at most three iterations, verified in under a second";
                      }
                    ];
                  }
                }
              # The evidence of each harness of each case, one check per
              # property. CASE names a case, HARNESS a harness of
              # bounds.rs; its evidence is the case's directory for it.
              jq=${pkgs.lib.getExe pkgs.jq}
              discovery=(discovery.arguments discovery.status discovery.stdout discovery.stderr)
              solver=(solver.arguments solver.identity solver.attempt solver.execution.json)
              part() {
                tr '\0' '\n' <"$1" | grep -F -x -q -- "$2"
              }
              # holds CASE HARNESS FILE...: each file is in the evidence.
              holds() {
                local name=$1 at=$checks/$1/evidence/$2 kept
                shift 2
                for kept in "$@"; do
                  [[ -f $at/$kept ]] || refuse $name "no $kept in its evidence"
                done
              }
              # preserved CASE HARNESS: the instrumented binary was preserved
              # before anything read it and outlived the run whatever its
              # outcome: the record names the copy and an absolute build path
              # outside the evidence, the copy's bytes have the recorded
              # digest, and the loop discovery read the copy, never the
              # build path.
              preserved() {
                local name=$1 at=$checks/$1/evidence/$2 path digest source
                holds $name $2 artifact.out artifact.json
                path=$($jq -er .path $at/artifact.json) || refuse $name "artifact.json names no path"
                digest=$($jq -er .sha256 $at/artifact.json) || refuse $name "artifact.json records no digest"
                source=$($jq -er .source $at/artifact.json) || refuse $name "artifact.json records no build path"
                [[ $path == "$at/artifact.out" ]] || refuse $name "artifact.json names $path, not its copy"
                [[ $source == /* && $source != "$at"/* ]] ||
                  refuse $name "artifact.json's build path $source is not outside its evidence"
                [[ $(sha256sum <$at/artifact.out) == "$digest  -" ]] ||
                  refuse $name "the preserved bytes do not have the recorded digest $digest"
                part $at/discovery.arguments "$path" ||
                  refuse $name "the loop discovery did not read the preserved artifact"
                ! part $at/discovery.arguments "$source" ||
                  refuse $name "the loop discovery read the build path"
              }
              # solved CASE HARNESS: the solver ran on the preserved copy,
              # never the build path.
              solved() {
                local name=$1 at=$checks/$1/evidence/$2
                part $at/solver.arguments "$($jq -er .path $at/artifact.json)" ||
                  refuse $name "the solver did not run on the preserved artifact"
                ! part $at/solver.arguments "$($jq -er .source $at/artifact.json)" ||
                  refuse $name "the solver ran on the build path"
              }
              # A refused resolution keeps its discovery, its error and the
              # artifact it refused.
              for refused in absent miscounted; do
                holds $refused counts_to_its_limit "''${discovery[@]}" resolution.error
                preserved $refused counts_to_its_limit
              done
              for resolved in sufficient insufficient; do
                # The bounded harness resolved and solved its preserved
                # artifact, its resolution naming the copy and its digest.
                at=$checks/$resolved/evidence/counts_to_its_limit
                holds $resolved counts_to_its_limit "''${discovery[@]}" resolution.json "''${solver[@]}"
                preserved $resolved counts_to_its_limit
                solved $resolved counts_to_its_limit
                $jq -e --slurpfile record $at/artifact.json \
                  '.artifact == {path: $record[0].path, sha256: $record[0].sha256}' \
                  $at/resolution.json >/dev/null ||
                  refuse $resolved "resolution.json names another artifact than artifact.json"
                # The harness the policy does not bound keeps the same
                # evidence but a resolution: its loop inventory lists
                # sum_to's loop, and its solver runs with no local bound.
                at=$checks/$resolved/evidence/sums_without_a_local_bound
                holds $resolved sums_without_a_local_bound "''${discovery[@]}" "''${solver[@]}"
                preserved $resolved sums_without_a_local_bound
                solved $resolved sums_without_a_local_bound
                [[ ! -e $at/resolution.json ]] ||
                  refuse $resolved "the unbounded harness has a resolution"
                $jq -e '[.[] | select(.loops) | .loops[] | select(.sourceLocation.function == "sum_to")] | length == 1' \
                  $at/discovery.stdout >/dev/null ||
                  refuse $resolved "the unbounded harness's inventory does not list sum_to's loop"
                ! part $at/solver.arguments --unwindset ||
                  refuse $resolved "the unbounded harness's solver ran with a local bound"
              done
              # The function-scoped bound resolved in sums_without_a_local_bound
              # alone: its resolution records no harness entry and the
              # policy's selector, its solver runs with that loop's bound,
              # and counts_to_its_limit, whose binary has no sum_to, has no
              # resolution and no local bound. The run's function-scope.json
              # names the selector with that one harness.
              scoped=$checks/function-scoped
              at=$scoped/evidence/sums_without_a_local_bound
              holds function-scoped sums_without_a_local_bound "''${discovery[@]}" resolution.json "''${solver[@]}"
              preserved function-scoped sums_without_a_local_bound
              solved function-scoped sums_without_a_local_bound
              $jq -e --slurpfile policy $scoped/policy.json \
                '.policy == null and .function_scope == $policy[0].loops and ([.resolved[].selector] == $policy[0].loops)' \
                $at/resolution.json >/dev/null ||
                refuse function-scoped "resolution.json does not record the function-scoped selector alone"
              loop=$($jq -er '.resolved[0].loop' $at/resolution.json) ||
                refuse function-scoped "resolution.json resolves no loop"
              part $at/solver.arguments --unwindset && part $at/solver.arguments "$loop:4" ||
                refuse function-scoped "the solver did not run with $loop:4"
              at=$scoped/evidence/counts_to_its_limit
              holds function-scoped counts_to_its_limit "''${discovery[@]}" "''${solver[@]}"
              [[ ! -e $at/resolution.json ]] ||
                refuse function-scoped "counts_to_its_limit resolved the function-scoped bound"
              ! part $at/solver.arguments --unwindset ||
                refuse function-scoped "counts_to_its_limit's solver ran with a local bound"
              [[ -f $scoped/evidence/function-scope.json ]] ||
                refuse function-scoped "no function-scope.json"
              $jq -e --slurpfile policy $scoped/policy.json \
                '. == [{selector: $policy[0].loops[0], harnesses: ["sums_without_a_local_bound"]}]' \
                $scoped/evidence/function-scope.json >/dev/null ||
                refuse function-scoped "function-scope.json does not name the selector with sums_without_a_local_bound"
              # Every spawned solver execution recorded its one timing record:
              # the killed run its 1 ms deadline, a duration of at least it,
              # and its deadline termination with the cleanup timed apart; the
              # harness that met its deadline its 60000 ms deadline and an
              # exit of CBMC's own. Its exit code is CBMC's, recorded as it
              # was: CBMC reports Kani's reachability checks as failed
              # properties and exits nonzero for a harness Kani verifies
              # (kani-driver call_cbmc.rs, `VerificationResult::from`), so the
              # code is not asserted here.
              breach=$checks/deadline-breach/evidence
              holds deadline-breach counts_to_its_limit solver.execution.json "''${solver[@]}"
              $jq -e '.deadline_milliseconds == 1
                  and (.elapsed.seconds * 1000000000 + .elapsed.nanoseconds) >= 1000000
                  and .termination.kind == "deadline"
                  and .termination.cleanup_error == null
                  and (.termination.cleanup_elapsed.nanoseconds < 1000000000)' \
                $breach/counts_to_its_limit/solver.execution.json >/dev/null ||
                refuse deadline-breach "solver.execution.json does not record the 1 ms deadline it was killed at"
              holds deadline-breach sums_without_a_local_bound solver.execution.json
              $jq -e '.deadline_milliseconds == 60000
                  and (.termination | keys) == ["code", "kind"]
                  and .termination.kind == "exited"
                  and (.termination.code | type) == "number"' \
                $breach/sums_without_a_local_bound/solver.execution.json >/dev/null ||
                refuse deadline-breach "the harness that met its deadline did not record its exit"
              # A normal exit permits property interpretation whatever its code:
              # the sufficient case verified, and its run exited 10, CBMC's
              # exit for a run whose properties include Kani's failed
              # reachability checks (CPROVER_EXIT_VERIFICATION_UNSAFE).
              $jq -e '.termination == {kind: "exited", code: 10}' \
                $checks/sufficient/evidence/counts_to_its_limit/solver.execution.json >/dev/null ||
                refuse sufficient "its verified run did not record its normal exit 10"
              # A solver killed by a signal after its whole report gives no
              # verdict whatever the report holds. The installed driver is run
              # as its launcher runs it (lib/kani/bin first on PATH, argv[0]
              # `kani`), the controlled solver first: the bundle's own CBMC,
              # its whole --json-ui output kept beside the case's evidence
              # (solver.stdout), then SIGKILL of itself. Under bound 4
              # count_up's unwinding property was SUCCESS, under bound 3
              # FAILURE; each harness records the signal, and the report
              # carries the signal's header and neither a verification nor a
              # failed-checks summary.
              signalling=$TMPDIR/signalling-solver
              mkdir $signalling
              printf '%s\n' '#!${pkgs.runtimeShell}' \
                '${kaniCbmc}/bin/cbmc "$@" | tee "$SOLVER_COPY"' \
                'kill -KILL $$' >$signalling/cbmc
              chmod +x $signalling/cbmc
              signalled() { # NAME STATUS POLICY
                local name=$1 status=$2 policy=$3 case=$checks/$1 found=0 harness
                mkdir $case $case/evidence
                cp $policy $case/policy.json
                (
                  export PATH=$signalling:$out/lib/kani/bin:$PATH SOLVER_COPY=$case/solver.stdout
                  exec -a kani $out/lib/kani/bin/kani-driver bounds.rs -Z unstable-options \
                    --loop-bounds $case/policy.json --loop-bounds-evidence $case/evidence
                ) >$case/report.log 2>&1 || found=$?
                echo "$found" >$case/exit
                echo "=== loop bounds, $name: exit $found"
                cat $case/report.log
                [[ $found == 1 ]] || refuse $name "exit $found, expected 1"
                $jq -e --arg status "$status" \
                  '[.[] | select(.result) | .result[] | select(.property == "count_up.unwind.0") | .status] == [$status]' \
                  $case/solver.stdout >/dev/null ||
                  refuse $name "the solver's report did not hold count_up.unwind.0 as $status"
                for harness in counts_to_its_limit sums_without_a_local_bound; do
                  holds $name $harness "''${discovery[@]}" "''${solver[@]}"
                  preserved $name $harness
                  solved $name $harness
                  $jq -e '.termination == {kind: "signaled", signal: 9}' \
                    $case/evidence/$harness/solver.execution.json >/dev/null ||
                    refuse $name "$harness did not record its SIGKILL"
                done
                grep -F -q 'CBMC failed: terminated by signal 9' $case/report.log ||
                  refuse $name "no signal header in its report"
                ! grep -F -q 'VERIFICATION:- SUCCESSFUL' $case/report.log ||
                  refuse $name "a signalled run was reported verified"
                ! grep -F -q 'Failed Checks:' $case/report.log ||
                  refuse $name "a signalled run reported failed checks"
                grep -F -q 'Complete - 0 successfully verified harnesses, 2 failures, 2 total.' $case/report.log ||
                  refuse $name "its summary does not count both signalled harnesses as failures"
              }
              signalled signal-after-success SUCCESS ${
                kaniLoopBounds "signal-after-success" "counts_to_its_limit" [ (countUp { }) ]
              }
              signalled signal-after-failure FAILURE ${
                kaniLoopBounds "signal-after-failure" "counts_to_its_limit" [ (countUp { bound = 3; }) ]
              }
              # Evidence is created exclusively: a harness whose evidence
              # directory already exists is refused before its discovery, and
              # nothing in that directory is written or replaced.
              collision=$checks/collision
              mkdir -p $collision/evidence/counts_to_its_limit
              cp ${kaniLoopBounds "collision" "counts_to_its_limit" [ (countUp { }) ]} $collision/policy.json
              found=0
              $out/bin/kani bounds.rs -Z unstable-options --loop-bounds $collision/policy.json \
                --loop-bounds-evidence $collision/evidence >$collision/report.log 2>&1 || found=$?
              echo "$found" >$collision/exit
              echo "=== loop bounds, collision: exit $found"
              cat $collision/report.log
              [[ $found == 1 ]] || refuse collision "exit $found, expected 1"
              grep -F -q 'failed to reserve the loop-bounds evidence' $collision/report.log ||
                refuse collision "no refused reservation"
              [[ -z $(ls -A $collision/evidence/counts_to_its_limit) ]] ||
                refuse collision "the existing evidence directory was written"
              ! grep -F -q 'CBMC launch attempt: counts_to_its_limit' $collision/report.log ||
                refuse collision "a refused reservation reported a solver launch"
            '';
          });
          # What maintaining the project runs besides the toolchain: the
          # proof harnesses (Kani, on its own pinned toolchain), the
          # mutation campaign, the reach map's coverage (cargo-llvm-cov), the
          # Miri gate's per-test memory and duration (GNU time), the fuzz
          # campaign (fuzz/qualify.sh, fuzz/smoke.sh), and the check of the
          # gate scripts, which launch the gate tool (tests/gate), built by
          # the toolchain itself.
          maintenance = [
            kaniBundle
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
