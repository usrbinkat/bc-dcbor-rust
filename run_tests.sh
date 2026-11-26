#!/bin/bash

set -e
# Run from the workspace root wherever the script is invoked from.
cd "$(dirname "${BASH_SOURCE[0]}")"

TERM_PURPLE='\033[0;35m'
TERM_BOLD='\033[1m'
TERM_RESET='\033[0m'

section() {
    echo -e "${TERM_PURPLE}${TERM_BOLD}=== $1 ===${TERM_RESET}"
}

# The verification layer every matrix in every leg runs: fast, the default,
# or exhaustive (tests/support/rigor.rs). The tests read it themselves; it is
# exported so every leg runs the same layer, and printed so a log names it.
# Exhaustive runs every target in every leg. Fast omits only targets whose
# compiled implementation is independent of the added features below.
export DCBOR_RIGOR="${DCBOR_RIGOR:-fast}"
case "$DCBOR_RIGOR" in
    fast | exhaustive) ;;
    *)
        echo "DCBOR_RIGOR must be fast or exhaustive" >&2
        exit 2
        ;;
esac
section "rigor: $DCBOR_RIGOR"

# The exhaustive layer's numeric sweeps (src/float.rs: every binary32
# pattern through the reduction, and the full spread of binary32 and
# binary64 patterns through both encoders) run once, optimized, with debug
# assertions and overflow checks kept on, not in each unoptimized leg below,
# which skips them; the fast layer runs their edges and a sample in every
# leg.
EXHAUSTIVE_SWEEPS=(
    float::tests::every_f32_reduces_as_its_reference_and_decodes_only_if_canonical
    float::tests::f32_and_f64_symbolic_and_bounded_agree
)
skips=()
if [[ "$DCBOR_RIGOR" == exhaustive ]]; then
    for sweep in "${EXHAUSTIVE_SWEEPS[@]}"; do
        skips+=(--skip "$sweep")
    done
    section "Exhaustive numeric sweeps"
    for sweep in "${EXHAUSTIVE_SWEEPS[@]}"; do
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
            cargo test --quiet --release --lib -- --exact "$sweep"
    done
fi

# Implementation validation only. The evidence tooling's own tests (the
# record format, the model-bounds and census rows, the gate tool) and the
# planted controls are test adequacy, a separate track: tests/red-green.sh.
# Nothing here runs or reads them.
TOOLING=(dcbor-record dcbor-model-bounds dcbor-census dcbor-gate)
tooling_excludes=()
for package in "${TOOLING[@]}"; do
    tooling_excludes+=(--exclude "$package")
done

select_targets() {
    local features="$1" path target
    targets=(--lib --bins --benches)
    if [[ "$DCBOR_RIGOR" == exhaustive || "$features" == *no_std* || "$features" == *multithreaded* ]]; then
        # no_std changes collection/error infrastructure; multithreaded changes
        # CBOR's shared ownership representation. Both affect arbitrary users.
        targets+=(--tests)
        return
    fi
    for path in tests/*.rs; do
        target="${path##*/}"
        target="${target%.rs}"
        case "$target" in
            normalization | version-numbers)
                # Unicode normalization and package version synchronization
                # contain no derive, hashbrown or bigint-dependent behavior.
                # The full default/workspace runs cover them; exhaustive
                # checks this independence assumption in every feature leg.
                ;;
            *) targets+=(--test "$target") ;;
        esac
    done
}

# Each feature set is tested and linted: code compiled only under some
# features, and the single admission route (clippy.toml), are checked in every
# build that compiles them. Tests run quietly, never silenced: a failure
# prints its test, its message and its location.
# argument: "feature1,feature2,..."
test_only_features() {
    local features="$1"
    section "no default + $features"
    select_targets "$features"
    cargo test --quiet "${targets[@]}" --no-default-features --features "$features" -- "${skips[@]}"
    cargo clippy --all-targets --no-default-features --features "$features" -- -D warnings
}

test_additional_features() {
    local features="$1"
    section "default + $features"
    select_targets "$features"
    cargo test --quiet "${targets[@]}" --features "$features" -- "${skips[@]}"
    cargo clippy --all-targets --features "$features" -- -D warnings
}

test_only_features "no_std"
test_only_features "no_std,multithreaded"
test_only_features "no_std,num-bigint"
test_only_features "no_std,multithreaded,num-bigint"

test_additional_features "multithreaded"
test_additional_features "num-bigint"
test_additional_features "multithreaded,num-bigint"
# Bounded map encoding over the hashbrown fork. custom-std-collections is not
# run here: it requires the standard library built from usrbinkat/rust.
test_additional_features "hashbrown"
test_additional_features "derive,hashbrown"
test_additional_features "derive,hashbrown,multithreaded,num-bigint"

section "All Default Features and doctests"
cargo test --quiet -- "${skips[@]}"
cargo clippy --all-targets -- -D warnings

# The step-latency ceiling is a property of this qualification host, not of
# the code, so the latency tests assert it only when asked; every other run,
# mutation layers included, checks their deterministic assertions alone.
section "Host step-latency qualification"
DCBOR_LATENCY_QUALIFICATION=1 cargo test --quiet --test resumable_contract latency::

# The legs above select the root package; every other member's own targets,
# the derive crate's included, are tested and linted here on the stock
# toolchain, the evidence tooling (TOOLING) excepted.
section "Workspace: every member's targets but the evidence tooling"
cargo test --quiet --workspace "${tooling_excludes[@]}" --features derive,hashbrown,multithreaded,num-bigint -- "${skips[@]}"
cargo clippy --workspace "${tooling_excludes[@]}" --all-targets --features derive,hashbrown,multithreaded,num-bigint -- -D warnings

cargo fmt --all -- --check
