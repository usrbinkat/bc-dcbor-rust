#!/usr/bin/env bash
# The proof gate (register item 4): every `#[kani::proof]` harness of the
# library checked by `cargo kani` in the proof build the gate tool defines
# once (tests/gate/src/proofs.rs, `arguments`), under the run's identity.
# Every decision is the gate tool's (`gate proofs`): the report read per
# harness, a reachable unsupported construct or a failed unwinding assertion
# classed as such and never as a verified or an intended failure, the
# harnesses checked held to exactly the `#[kani::proof]` functions of the
# source, one results row each, proved only when it verified, and the
# verdict. Run from the proof shell, which puts `cargo kani` on PATH.
#
# With `calibrate PLAN`, the run is a calibration instead (`gate
# proofs-calibrate`, tests/gate/src/proofs.rs `calibration`): ready once no
# other gate workload runs (the calibration holds target/gate-workload.lock
# itself) and the system settled under the declared policy
# (`readiness.json`). No planted-control run is a prerequisite: proofs
# validate the implementation, and test adequacy is tests/red-green.sh's
# separate track. Then each
# harness the plan names (`plan_of`) checked alone, one Kani run each, under
# its plan's operational limit, measured and qualifying nothing, each run's
# records adoptable as calibration evidence (`gate proofs-adopt
# LOGS/calibration/H.N.evidence`). A qualification holds the workload lock
# here, for its whole run.
#
# With `discover HARNESS...`, the run is a discovery (`gate proofs-discover`,
# tests/gate/src/proofs.rs `discover`): each named harness compiled by the
# proof build, its instrumented binary preserved and its loops inventoried
# by the driver (LOGS/kani.evidence/loop-bounds/H/discovery.*, before CBMC
# starts), nothing verified and no results row written; what the loop-bound
# policy's selectors are copied from. It holds the workload lock here, for
# its whole run, as a qualification does.
#
# With `diagnose DISCOVERY_LOGS HARNESS HARNESS_FILE [FOCUS...]`, the run
# diagnoses one harness of a finished discovery (`gate proofs-diagnose`,
# tests/gate/src/proofs/diagnostics.rs): its preserved artifact solved by
# the recorded solver and command under each step's flags, each step a
# bounded workload, the shares of the FOCUS reported (`--site FILE:LINE`,
# `--function FRAGMENT`, `--callers FRAGMENT`). Its records, its identity
# among them, are a new numbered directory of its own under
# target/kani.diagnostics, never in the discovery's logs. Evidence only,
# never a sample; it holds the workload lock.
#
# Evidence is of a commit: the tree must be clean, and Kani runs on a copy of
# it (`copy_of`), never the checkout, at one location, target/proof-source,
# so a calibration's and a qualification's builds share their paths and so
# their instrumented binaries. The copy is held under an exclusive lock
# (target/proof-source.lock) for the whole run: a second proof run is
# refused, never interleaved with this one's copy or workload.
#
# Usage: tests/proofs.sh [calibrate PLAN | discover HARNESS... | diagnose DISCOVERY_LOGS HARNESS HARNESS_FILE [FOCUS...]]
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
own_process_group "$@"
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo cargo-kani rustc sha256sum git tar flock realpath; do
    if ! command -v "$tool" > /dev/null; then
        printf 'proof gate prerequisite missing from PATH: %s. Enter the proof development shell.\n' "$tool" >&2
        exit 127
    fi
done
plan=""
discover=()
diagnose=()
usage() {
    echo "usage: tests/proofs.sh [calibrate PLAN | discover HARNESS... | diagnose DISCOVERY_LOGS HARNESS HARNESS_FILE [FOCUS...]]" >&2
    exit 2
}
workload_lock="$PWD/target/gate-workload.lock"
# The checkout's workload lock, held on descriptor 8 for the rest of the
# run; refused while another gate workload holds it.
hold_workload_lock() {
    exec 8> "$workload_lock" || exit 2
    if ! flock --nonblock 8; then
        event "FAIL another gate workload holds target/gate-workload.lock; nothing was run"
        exit 2
    fi
}
case "$#:${1:-}" in
    0:) ;;
    2:calibrate)
        plan="$(realpath -e "$2")" || exit 2
        ;;
    *:discover)
        (($# >= 2)) || usage
        discover=("${@:2}")
        ;;
    *:diagnose)
        (($# >= 4)) || usage
        evidence="$(realpath -e "$2/kani.evidence")" || exit 2
        diagnose=("$evidence" "$3" "$4" "$PWD/target/kani.diagnostics" "${@:5}")
        ;;
    *) usage ;;
esac
gate_prepare || exit 2
mkdir -p "$PWD/target" || exit 2
if ((${#diagnose[@]} > 0)); then
    hold_workload_lock
    directory="$(gate proofs-diagnose "${diagnose[@]}")"
    status=$?
    event "DONE diagnosis of ${diagnose[1]}; status $status; records ${directory:-none}"
    exit "$status"
fi
logs="${PROOF_LOG_DIR:-${TMPDIR:?required, or PROOF_LOG_DIR: the log directory of the proof gate}/proofs}"
# A run's evidence is created once: an existing log directory is another
# run's, never overwritten.
mkdir "$logs" || exit 2
clean_commit "$logs" || exit 1
exec 9> "$PWD/target/proof-source.lock" || exit 2
if ! flock --nonblock 9; then
    event "FAIL another proof run holds target/proof-source.lock; nothing was run"
    exit 2
fi
if [[ -z "$plan" ]]; then
    hold_workload_lock
fi
source_copy="$PWD/target/proof-source"
copy_of "$source_copy" "$commit" || exit 2
# The Kani this run launches, selected once: its path is written to
# kani-launcher, which the verification below is given.
launcher="$logs/kani-launcher"
kani_identity="$(gate proofs-identity "$launcher")" || {
    event "FAIL the Kani the run launches could not be identified; nothing was run"
    exit 2
}
{
    printf '%s\n' "$kani_identity"
    printf 'build\t%s\n' "$(gate proofs-build)"
    printf 'commit\t%s\n' "$commit"
    if ((${#discover[@]} > 0)); then
        printf 'discover\t%s\n' "${discover[@]}"
    fi
} | identity "$logs" || {
    event "FAIL the run's identity could not be written; nothing was run"
    exit 2
}
echo "identity: $(cat "$logs/identity.txt")"
if [[ -n "$plan" ]]; then
    gate proofs-calibrate "$source_copy" "$PWD/target/kani" "$logs" "$launcher" "$plan" \
        "$workload_lock"
    status=$?
    if ! still_at_commit; then
        event "FAIL the checkout moved off $commit during the run"
        status=1
    fi
    event "DONE calibration of $commit; status $status; records $logs"
    exit "$status"
fi
if ((${#discover[@]} > 0)); then
    gate proofs-discover "$source_copy" "$PWD/target/kani" "$logs" "$launcher" "${discover[@]}"
    status=$?
    if ! still_at_commit; then
        event "FAIL the checkout moved off $commit during the run"
        status=1
    fi
    event "DONE discovery of $commit; status $status; records $logs/kani.evidence/loop-bounds"
    exit "$status"
fi
gate proofs "$source_copy" "$PWD/target/kani" "$logs" "$launcher"
status=$?
if ! still_at_commit; then
    event "FAIL the checkout moved off $commit during the run"
    status=1
fi
event "DONE proofs; status $status; results $logs/results.tsv, report $logs/kani.log"
exit "$status"
