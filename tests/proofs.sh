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
# With `calibrate PLAN CONTROL_LOGS`, the run is a calibration instead (`gate
# proofs-calibrate`, tests/gate/src/proofs.rs `calibration`): ready only once
# the control run whose log directory is CONTROL_LOGS finished and passed on
# this commit (its `verdict.json`) and the system settled under the declared
# policy (`readiness.json`); then each harness the plan names (`plan_of`)
# checked alone, one Kani run each, under its plan's operational limit,
# measured and qualifying nothing, each run's records adoptable as
# calibration evidence (`gate proofs-adopt LOGS/calibration/H.N.evidence`).
#
# Evidence is of a commit: the tree must be clean, and Kani runs on a copy of
# it (`copy_of`), never the checkout, at one location, target/proof-source,
# so a calibration's and a qualification's builds share their paths and so
# their instrumented binaries. The copy is held under an exclusive lock
# (target/proof-source.lock) for the whole run: a second proof run is
# refused, never interleaved with this one's copy or workload.
#
# Usage: tests/proofs.sh [calibrate PLAN CONTROL_LOGS]
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
control_logs=""
case "$#:${1:-}" in
    0:) ;;
    3:calibrate)
        plan="$(realpath -e "$2")" || exit 2
        control_logs="$(realpath -e "$3")" || exit 2
        ;;
    *)
        echo "usage: tests/proofs.sh [calibrate PLAN CONTROL_LOGS]" >&2
        exit 2
        ;;
esac
gate_prepare || exit 2
logs="${PROOF_LOG_DIR:-${TMPDIR:?required, or PROOF_LOG_DIR: the log directory of the proof gate}/proofs}"
# A run's evidence is created once: an existing log directory is another
# run's, never overwritten.
mkdir "$logs" || exit 2
clean_commit "$logs" || exit 1
mkdir -p "$PWD/target" || exit 2
exec 9> "$PWD/target/proof-source.lock" || exit 2
if ! flock --nonblock 9; then
    event "FAIL another proof run holds target/proof-source.lock; nothing was run"
    exit 2
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
} | identity "$logs" || {
    event "FAIL the run's identity could not be written; nothing was run"
    exit 2
}
echo "identity: $(cat "$logs/identity.txt")"
if [[ -n "$plan" ]]; then
    gate proofs-calibrate "$source_copy" "$PWD/target/kani" "$logs" "$launcher" "$plan" "$control_logs"
    status=$?
    if ! still_at_commit; then
        event "FAIL the checkout moved off $commit during the run"
        status=1
    fi
    event "DONE calibration of $commit; status $status; records $logs"
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
