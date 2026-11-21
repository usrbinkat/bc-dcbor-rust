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
# Usage: tests/proofs.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
own_process_group "$@"
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo cargo-kani rustc sha256sum git; do
	if ! command -v "$tool" >/dev/null; then
		printf 'proof gate prerequisite missing from PATH: %s. Enter the proof development shell.\n' "$tool" >&2
		exit 127
	fi
done
if (($# != 0)); then
	echo "usage: tests/proofs.sh" >&2
	exit 2
fi
gate_prepare || exit 2
logs="${PROOF_LOG_DIR:-${TMPDIR:?required, or PROOF_LOG_DIR: the log directory of the proof gate}/proofs}"
# A run's evidence is created once: an existing log directory is another
# run's, never overwritten.
mkdir "$logs" || exit 2
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
} | identity "$logs" || {
	event "FAIL the run's identity could not be written; nothing was run"
	exit 2
}
echo "identity: $(cat "$logs/identity.txt")"
gate proofs "$PWD" "$PWD/target/kani" "$logs" "$launcher"
status=$?
event "DONE proofs; status $status; results $logs/results.tsv, report $logs/kani.log"
exit "$status"
