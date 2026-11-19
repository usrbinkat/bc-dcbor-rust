#!/usr/bin/env bash
# The concurrency gate: the decode scope's atomic protocol (its intrusive
# queue, stepping flag, retained removal admission, reference count and
# terminal drain) under the model checkers, each model's test a process and
# a row of its own (src/sync/models.rs, and the baselines' entry point,
# tests/resumable/native_traces.rs), every model configured by the one
# runner (tests/support/model.rs) and judged by the gate (tests/gate):
#
#   loom      every interleaving of one to four workers beside the main
#             thread, no preemption bound, and the outcomes acquire and
#             release orderings permit;
#   shuttle   every schedule of five workers, the first count loom cannot
#             reach, by shuttle's exhaustive depth-first scheduler, each
#             schedule replayed for determinism; exhaustive under
#             sequential consistency.
#
# Modes:
#
#   derive    on the working tree: each model's least bound and least stack
#             searched upward across processes, and published as
#             tests/data/model-bounds.txt, a source change to commit;
#   gate      on a commit, the tree clean: the evidence, every model at its
#             recorded values and one under each, and the planted controls
#             (CONTROLS), each run on its own copy of the commit made by
#             `git archive`, never on the checkout; results.tsv and the
#             gate's verdict.
#
# Every input a model run reads is set here and recorded in the identity:
# no LOOM_*, SHUTTLE_* or DCBOR_MODEL_* variable reaches a run (the gate sets
# DCBOR_MODEL_BOUND and DCBOR_MODEL_STACK per row), backtraces are off, and
# the page size the stacks are multiples of is the host's.
#
# Usage: tests/concurrency-models.sh derive|gate
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo rustc patch time sha256sum getconf git tar; do
	if ! command -v "$tool" >/dev/null; then
		printf 'concurrency gate prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
		exit 127
	fi
done
gate_prepare || exit 2
if (($# != 1)); then
	echo "usage: tests/concurrency-models.sh derive|gate" >&2
	exit 2
fi
mode="$1"
case "$mode" in
derive | gate) ;;
*)
	echo "usage: tests/concurrency-models.sh derive|gate" >&2
	exit 2
	;;
esac
logs="${CONCURRENCY_LOG_DIR:-${TMPDIR:?required, or CONCURRENCY_LOG_DIR: the gate log directory}/concurrency-models}"
mkdir -p "$logs" || exit 2

# The environment of every run: nothing a checker or the runner reads
# besides what the gate sets per row. The names are the shell's own prefix
# expansion (`${!prefix@}`), which every bash has; `compgen` exists only in
# a bash built with programmable completion, which the development shell's
# is not.
for name in "${!LOOM_@}" "${!SHUTTLE_@}" "${!DCBOR_MODEL_@}"; do
	unset "$name"
done
export RUST_BACKTRACE=0
page="$(getconf PAGESIZE)" || exit 2

# The planted controls of the checkers, one table row per line, from the
# controls' one table (tests/data/controls/controls.tsv, tests/gate
# `controls`), which names each one's diff, checker, planned refusal and
# the text it must name. The table is refused, and nothing runs, when a diff
# in the controls directory has no row or a row's diff does not exist.
listed="$(gate control list "$PWD" - loom shuttle)" || {
	event "FAIL the controls' table is refused; nothing was run"
	exit 1
}
CONTROLS=()
mapfile -t CONTROLS <<<"$listed"
if ((${#CONTROLS[@]} == 0)) || [[ -z "${CONTROLS[0]}" ]]; then
	event "FAIL the controls' table holds no model control; nothing was run"
	exit 1
fi

# The run's identity: the input closure (the control diffs and the bounds
# record among it), the mode, the page size, the environment every run
# reads, each checker's flags and each control.
{
	printf 'mode\t%s\n' "$mode"
	printf 'page\t%s\n' "$page"
	printf 'RUST_BACKTRACE\t%s\n' "$RUST_BACKTRACE"
	for checker in loom shuttle; do
		printf 'checker\t%s\tRUSTFLAGS\t%s\n' "$checker" "${RUSTFLAGS:-} --cfg $checker"
	done
	printf 'control\t%s\n' "${CONTROLS[@]}"
} | identity "$logs" || {
	event "FAIL the run's identity could not be written; nothing was run"
	exit 2
}
echo "identity: $(cat "$logs/identity.txt")"

if [[ "$mode" == derive ]]; then
	event "DERIVE every model's bound and stack ($logs)"
	gate models derive "$PWD" "$page" "$logs"
	status=$?
	event "DONE derive: tests/data/model-bounds.txt, status $status"
	exit "$status"
fi

# Evidence is of a commit: the tree must be clean, and every run is of a
# copy of the commit, so nothing the gate applies reaches the checkout and
# nothing edited meanwhile reaches the evidence (tests/gate-common.sh).
clean_commit "$logs" || exit 1
copies="$PWD/target/concurrency-copies"
# Every control diff applied dry to the commit before any model runs.
preflight_controls "$copies/preflight" || {
	event "FAIL a control diff does not apply to $commit; nothing was run"
	exit 1
}

status=0
mkdir -p "$logs/evidence"
cp "$logs/identity.txt" "$logs/evidence/identity.txt"
copy_of "$copies/evidence" "$commit" || exit 2
event "START evidence of $commit ($logs/evidence)"
if gate models evidence "$copies/evidence" "$page" "$logs/evidence"; then
	event "PASS evidence"
else
	event "FAIL evidence ($logs/evidence/results.tsv)"
	status=1
fi

for line in "${CONTROLS[@]}"; do
	IFS=$'\t' read -r name diff checker _ <<<"$line"
	run="control-$name-$checker"
	mkdir -p "$logs/$run"
	cp "$logs/identity.txt" "$logs/$run/identity.txt"
	copy_of "$copies/$run" "$commit" || exit 2
	if ! apply_diff "$diff" "$copies/$run"; then
		event "FAIL $run: the diff does not apply: $diff"
		status=1
		continue
	fi
	event "START $run ($logs/$run)"
	if gate models control "$copies/$run" "$logs/$run" "$name" "$checker"; then
		event "PASS $run: the planted defect was refused by its own rule"
	else
		event "FAIL $run: the planted defect was not refused by its own rule ($logs/$run)"
		status=1
	fi
done
if ! still_at_commit; then
	event "FAIL the checkout moved off $commit during the run"
	status=1
fi
event "DONE evidence and ${#CONTROLS[@]} controls of $commit; status $status"
exit "$status"
