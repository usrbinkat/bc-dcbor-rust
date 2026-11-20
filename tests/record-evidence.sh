#!/usr/bin/env bash
# Run in the active fork-enabled development shell. This script never
# changes toolchains: all four feature projections share its identity.
#
# Every decision is the gate tool's (tests/gate): the record variants, the
# currency of each record, and the matrix cost evidence, checked or
# recorded (`gate costs`, which stages every leg's records and publishes
# them only after all eight legs pass, reuses a completed run's legs, and
# prunes or names the records no matrix produces). This script launches it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
own_process_group "$@"
mode="${1:-check}"
resume="${2:-}"
if (($# > 2)) || [[ -n "$resume" && "$mode" != record-costs && "$mode" != check-costs ]]; then
	echo "usage: bash tests/record-evidence.sh {record-costs|check-costs} [completed-run-directory]" >&2
	exit 2
fi
case "$mode" in
check | record | record-budgets | check-costs | record-costs) ;;
*)
	echo "usage: bash tests/record-evidence.sh [check|record|record-budgets|check-costs|record-costs]" >&2
	exit 2
	;;
esac
# The command selects the recording mode; inherited flags must not let a cost
# check or recording rewrite the independent trace and tightness baselines.
unset DCBOR_RECORD_FACTORS DCBOR_RECORD_TRACES DCBOR_COST_MODE DCBOR_COST_DIRECTORY DCBOR_COST_VARIANT DCBOR_CLASS_COVERAGE DCBOR_RECORD_BUDGETS
: "${DCBOR_CONFIGURATION:?the development shell must identify the configuration}"
export DCBOR_RIGOR="${DCBOR_RIGOR:-fast}"
case "$DCBOR_RIGOR" in
fast | exhaustive) ;;
*)
	echo "DCBOR_RIGOR must be fast or exhaustive" >&2
	exit 2
	;;
esac
gate_prepare

# The record variants, from their one definition (tests/gate, `records`):
# each a feature set, comma-separated as --features takes it, and the suffix
# its records are written under.
suffixes=()
features=()
# Captured first: `set -e` does not see a process substitution's failure,
# so a list cut short by the tool would otherwise pass.
variants="$(gate variants)"
while IFS=$'\t' read -r variant_features variant_suffix; do
	features+=("$variant_features")
	suffixes+=("$variant_suffix")
done <<<"$variants"
((${#features[@]} > 0)) || {
	echo "the gate names no record variant" >&2
	exit 2
}

if [[ "$mode" == record || "$mode" == record-costs ]]; then
	: "${DCBOR_COST_REASON:?recording requires a mechanism explanation in DCBOR_COST_REASON}"
fi

# The matrix cost evidence (tests/gate, `costs`): TMPDIR is where its logs
# are made; DCBOR_COST_BASELINE, when set, the approved baseline a check
# reads instead of tests/data/costs.
costs() {
	: "${TMPDIR:?required: the cost recorder staging directory}"
	gate costs "$1" "$PWD" ${resume:+"$resume"}
}

case "$mode" in
check-costs)
	costs check
	exit 0
	;;
record-costs)
	costs record
	exit 0
	;;
esac

# The recording budgets (tests/gate, `budgets`, from the record crate's one
# inventory) of this run's layer (DCBOR_RIGOR): each record recorded by its
# family's own test with DCBOR_RECORD_BUDGETS naming that record alone, its
# currency checked, then the same test run with recording disabled against
# the record just published. Each run's whole output is kept under TMPDIR,
# judged by the gate's one classifier, and required to name the record it
# finalized exactly once. One run records one layer, so the exhaustive
# layer's records are recorded only where its execution is authorized; the
# inventory is held by both layers' runs together. `record-budgets` exits
# after its layer; the evidence gate (`gate evidence`, which `check` and
# `record` reach below) refuses any record of the inventory missing.
if [[ "$mode" == record || "$mode" == record-budgets ]]; then
	budget_logs="$(mktemp -d "${TMPDIR:?required: budget execution logs}/dcbor-budgets.XXXXXXXX")"
	echo "budget execution logs: $budget_logs"
	# `record` runs the family's test with DCBOR_RECORD_BUDGETS naming its one
	# record; `check` runs it with the variable removed outright, so the check
	# reads the record just published (compiled in again: the support crate's
	# build reruns on any change under tests/data/budgets) and never records.
	budget_run() {
		local phase="$1"
		local log="$budget_logs/$name.$phase.log"
		local recording
		case "$phase" in
		record) recording=(env "DCBOR_RECORD_BUDGETS=$name") ;;
		check) recording=(env -u DCBOR_RECORD_BUDGETS) ;;
		*)
			echo "no budget phase $phase; record or check" >&2
			exit 2
			;;
		esac
		"${recording[@]}" "${confined[@]}" cargo test -p dcbor --no-default-features --features "$projection" \
			--test "$target" "$test" -- --exact --nocapture 2>&1 | tee "$log"
		local outcome
		outcome="$(gate classify cargo test 0 "$log")"
		[[ "$outcome" == pass ]] || {
			echo "$name: $phase did not execute a passing test ($outcome)" >&2
			exit 1
		}
		# Every receipt the run printed, whichever record it names (`budget
		# finalized: RECORD`, after libtest's `test NAME ... ` prefix when it
		# shares that line): exactly one, and it is this record's.
		local line finalized=()
		while IFS= read -r line; do
			if [[ "$line" == *"budget finalized: "* ]]; then
				finalized+=("${line##*budget finalized: }")
			fi
		done <"$log"
		[[ "${#finalized[@]}" == 1 && "${finalized[0]}" == "$name" ]] || {
			echo "$name: $phase finalized ${#finalized[@]} families (${finalized[*]}), expected $name alone" >&2
			exit 1
		}
	}
	budgets="$(gate budgets)"
	[[ -n "$budgets" ]] || {
		echo "the gate names no budget family" >&2
		exit 2
	}
	selected=0
	inventoried=0
	while IFS=$'\t' read -r name projection target test rigor witness; do
		inventoried=$((inventoried + 1))
		[[ "$rigor" == "$DCBOR_RIGOR" ]] || continue
		selected=$((selected + 1))
		DCBOR_RIGOR="$rigor" DCBOR_WITNESS="$witness" \
			budget_run record
		gate current "tests/data/budgets/$name"
		DCBOR_RIGOR="$rigor" DCBOR_WITNESS="$witness" \
			budget_run check
	done <<<"$budgets"
	((selected > 0)) || {
		echo "the budget inventory holds no selection of the $DCBOR_RIGOR layer" >&2
		exit 2
	}
	echo "budgets recorded and checked: $selected of $inventoried, the $DCBOR_RIGOR layer's"
	if [[ "$mode" == record-budgets ]]; then
		exit 0
	fi
fi

if [[ "$mode" == record ]]; then
	for index in "${!suffixes[@]}"; do
		echo "record evidence: ${suffixes[index]:-default}, rigor=$DCBOR_RIGOR"
		DCBOR_RECORD_FACTORS=1 "${confined[@]}" cargo test -p dcbor --no-default-features \
			--features "${features[index]}" --lib
		DCBOR_RECORD_TRACES=1 "${confined[@]}" cargo test -p dcbor --no-default-features \
			--features "${features[index]}" --test resumable_contract \
			every_baseline_admits_exactly_its_recorded_calls -- --nocapture
	done
	costs record
fi

# Every trace and tightness record of every variant, present and current
# (tests/gate, `evidence`, which holds the family inventory). Detailed row
# validation remains in the Rust recorders, the single schema owners.
gate evidence "$PWD"
