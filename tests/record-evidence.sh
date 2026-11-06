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
mode="${1:-check}"
resume="${2:-}"
if (($# > 2)) || [[ -n "$resume" && "$mode" != record-costs && "$mode" != check-costs ]]; then
	echo "usage: bash tests/record-evidence.sh {record-costs|check-costs} [completed-run-directory]" >&2
	exit 2
fi
case "$mode" in
check | record | check-costs | record-costs) ;;
*)
	echo "usage: bash tests/record-evidence.sh [check|record|check-costs|record-costs]" >&2
	exit 2
	;;
esac
# The command selects the recording mode; inherited flags must not let a cost
# check or recording rewrite the independent trace and tightness baselines.
unset DCBOR_RECORD_FACTORS DCBOR_RECORD_TRACES DCBOR_COST_MODE DCBOR_COST_DIRECTORY DCBOR_COST_VARIANT DCBOR_CLASS_COVERAGE
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
while IFS=$'\t' read -r variant_features variant_suffix; do
	features+=("$variant_features")
	suffixes+=("$variant_suffix")
done < <(gate variants)
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

if [[ "$mode" == record ]]; then
	for index in "${!suffixes[@]}"; do
		echo "record evidence: ${suffixes[index]:-default}, rigor=$DCBOR_RIGOR"
		DCBOR_RECORD_FACTORS=1 cargo test -p dcbor --no-default-features \
			--features "${features[index]}" --lib
		DCBOR_RECORD_TRACES=1 cargo test -p dcbor --no-default-features \
			--features "${features[index]}" --test resumable_contract \
			every_baseline_admits_exactly_its_recorded_calls -- --nocapture
	done
	costs record
fi

# Every trace and tightness record of every variant, present and current
# (tests/gate, `evidence`, which holds the family inventory). Detailed row
# validation remains in the Rust recorders, the single schema owners.
gate evidence "$PWD"
