#!/usr/bin/env bash
# Run in the active fork-enabled development shell. This script never
# changes toolchains: all four feature projections share its identity.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
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

# Explicit inventory: discovering existing files would miss an entire family.
families=(buckets decode emission header lifecycle_borrow lifecycle_construct
	lifecycle_copy lifecycle_operations lifecycle_parse lifecycle_scope
	preparation retained_parse string_decode text_encode text_joint text_write validation)
# Families of code compiled only over the forked collections, recorded and
# checked in the two custom-std variants alone.
custom_std_families=(btree)
suffixes=('' .num-bigint .custom-std .custom-std.num-bigint)
# One feature set per element, its features comma-separated as --features
# takes them.
features=('std,derive,hashbrown,multithreaded'
	'std,derive,hashbrown,multithreaded,num-bigint'
	'std,derive,hashbrown,multithreaded,custom-std-collections'
	'std,derive,hashbrown,multithreaded,custom-std-collections,num-bigint')

if [[ "$mode" == record || "$mode" == record-costs ]]; then
	: "${DCBOR_COST_REASON:?recording requires a mechanism explanation in DCBOR_COST_REASON}"
fi

costs() {
	local action="$1" index layer log manifest observed line directory old_identity new_identity header
	: "${TMPDIR:?required: the cost recorder's staging directory}"
	local logs checkpoint reused=''
	local -A staged_identities=()
	local baseline="${DCBOR_COST_BASELINE:-$PWD/tests/data/costs}"
	if [[ "$action" == check ]]; then
		baseline="$(cd "$baseline" && pwd)" || return 1
		# Baselines are local artifacts. A fresh checkout supplies an approved
		# directory explicitly; checking never manufactures its own baseline.
		for index in "${!suffixes[@]}"; do
			for layer in fast exhaustive; do
				manifest="$baseline/inventory${suffixes[index]}.$layer.txt"
				[[ -s "$manifest" ]] || {
					echo "$manifest: missing baseline inventory" >&2
					return 1
				}
				{
					IFS= read -r header
					IFS= read -r line
					[[ "$header" == $'#\tconfiguration\t'"$DCBOR_CONFIGURATION" ]] || return 1
					[[ "$line" == $'#\tfeatures\t'"${features[index]}" ]] || return 1
					local count=0
					while IFS= read -r line; do
						[[ "$line" =~ ^[0-9a-f]{16}$ ]] || return 1
						[[ -s "$baseline/$line.txt" ]] || {
							echo "$line: missing cost baseline" >&2
							return 1
						}
						IFS= read -r header <"$baseline/$line.txt"
						[[ "$header" == $'#\tconfiguration\t'"$DCBOR_CONFIGURATION" ]] || return 1
						count=$((count + 1))
					done
					((count > 0)) || return 1
				} <"$manifest"
			done
		done
	fi
	if [[ -n "$resume" ]]; then
		logs="$(cd "$resume" && pwd)" || return 1
		if [[ "$action" == check ]]; then
			reused="$logs"
			logs="$(mktemp -d "$TMPDIR/dcbor-cost-reuse.XXXXXX")"
			printf 'Reuse completed qualification: %s (artifact verification; no source-equivalence claim)\n' "$reused"
		fi
	else
		logs="$(mktemp -d "$TMPDIR/dcbor-costs.XXXXXX")"
	fi
	printf 'Cost evidence logs: %s\n' "$logs"
	for index in "${!suffixes[@]}"; do
		for layer in fast exhaustive; do
			echo "matrix costs: ${features[index]}, rigor=$layer, mode=$action"
			log="$logs/${index}-${layer}.log"
			observed="$logs/${index}-${layer}.inventory"
			checkpoint="$observed"
			if [[ -n "$reused" ]]; then
				log="$reused/${index}-${layer}.log"
				checkpoint="$reused/${index}-${layer}.inventory"
				[[ -s "$checkpoint.complete" ]] || {
					echo "$checkpoint.complete: missing completed leg; reuse never launches Cargo" >&2
					return 1
				}
			fi
			directory="$baseline"
			if [[ "$action" == record ]]; then
				directory="$logs/${index}-${layer}.records"
				mkdir -p "$directory"
			fi
			if [[ -n "$resume" && -s "$checkpoint.complete" ]]; then
				# The old recorder wrote this checkpoint only after Cargo succeeded.
				# Rebuild its inventory from the retained log and compare it below.
				[[ -s "$log" && -s "$checkpoint" ]] || return 1
				echo "reuse completed leg: $index-$layer"
			else
				if ! DCBOR_COST_MODE="$action" DCBOR_COST_VARIANT="${features[index]}" \
					DCBOR_COST_DIRECTORY="$directory" \
					DCBOR_RIGOR="$layer" cargo test -p dcbor --no-default-features \
					--features "${features[index]}" --tests -- --nocapture --test-threads=1 >"$log" 2>&1; then
					cat "$log"
					return 1
				fi
			fi
			while IFS= read -r line; do
				case "$line" in
				*DCBOR_COST$'\t'*) printf '%s\n' "${line#*DCBOR_COST$'\t'}" ;;
				esac
			done <"$log" | LC_ALL=C sort -u >"$observed.next"
			if [[ ! -s "$observed.next" ]]; then
				echo "$log: no matrix cost evidence" >&2
				return 1
			fi
			manifest="$baseline/inventory${suffixes[index]}.$layer.txt"
			{
				printf '#\tconfiguration\t%s\n' "$DCBOR_CONFIGURATION"
				printf '#\tfeatures\t%s\n' "${features[index]}"
				cat "$observed.next"
			} >"$observed.complete.next"
			if [[ -n "$resume" && -s "$checkpoint.complete" ]]; then
				diff -u "$checkpoint" "$observed.next" || return 1
				diff -u "$checkpoint.complete" "$observed.complete.next" || return 1
			fi
			mv "$observed.next" "$observed"
			if [[ "$action" == record ]]; then
				# Preflight every staged record now; publication waits until all
				# eight test commands and all collision checks have succeeded.
				while IFS= read -r line; do
					[[ "$line" =~ ^[0-9a-f]{16}$ ]] || return 1
					[[ -s "$directory/$line.txt" ]] || return 1
					{
						IFS= read -r header
						IFS= read -r new_identity
					} <"$directory/$line.txt"
					if [[ "$header" != $'#\tconfiguration\t'"$DCBOR_CONFIGURATION" || -z "$new_identity" ]]; then
						echo "$directory/$line.txt: invalid staged configuration or identity" >&2
						return 1
					fi
					if [[ -v "staged_identities[$line]" && "${staged_identities[$line]}" != "$new_identity" ]]; then
						echo "$line: staged cost filename identity collision" >&2
						return 1
					fi
					staged_identities[$line]="$new_identity"
					if [[ -e "tests/data/costs/$line.txt" ]]; then
						{
							IFS= read -r header
							IFS= read -r old_identity
						} <"tests/data/costs/$line.txt"
						if [[ "$old_identity" != "$new_identity" ]]; then
							echo "$line: cost filename identity collision" >&2
							return 1
						fi
					fi
				done <"$observed"
			else
				diff -u "$manifest" "$observed.complete.next"
				if [[ -n "$reused" ]]; then
					while IFS= read -r line; do
						cmp -- "$reused/${index}-${layer}.records/$line.txt" "$baseline/$line.txt" || return 1
					done <"$observed"
				fi
			fi
			mv "$observed.complete.next" "$observed.complete"
		done
	done
	if [[ "$action" == record ]]; then
		mkdir -p tests/data/costs
		# Publish records before any inventory can refer to them. A failed
		# validation leg above never reaches this publication phase.
		for index in "${!suffixes[@]}"; do
			for layer in fast exhaustive; do
				directory="$logs/${index}-${layer}.records"
				observed="$logs/${index}-${layer}.inventory"
				while IFS= read -r line; do
					cp "$directory/$line.txt" "tests/data/costs/.$line.$$.tmp"
					mv "tests/data/costs/.$line.$$.tmp" "tests/data/costs/$line.txt"
				done <"$observed"
			done
		done
		for index in "${!suffixes[@]}"; do
			for layer in fast exhaustive; do
				observed="$logs/${index}-${layer}.inventory"
				manifest="tests/data/costs/inventory${suffixes[index]}.$layer.txt"
				cp "$observed.complete" "$manifest.$$.tmp"
				mv "$manifest.$$.tmp" "$manifest"
			done
		done
	fi
	# Every record must be some matrix's: the eight inventories together are
	# the complete set this configuration produces. A record no inventory
	# names (a renamed or removed matrix) is evidence of nothing. A complete
	# recording removes it; a check fails, naming it. Only records, named by
	# their identity digest, are considered.
	local -A referenced=()
	local record digest stale=0
	for index in "${!suffixes[@]}"; do
		for layer in fast exhaustive; do
			while IFS= read -r line; do
				referenced[$line]=1
			done <"$logs/${index}-${layer}.inventory"
		done
	done
	if [[ "$action" == record ]]; then baseline="$PWD/tests/data/costs"; fi
	for record in "$baseline"/*.txt; do
		digest="${record##*/}"
		digest="${digest%.txt}"
		[[ "$digest" =~ ^[0-9a-f]{16}$ ]] || continue
		# Configuration is part of record identity. This invocation has no
		# authority to prune another configuration's evidence or unknown files.
		IFS= read -r header <"$record" || header=''
		[[ "$header" == $'#\tconfiguration\t'"$DCBOR_CONFIGURATION" ]] || continue
		if [[ ! -v "referenced[$digest]" ]]; then
			if [[ "$action" == record ]]; then
				rm -- "$record"
				echo "$record: removed, no matrix of this configuration records it"
			else
				echo "$record: no matrix of this configuration records it" >&2
				stale=1
			fi
		fi
	done
	printf 'Cost evidence logs: %s\n' "$logs"
	return "$stale"
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

status=0
expected=$'#\tconfiguration\t'"$DCBOR_CONFIGURATION"
for suffix in "${suffixes[@]}"; do
	paths=("tests/data/admission-traces${suffix}.txt")
	for family in "${families[@]}"; do
		paths+=("tests/data/tightness/${family}${suffix}.txt")
	done
	if [[ "$suffix" == .custom-std* ]]; then
		for family in "${custom_std_families[@]}"; do
			paths+=("tests/data/tightness/${family}${suffix}.txt")
		done
	fi
	for path in "${paths[@]}"; do
		if [[ ! -s "$path" ]]; then
			echo "$path: missing or empty evidence" >&2
			status=1
			continue
		fi
		# A header alone is not a measurement. Detailed outcome and row
		# validation remains in the Rust recorders, the single schema owners.
		{
			IFS= read -r header || header=''
			IFS= read -r first_measurement || first_measurement=''
		} <"$path"
		if [[ "$header" != "$expected" ]]; then
			echo "$path: stale or missing configuration" >&2
			echo "  expected: $expected" >&2
			echo "  recorded: $header" >&2
			status=1
		fi
		if [[ -z "$first_measurement" ]]; then
			echo "$path: no measured evidence after the configuration" >&2
			status=1
		fi
	done
done
exit "$status"
