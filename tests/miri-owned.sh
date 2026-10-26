#!/usr/bin/env bash
# Run in an environment with cargo-miri and the matching compiler installed.
# Do not substitute a normal cargo test run for this gate. Every feature is
# enabled: the ordered-collection schemas, whose stepped cursors live in the
# engine's Slot, exist only with custom-std-collections, so Miri's sysroot
# must be built from the patched library the flake installs.
#
# Every suite runs under strict provenance: an integer cast to a pointer is
# an error, not a permissive fallback, so a pointer that loses its provenance
# across a suspension fails the gate. Each suite runs under both aliasing
# models, Stacked Borrows (Miri's default) and Tree Borrows, which differ on
# the raw-pointer projections records and metadata blocks make. Flags the
# caller sets in MIRIFLAGS follow the gate's own.
#
# DCBOR_RIGOR selects the verification layer (fast, the default, or
# exhaustive); Miri isolates the interpreted program from the environment,
# so it is forwarded explicitly, or every interpreted matrix would run its
# default layer whatever the caller chose. Test output is not captured: each
# matrix reports its stages and cases as it runs, so a slow case and a
# stalled one are told apart in the log while the gate runs.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
logs="${MIRI_LOG_DIR:-${TMPDIR:?set TMPDIR to the session scratchpad}/miri-owned}"
mkdir -p "$logs" || exit 2
status=0
rigor="${DCBOR_RIGOR:-fast}"
case "$rigor" in
fast | exhaustive) ;;
*)
	echo "DCBOR_RIGOR=$rigor: the layers are fast and exhaustive" >&2
	exit 2
	;;
esac
export DCBOR_RIGOR="$rigor"
echo "rigor: $rigor"
export DCBOR_CLASS_COVERAGE=1
strict="-Zmiri-strict-provenance -Zmiri-env-forward=DCBOR_RIGOR,DCBOR_CLASS_COVERAGE"

# Capture only the structured inventory emitted by the shared matrix and
# binding-simulation checks. Sort full records, never hashes or samples.
inventory() {
	local line
	while IFS= read -r line; do
		case "$line" in
		*DCBOR_CLASSES$'\t'*) printf 'DCBOR_CLASSES\t%s\n' "${line#*DCBOR_CLASSES$'\t'}" ;;
		*DCBOR_CLASS$'\t'*) printf 'DCBOR_CLASS\t%s\n' "${line#*DCBOR_CLASS$'\t'}" ;;
		esac
	done <"$1" | LC_ALL=C sort -u >"$2"
}

executed() {
	# A successful empty libtest selection is not qualification.
	grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "$1"
}
# Each line names a test binary and an optional test-name filter. The filters
# keep the resumable suite to the code whose unsafe operations are under
# test: the Slot cursors of BTreeMap, Map and symbolic CBOR; and the retained
# arena's staged growth, whose block is acquired, vacated into the arena and
# freed, refused at every admission and cancelled at every partial
# relocation. Fixed arrays are qualified by reclamation_owner, owned
# preparation by the owned suites.
while read -r target suite filter; do
	case "$target" in
	lib) selection=(--lib "$suite") ;;
	test)
		selection=(--test "$suite")
		if [[ -n "$filter" ]]; then selection+=("$filter"); fi
		;;
	*)
		echo "unknown Miri target: $target" >&2
		exit 2
		;;
	esac
	base="$suite${filter:+-$filter}"
	started=$SECONDS
	if cargo test --all-features "${selection[@]}" -- --nocapture --test-threads=1 >"$logs/$base-native.log" 2>&1 &&
		executed "$logs/$base-native.log" &&
		inventory "$logs/$base-native.log" "$logs/$base-native.classes"; then
		case "$suite" in
		owned_btree | owned_lifecycle_matrix | owned_pipeline_matrix | reclamation_owner)
			if [[ ! -s "$logs/$base-native.classes" ]]; then
				echo "FAIL $base-native: missing class inventory"
				status=1
				continue
			fi
			;;
		esac
		echo "PASS $base-native ($((SECONDS - started))s)"
	else
		echo "FAIL $base-native ($((SECONDS - started))s, $logs/$base-native.log)"
		status=1
		continue
	fi
	for model in stacked tree; do
		case "$model" in
		stacked) flags="$strict" ;;
		tree) flags="$strict -Zmiri-tree-borrows" ;;
		esac
		name="$suite${filter:+-$filter}-$model"
		started=$SECONDS
		if MIRIFLAGS="$flags ${MIRIFLAGS:-}" cargo miri test --all-features "${selection[@]}" -- --nocapture --test-threads=1 >"$logs/$name.log" 2>&1 &&
			executed "$logs/$name.log" &&
			inventory "$logs/$name.log" "$logs/$name.classes"; then
			if diff -u "$logs/$base-native.classes" "$logs/$name.classes" >"$logs/$name-coverage.diff"; then
				echo "PASS $name ($((SECONDS - started))s), class coverage equals native"
			else
				echo "FAIL $name class coverage, $logs/$name-coverage.diff"
				status=1
			fi
		else
			echo "FAIL $name ($((SECONDS - started))s, $logs/$name.log)"
			status=1
		fi
	done
done <<'SUITES'
lib bounded::decode::construction::in_place
test owned_input
test owned_inspection
test owned_decode
test owned_physical_failure terminal_tree_cleanup
test owned_btree
test owned_lifecycle_matrix
test owned_pipeline_matrix
test owned_pipeline_interleavings
test owned_public_contract
test owner_concurrency
test optional_admission
test reclamation_owner
test typed_lifecycle_floor
test typed_error_custody
test resumable_contract schema_encoding::ordered
test resumable_contract storage_cursor::
SUITES
exit "$status"
