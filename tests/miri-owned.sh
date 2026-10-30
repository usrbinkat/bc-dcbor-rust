#!/usr/bin/env bash
# The Miri gate, and the one Miri runner of this repository: the gate itself,
# and (with --judge) the mutation campaign's Miri layer, which judges a
# mutant on the tests that reach it (tests/mutation-evidence.sh).
#
# Run in the configured development shell, whose cargo-miri and sysroot are
# built from the patched library the flake installs. Do not substitute a
# normal cargo test run. Each suite runs in its mutation domain's build
# (tests/miri-suites.txt): every feature, where the ordered-collection
# schemas, whose stepped cursors live in the engine's Slot, exist only with
# custom-std-collections; or the no_std build, whose abort only it compiles.
#
# Every test runs under strict provenance: an integer cast to a pointer is an
# error, not a permissive fallback, so a pointer that loses its provenance
# across a suspension fails the gate. Each runs under both aliasing models,
# Stacked Borrows (Miri's default) and Tree Borrows, which differ on the
# raw-pointer projections records and metadata blocks make. Flags the caller
# sets in MIRIFLAGS follow the gate's own (tests/gate-common.sh).
#
# DCBOR_RIGOR selects the verification layer (fast, the default, or
# exhaustive). DCBOR_WITNESS is `minimal`: Miri's evidence is about the paths
# and transition classes a test executes, not its data volume, so each
# witness runs at the boundary-minimal size of every class it covers; the
# native layers keep full sizes, and the reach map requires the minimal
# sizes to execute every region the full ones do (tests/reach-map.sh). Both
# are forwarded into the interpreter. Test output is not captured: each
# matrix reports its stages and cases as it runs, so a slow case and a
# stalled one are told apart in the log.
#
# A suite of kind `abort` holds scenarios that end their own process: each
# runs alone and passes when it aborts, natively by SIGABRT, under Miri by
# its abnormal termination with no undefined behavior reported. A suite of
# kind `race` holds tests that race threads: each runs once per seed
# (tests/gate-common.sh, `miri_seeds`), each seed one schedule, its own
# process, verdict and results row.
#
# Both modes require DCBOR_REACH_DIR, a passing reach map of this source and
# toolchain (tests/reach-map.sh), checked before anything runs. The gate
# lists every selection line first and runs nothing unless each names a
# test; it publishes its outcome per test, model and domain in
# results.tsv under its identity.
#
# Usage:
#   tests/miri-owned.sh                          the gate
#   tests/miri-owned.sh --judge PLAN OUT BASELINE
#       judge the mutants of PLAN (tests/mutation-evidence.py, `miri-plan`)
#       against BASELINE, a gate run of the same identity, writing their
#       verdicts to OUT/verdicts.tsv
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo rustc patch time sha256sum; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Miri gate prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
		exit 127
	fi
done
mode=gate
if [[ "${1:-}" == --judge ]]; then
	if (($# != 4)); then
		echo "usage: tests/miri-owned.sh --judge PLAN OUT BASELINE" >&2
		exit 2
	fi
	mode=judge
	plan="$2"
	logs="$3"
	baseline="$4"
elif (($# != 0)); then
	echo "usage: tests/miri-owned.sh [--judge PLAN OUT BASELINE]" >&2
	exit 2
else
	logs="${MIRI_LOG_DIR:-${TMPDIR:?required, or MIRI_LOG_DIR: the gate log directory}/miri-owned}"
fi
mkdir -p "$logs" || exit 2
rigor="${DCBOR_RIGOR:-fast}"
case "$rigor" in
fast | exhaustive) ;;
*)
	echo "DCBOR_RIGOR=$rigor: the layers are fast and exhaustive" >&2
	exit 2
	;;
esac
export DCBOR_RIGOR="$rigor"
export DCBOR_CLASS_COVERAGE=1
export DCBOR_WITNESS=minimal
seeds=()
mapfile -t seeds < <(miri_seeds) || exit 2
((${#seeds[@]} > 0)) || exit 2
echo "rigor: $rigor, witnesses: $DCBOR_WITNESS, race seeds: ${#seeds[@]}"

# The selection is evidence only with a reach map over this source and
# toolchain that passed (tests/reach-map.sh): every function of a module
# holding `unsafe` reached by a test of this selection, and the minimal
# witnesses executing every region the full ones do. Set cover chose the
# fewest tests, so any change to a test can leave a function unreached; a
# map of another source proves nothing about this one. Checked before
# anything runs, in both modes, and named in the run's identity.
: "${DCBOR_REACH_DIR:?required: a passing reach map of this source (tests/reach-map.sh)}"
if [[ "$(cat "$DCBOR_REACH_DIR/verdict" 2>/dev/null)" != pass ]]; then
	event "FAIL the reach map $DCBOR_REACH_DIR did not pass; nothing was run"
	exit 1
fi
if ! same_source "$DCBOR_REACH_DIR"; then
	event "FAIL the reach map $DCBOR_REACH_DIR is of another source or toolchain; nothing was run"
	exit 1
fi
event "REACH $DCBOR_REACH_DIR, identity $(cat "$DCBOR_REACH_DIR/identity.txt"), same source"

# The run's identity: the input closure (the suite list and each suite's
# domain among it), the reach map it rests on, the rigor, the witness sizes,
# the race suites' seeds and each model's flags. A judgement counts only
# against a baseline of the same identity: the same sources, locks, features,
# forked std, reach map, seeds and flags.
for model in "${MIRI_MODELS[@]}"; do
	printf 'model\t%s\tMIRIFLAGS\t%s\n' "$model" "$(miri_flags "$model")"
done | {
	printf 'reach\t%s\n' "$(cat "$DCBOR_REACH_DIR/identity.txt")"
	printf 'rigor\t%s\twitness\t%s\n' "$DCBOR_RIGOR" "$DCBOR_WITNESS"
	printf 'race seeds\t%s\n' "${seeds[*]}"
	cat
} | identity "$logs"
echo "identity: $(cat "$logs/identity.txt")"

# The toolchain's own Miri sysroot and build cache (tests/gate-common.sh).
miri_prepare >"$logs/miri-setup.log" 2>&1 || {
	cat "$logs/miri-setup.log"
	exit 1
}

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

# The outcome class of a Miri run that did not do what its kind requires,
# from its log `$1`: undefined behavior reported, an operation Miri does not
# support, or any other failure (a failed assertion, a panic, a scenario
# that returned instead of aborting).
outcome_of() {
	if grep -Fq 'Undefined Behavior' "$1"; then
		echo undefined_behavior
	elif grep -Fq 'unsupported operation' "$1"; then
		echo unsupported
	else
		echo failed
	fi
}

# Whether the run of log `$2`, of suite kind `$1`, under Miri when `$3` is
# `miri`, did what its kind requires: a test passed, or a scenario aborted.
fulfilled() {
	case "$1:$3" in
	test:* | race:*) executed "$2" ;;
	abort:native) aborted_natively "$2" ;;
	abort:miri) aborted_under_miri "$2" ;;
	*)
		echo "unknown suite kind or runner: $1, $3" >&2
		return 2
		;;
	esac
}

# Miri interprets one thread at a time, so a suite run in one process takes
# the sum of its tests' interpreted times, and the slowest suite bounded the
# whole gate. Each test therefore runs in a Miri process of its own, under
# each model: the gate's critical path is its slowest single test. Runs
# share DCBOR_MIRI_JOBS slots (the host's processors by default), handed out
# through a token pipe. A run's verdict is its own file: a background job
# cannot set the gate's status, which is derived from every verdict once all
# have finished. Each run's peak memory and duration are measured beside its
# verdict, from which the slots are sized.
jobs="${DCBOR_MIRI_JOBS:-$(nproc)}"
if ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
	echo "DCBOR_MIRI_JOBS=$jobs: a positive number of concurrent runs" >&2
	exit 2
fi
echo "concurrent runs: $jobs"
tokens="$logs/.tokens"
rm -f "$tokens"
mkfifo "$tokens" || exit 2
exec 3<>"$tokens"
rm -f "$tokens"
for ((slot = 0; slot < jobs; slot++)); do
	printf 'slot\n' >&3
done
take() {
	read -r -u 3 _
}
give() {
	printf 'slot\n' >&3
}

# One run of a test of kind `$5` under one model, under seed `$6` (`-` for
# Miri's default seed): its own Miri process, its own log, verdict, outcome,
# measurement and class inventory, in `$1` by `$3`, its run index there.
test_run() {
	local dir="$1" model="$2" index="$3" test="$4" kind="$5" seed="$6" flags started
	shift 6
	flags="$(miri_flags "$model")" || return 2
	if [[ "$seed" != - ]]; then
		flags="$flags -Zmiri-seed=$seed"
	fi
	local select=()
	mapfile -t select < <(selecting "$kind" "$test") || return 2
	started=$SECONDS
	# GNU time, through env: the bash keyword of that name measures nothing
	# the gate can record. An abort scenario's run fails by design; its
	# verdict is whether it aborted.
	local miri_cmd
	miri_command || return 2
	if [[ "$seed" != - ]]; then
		test="$test, seed $seed"
	fi
	event "START $dir $test ($dir/$index.log)"
	env MIRIFLAGS="$flags" time -f '%M %e' -o "$dir/$index.measure" \
		"${miri_cmd[@]}" "$@" -- "${select[@]}" --nocapture --test-threads=1 >"$dir/$index.log" 2>&1
	local status=$?
	if { [[ "$kind" == abort ]] || ((status == 0)); } &&
		fulfilled "$kind" "$dir/$index.log" miri &&
		inventory "$dir/$index.log" "$dir/$index.classes"; then
		event "PASS $dir $test ($((SECONDS - started))s, $(tail -n 1 "$dir/$index.measure") kB s)"
		echo pass >"$dir/$index.outcome"
		echo pass >"$dir/$index.verdict"
	else
		outcome_of "$dir/$index.log" >"$dir/$index.outcome"
		event "FAIL $dir $test: $(cat "$dir/$index.outcome") ($((SECONDS - started))s, $dir/$index.log)"
		echo fail >"$dir/$index.verdict"
	fi
}

# A model's verdict over a suite: every run passed, and the union of their
# class inventories equals the native run's.
model_verdict() {
	local base="$1" model="$2" count="$3" dir index
	dir="$logs/$base-$model"
	for ((index = 0; index < count; index++)); do
		if [[ "$(cat "$dir/$index.verdict" 2>/dev/null)" != pass ]]; then
			event "FAIL $base-$model: run $index ($(sed -n "$((index + 1))p" "$logs/$base.runs")) did not pass"
			echo fail >"$logs/$base-$model.verdict"
			return
		fi
	done
	cat "$dir"/*.classes | LC_ALL=C sort -u >"$logs/$base-$model.classes"
	if diff -u "$logs/$base-native.classes" "$logs/$base-$model.classes" >"$logs/$base-$model-coverage.diff"; then
		event "PASS $base-$model ($count tests), class coverage equals native"
		echo pass >"$logs/$base-$model.verdict"
	else
		event "FAIL $base-$model class coverage, $logs/$base-$model-coverage.diff"
		echo fail >"$logs/$base-$model.verdict"
	fi
}

# The native baseline of a suite of kind `$2`, its tests `$3...` up to `--`,
# then its selection: a `test` suite's tests in one process; an `abort`
# suite's scenarios each in a process of its own, since each ends it.
native_run() {
	local base="$1" kind="$2"
	shift 2
	local listed=()
	while [[ "$1" != -- ]]; do
		listed+=("$1")
		shift
	done
	shift
	case "$kind" in
	test | race)
		cargo test "$@" -- --exact "${listed[@]}" --nocapture --test-threads=1 >"$logs/$base-native.log" 2>&1 &&
			executed "$logs/$base-native.log"
		;;
	abort)
		local index=0 name
		: >"$logs/$base-native.log"
		for name in "${listed[@]}"; do
			cargo test "$@" -- --ignored --exact "$name" --nocapture --test-threads=1 \
				>"$logs/$base-native-$index.log" 2>&1
			cat "$logs/$base-native-$index.log" >>"$logs/$base-native.log"
			aborted_natively "$logs/$base-native-$index.log" || return 1
			index=$((index + 1))
		done
		;;
	*)
		echo "unknown suite kind: $kind" >&2
		return 2
		;;
	esac
}

# The runs of a suite of kind `$1` over its tests `$2...`, one line each,
# `test<TAB>seed`: a `race` suite's test once per seed, any other's once
# under Miri's default seed (`-`).
runs_of() {
	local kind="$1" test seed
	shift
	for test in "$@"; do
		if [[ "$kind" == race ]]; then
			for seed in "${seeds[@]}"; do
				printf '%s\t%s\n' "$test" "$seed"
			done
		else
			printf '%s\t-\n' "$test"
		fi
	done
}

# One suite: the tests the listing pass found it names (`$logs/$base.tests`),
# their native baseline, then every run of each (`runs_of`, written to
# `$logs/$base.runs`) under both models in processes of their own, then each
# model's verdict over the suite.
suite_run() {
	local suite="$1" base="$2" kind="$4" started passed count index model run test seed
	shift 5
	started=$SECONDS
	take
	local names=() runs=()
	mapfile -t names <"$logs/$base.tests"
	runs_of "$kind" "${names[@]}" >"$logs/$base.runs"
	mapfile -t runs <"$logs/$base.runs"
	event "PLAN $base: ${#names[@]} tests, ${#runs[@]} Miri runs under each of ${#MIRI_MODELS[@]} models"
	event "START $base-native ($logs/$base-native.log)"
	native_run "$base" "$kind" "${names[@]}" -- "$@" &&
		inventory "$logs/$base-native.log" "$logs/$base-native.classes"
	passed=$?
	give
	if ((passed != 0)); then
		event "FAIL $base-native ($((SECONDS - started))s, $logs/$base-native.log)"
		echo fail >"$logs/$base-native.verdict"
		return
	fi
	case "$suite" in
	owned_btree | owned_lifecycle_matrix | owned_pipeline_matrix | reclamation_owner)
		if [[ ! -s "$logs/$base-native.classes" ]]; then
			event "FAIL $base-native: missing class inventory"
			echo fail >"$logs/$base-native.verdict"
			return
		fi
		;;
	esac
	count=${#runs[@]}
	event "PASS $base-native ($((SECONDS - started))s, ${#names[@]} tests)"
	echo pass >"$logs/$base-native.verdict"
	for model in "${MIRI_MODELS[@]}"; do
		mkdir -p "$logs/$base-$model"
		index=0
		for run in "${runs[@]}"; do
			IFS=$'\t' read -r test seed <<<"$run"
			(
				take
				test_run "$logs/$base-$model" "$model" "$index" "$test" "$kind" "$seed" "$@"
				give
			) &
			index=$((index + 1))
		done
	done
	wait
	for model in "${MIRI_MODELS[@]}"; do
		model_verdict "$base" "$model" "$count"
	done
}

# The suite of base name `$1`, from tests/miri-suites.txt: its kind into
# `selected_kind`, its cargo selection into the array `selection`.
selection_of() {
	local wanted="$1"
	found_selection() {
		local base="$2" kind="$4"
		shift 5
		if [[ "$base" == "$wanted" ]]; then
			selected_kind="$kind"
			selection=("$@")
		fi
	}
	selected_kind=""
	selection=()
	each_suite found_selection || return 2
	((${#selection[@]} > 0))
}

# The mutation campaign's Miri layer: each mutant of the plan applied in
# place, judged on the tests that reach it under both models, then reverted.
# Plan lines are `mutant<TAB>index<TAB>name<TAB>diff` and
# `test<TAB>index<TAB>base<TAB>test`. A mutant is caught under Miri when any
# of its tests fails under either model, missed when all pass; without a
# baseline pass of every one of its tests under both models in BASELINE, of
# this run's identity, it is `no_baseline`.
judge() {
	if ! cmp -s "$baseline/identity.txt" "$logs/identity.txt"; then
		echo "the baseline $baseline is of another identity than this run: $(cat "$baseline/identity.txt" 2>/dev/null) and $(cat "$logs/identity.txt")" >&2
		exit 1
	fi
	snapshot >"$logs/source.sha256"
	local kind index name diff base test
	local -A names diffs
	local -a tests_of
	while IFS=$'\t' read -r kind index name diff; do
		case "$kind" in
		mutant)
			names[$index]="$name"
			diffs[$index]="$diff"
			;;
		test) tests_of[index]+="$name"$'\t'"$diff"$'\n' ;;
		*)
			echo "unknown plan line kind: $kind" >&2
			exit 2
			;;
		esac
	done <"$plan"
	applied=""
	restore() {
		if [[ -n "$applied" ]]; then
			patch -R -p0 --batch --fuzz=0 --no-backup-if-mismatch --quiet <"$applied" || exit 1
			applied=""
		fi
	}
	trap restore EXIT
	: >"$logs/verdicts.tsv"
	# An empty plan judges nothing; printf over no keys would yield one empty
	# index.
	local order=()
	if ((${#names[@]} > 0)); then
		mapfile -t order < <(printf '%s\n' "${!names[@]}" | LC_ALL=C sort -n)
	fi
	for index in "${order[@]}"; do
		name="${names[$index]}"
		diff="${diffs[$index]}"
		local outcome=missed_under_miri
		# Every run of every selected test, each seed of a race test, has a
		# baseline pass under both models.
		local runs_judged=()
		while IFS=$'\t' read -r base test; do
			[[ -z "$base" ]] && continue
			local found=0 at=0 listed seed
			while IFS=$'\t' read -r listed seed; do
				if [[ "$listed" == "$test" ]]; then
					found=1
					runs_judged+=("$base"$'\t'"$test"$'\t'"$seed")
					for model in "${MIRI_MODELS[@]}"; do
						if [[ "$(cat "$baseline/$base-$model/$at.verdict" 2>/dev/null)" != pass ]]; then
							outcome=no_baseline
						fi
					done
				fi
				at=$((at + 1))
			done <"$baseline/$base.runs"
			((found == 1)) || outcome=no_baseline
		done <<<"${tests_of[index]:-}"
		if [[ "$outcome" == no_baseline ]]; then
			printf '%s\t%s\n' "$name" "$outcome" >>"$logs/verdicts.tsv"
			event "NO_BASELINE $name"
			continue
		fi
		event "START mutant $index: $name"
		patch -p0 --batch --fuzz=0 --no-backup-if-mismatch --quiet <"$diff" || {
			echo "the mutant does not apply: $name ($diff)" >&2
			exit 1
		}
		applied="$diff"
		local dir="$logs/mutant-$index"
		local run=0 judged
		for judged in "${runs_judged[@]}"; do
			IFS=$'\t' read -r base test seed <<<"$judged"
			selection_of "$base" || {
				echo "the plan names a suite the gate does not run: $base" >&2
				exit 2
			}
			for model in "${MIRI_MODELS[@]}"; do
				mkdir -p "$dir/$model"
				printf '%s\t%s\t%s\n' "$base" "$test" "$seed" >"$dir/$model/$run.test"
				(
					take
					test_run "$dir/$model" "$model" "$run" "$test" "$selected_kind" "$seed" "${selection[@]}"
					give
				) &
			done
			run=$((run + 1))
		done
		wait
		restore
		snapshot | diff -u "$logs/source.sha256" - >/dev/null || {
			echo "the source differs from its snapshot after reverting $name" >&2
			exit 1
		}
		for model in "${MIRI_MODELS[@]}"; do
			for verdict in "$dir/$model"/*.verdict; do
				if [[ "$(cat "$verdict")" != pass ]]; then
					outcome=caught_under_miri
				fi
			done
		done
		printf '%s\t%s\n' "$name" "$outcome" >>"$logs/verdicts.tsv"
		event "${outcome^^} $name"
	done
	trap - EXIT
}

if [[ "$mode" == judge ]]; then
	judge
	exit 0
fi

# Every line of the selection listed under Miri before any test runs: each
# must name a test (`listed_under_miri`), and no test of one build may be
# named by two lines, so a mistyped or overlapping line fails the gate before
# it spends anything. A test a filter matches only as a substring is not run
# by that line, and is reported.
listing=()
planned=0
declare -A domain_of suite_of kind_of
list_line() {
	local suite="$1" base="$2" filter="$3" kind="$4" domain="$5"
	shift 5
	listing+=("$base")
	domain_of[$base]="$domain"
	suite_of[$base]="$suite"
	kind_of[$base]="$kind"
	rm -f "$logs/$base.tests.err"
	(
		take
		if listed_under_miri "$logs/$base.tests" "$filter" "$kind" "$@"; then
			echo pass >"$logs/$base.listed"
		else
			echo fail >"$logs/$base.listed"
		fi
		give
	) &
}
each_suite list_line || exit 2
wait
unlisted=0
declare -A named_by
for base in "${listing[@]}"; do
	if [[ "$(cat "$logs/$base.listed" 2>/dev/null)" != pass ]]; then
		event "FAIL $base: no test listed ($logs/$base.tests.err)"
		unlisted=1
		continue
	fi
	if [[ -s "$logs/$base.tests.unnamed" ]]; then
		event "UNNAMED $base: matched by substring, not run by this line: $(paste -sd' ' "$logs/$base.tests.unnamed")"
	fi
	while IFS= read -r test; do
		key="${domain_of[$base]} ${suite_of[$base]} $test"
		if [[ -v "named_by[$key]" ]]; then
			event "FAIL $base: $test is also named by ${named_by[$key]}"
			unlisted=1
		fi
		named_by[$key]="$base"
		if [[ "${kind_of[$base]}" == race ]]; then
			planned=$((planned + ${#seeds[@]}))
		else
			planned=$((planned + 1))
		fi
	done <"$logs/$base.tests"
done
if ((unlisted != 0)); then
	event "DONE the selection does not list; nothing was run"
	exit 1
fi
event "LISTED ${#listing[@]} lines, ${#named_by[@]} tests, $((planned * ${#MIRI_MODELS[@]})) Miri runs"

expected=()
gate_suite() {
	local base="$2"
	expected+=("$base-native" "${MIRI_MODELS[@]/#/$base-}")
	suite_run "$@" &
}
each_suite gate_suite || exit 2
wait

# The gate's result, published whole: one row per test, model and domain,
# its outcome class (pass, undefined_behavior, unsupported, failed, or
# not_run when its suite's native baseline failed or it never started), its
# seconds and peak memory; and one row per suite and runner, its verdict
# (the native baseline; each model's tests together with its class coverage
# equal to the native run's). Written beside the identity it was run under,
# then renamed into place.
publish_results() {
	local out="$logs/results.tsv" base model index test seed outcome peak seconds dir
	local temporary="$out.$$.tmp"
	{
		printf '#\tidentity\t%s\n' "$(cat "$logs/identity.txt")"
		printf 'domain\tline\trunner\ttest\tseed\toutcome\tseconds\tpeak_kB\n'
		for base in "${listing[@]}"; do
			for model in native "${MIRI_MODELS[@]}"; do
				outcome="$(cat "$logs/$base-$model.verdict" 2>/dev/null || echo not_run)"
				printf '%s\t%s\t%s\t(suite)\t-\t%s\t-\t-\n' "${domain_of[$base]}" "$base" "$model" "$outcome"
			done
			# A suite that never started wrote no runs: each of its tests'
			# runs is reported not run.
			if [[ ! -s "$logs/$base.runs" ]]; then
				local names=()
				mapfile -t names <"$logs/$base.tests"
				runs_of "${kind_of[$base]}" "${names[@]}" >"$logs/$base.runs"
			fi
			index=0
			while IFS=$'\t' read -r test seed; do
				for model in "${MIRI_MODELS[@]}"; do
					dir="$logs/$base-$model"
					outcome="$(cat "$dir/$index.outcome" 2>/dev/null || echo not_run)"
					peak=-
					seconds=-
					if [[ -s "$dir/$index.measure" ]]; then
						read -r peak seconds < <(tail -n 1 "$dir/$index.measure")
					fi
					printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${domain_of[$base]}" "$base" "$model" "$test" "$seed" "$outcome" "$seconds" "$peak"
				done
				index=$((index + 1))
			done <"$logs/$base.runs"
		done
	} >"$temporary" && mv "$temporary" "$out"
}

# Every expected run has a verdict, and every verdict passed: a run that
# never started (its suite's native run failed) is a failure, not an
# omission.
status=0
failed=0
for name in "${expected[@]}"; do
	if [[ "$(cat "$logs/$name.verdict" 2>/dev/null)" != pass ]]; then
		status=1
		failed=$((failed + 1))
	fi
done
publish_results || status=1
event "DONE ${#expected[@]} suite verdicts, $failed not passed; results $logs/results.tsv"
exit "$status"
