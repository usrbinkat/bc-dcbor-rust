#!/usr/bin/env bash
# The reach map: which test of the Miri gate's selection (tests/miri-suites.txt)
# executes which code of this crate, each test run alone, instrumented, as
# Miri runs it: in its suite's mutation domain's build, the tests Miri lists
# (those ignored under Miri drop out; an abort suite's scenarios are its
# ignored tests), the same rigor, the same boundary-minimal witnesses
# (DCBOR_WITNESS=minimal), no `cfg(miri)` divergence (tests/unsafe_census.rs
# refuses one in a suite). Miri checks the paths it executes and nothing
# else, so a mutant is judged under Miri on exactly the tests of its domain
# whose execution reaches its mutated region (tests/mutation-evidence.py,
# `miri-plan`).
#
# Coverage is LLVM's source-based instrumentation of the workspace crates
# (cargo-llvm-cov's rustc wrapper), linked against the forked std with the
# profile runtime built beside it (DCBOR_PROFILER=1, compiler-rt of the
# compiler's own LLVM; flake.nix), read by that LLVM's llvm-profdata and
# llvm-cov. Profiles are written in continuous mode (`%c`): the counters are
# the profile file's own mapped pages, so a scenario that aborts keeps the
# coverage it reached, which a profile written at exit would lose. On ELF the
# runtime requires the compiler's counter relocation for it
# (`-runtime-counter-relocation`, compiler-rt InstrProfilingFile.c), passed
# to every crate this build compiles. The census (tests/unsafe_census.rs)
# names the trust boundaries: every function of a module holding `unsafe`,
# or of a descendant, outside test code (`cfg(test)`, never mutated), must be
# reached by some test Miri runs, or the map fails.
#
# Each test also runs at the full witness sizes the native layers run
# (DCBOR_WITNESS=full): its minimal run must execute every region of this
# crate its full run executes, or the map fails. A witness resized for Miri
# keeps every path its full size takes.
#
# Writes, in DCBOR_REACH_DIR (a new directory under TMPDIR by default):
# identity.txt, census.jsonl, each suite's Miri-listed tests (<base>.tests),
# kind (<base>.kind) and domain (<base>.domain), each test's reached regions
# at minimal sizes (reach/<base>/<index>.json) and at full sizes
# (reach-full/<base>/<index>.json), the functions of every instrumented
# binary (functions/<base>.json), and reach.json, the map the campaign's
# Miri layer reads.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
: "${TMPDIR:?required: the reach map's output directory}"
for tool in cargo cargo-llvm-cov rustc python3 sha256sum; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Reach map prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
		exit 127
	fi
done
out="${DCBOR_REACH_DIR:-$(mktemp -d "$TMPDIR/dcbor-reach.XXXXXX")}"
mkdir -p "$out"
echo "reach map: $out"
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
# The coverage build's own flags: nothing from the caller's environment.
counter_relocation="-C llvm-args=-runtime-counter-relocation"
{
	printf 'rigor\t%s\twitness\t%s\n' "$DCBOR_RIGOR" "$DCBOR_WITNESS"
	printf 'compared\tfull\n'
	printf 'coverage\t%s\tRUSTFLAGS\t%s\n' "$(cargo llvm-cov --version)" "$counter_relocation"
} | identity "$out"
echo "identity: $(cat "$out/identity.txt")"

# The trust boundaries.
DCBOR_UNSAFE_CENSUS="$out/census.jsonl" cargo test --all-features --test unsafe_census -- \
	--exact every_unsafe_trust_boundary_of_this_crate_is_found >"$out/census.log" 2>&1 || {
	cat "$out/census.log"
	exit 1
}

# Every suite's tests as Miri lists them, before the coverage environment
# is loaded: listing runs in the interpreter, uninstrumented, in the
# toolchain's own Miri sysroot and build cache (tests/gate-common.sh).
miri_prepare >"$out/miri-setup.log" 2>&1 || {
	cat "$out/miri-setup.log"
	exit 1
}
bases=()
list_suite() {
	local base="$2" filter="$3" kind="$4" domain="$5"
	shift 5
	listed_under_miri "$out/$base.tests" "$filter" "$kind" "$@" || {
		echo "the tests of $base could not be listed under Miri: $out/$base.tests.err" >&2
		exit 1
	}
	printf '%s\n' "$kind" >"$out/$base.kind"
	printf '%s\n' "$domain" >"$out/$base.domain"
	bases+=("$base")
	planned=$((planned + $(wc -l <"$out/$base.tests")))
}
planned=0
each_suite list_suite
event "PLAN ${#bases[@]} suites, $planned tests, $((planned * 2)) test runs (minimal and full witness sizes)"

# The instrumented environment, in the workspace's own target directory:
# the profile runtime joins the built standard library
# (DCBOR_PROFILER=1, build-std's `profiler_builtins`), which changes the
# standard library's identity and so every crate's hash built on it, so
# instrumented artifacts sit beside the gates' uninstrumented ones and never
# replace them. `show-env` names the workspace `target` too
# (CARGO_LLVM_COV_TARGET_DIR, CARGO_LLVM_COV_BUILD_DIR).
export DCBOR_PROFILER=1
eval "$(cargo llvm-cov show-env --sh)"
export RUSTFLAGS="$counter_relocation"
unset CARGO_ENCODED_RUSTFLAGS
tools="$(rustc --print target-libdir)/../bin"
for tool in llvm-profdata llvm-cov; do
	if [[ ! -x "$tools/$tool" ]]; then
		echo "$tool is missing from the toolchain's llvm-tools ($tools)" >&2
		exit 127
	fi
done

# One test of kind `$4` of suite `$2`'s binary `$1`, its index `$3`, run
# alone at witness sizes `$5`: its profile merged and the regions it
# executed written to reach/ (minimal, the sizes Miri runs) or reach-full/
# (full, the native layers' sizes). A `test` must pass; an `abort` scenario
# must be killed by SIGABRT (exit status 134 through the shell).
reach_test() {
	local exe="$1" base="$2" index="$3" kind="$4" sizes="$5" test="$6" raw reach status
	case "$sizes" in
	minimal) reach="reach" ;;
	full) reach="reach-full" ;;
	*)
		echo "unknown witness sizes: $sizes" >&2
		exit 2
		;;
	esac
	raw="$out/raw/$base/$sizes"
	mkdir -p "$raw" "$out/$reach/$base"
	local select=() started=$SECONDS
	mapfile -t select < <(selecting "$kind" "$test")
	# Uncaptured: each matrix reports its stages and cases into the run's
	# log as it runs (tests/support/rigor.rs `Progress`).
	event "START $base $test $sizes ($raw/$index.log)"
	status=0
	DCBOR_WITNESS="$sizes" LLVM_PROFILE_FILE="$raw/$index-%p%c.profraw" "$exe" "${select[@]}" \
		--nocapture --test-threads=1 >"$raw/$index.log" 2>&1 || status=$?
	case "$kind:$status" in
	test:0 | abort:134) ;;
	*)
		event "FAIL $base $test $sizes: status $status uninterpreted, instrumented ($((SECONDS - started))s, $raw/$index.log)"
		exit 1
		;;
	esac
	"$tools/llvm-profdata" merge -sparse "$raw/$index"-*.profraw -o "$raw/$index.profdata"
	"$tools/llvm-cov" export -format=text -instr-profile="$raw/$index.profdata" "$exe" |
		python3 tests/reach-map.py regions "$PWD" >"$out/$reach/$base/$index.json"
	rm -f "$raw/$index"-*.profraw
	event "DONE $base $test $sizes ($((SECONDS - started))s)"
}

# One suite: its test binary built instrumented in its domain's build, then
# every Miri-listed test run alone at both witness sizes.
reach_suite() {
	local base="$2" kind="$4" exe index test started=$SECONDS
	shift 5
	event "BUILD $base ($out/$base.build.log)"
	exe="$(cargo test "$@" --no-run --message-format=json 2>>"$out/$base.build.log" |
		python3 tests/reach-map.py executable)" || {
		event "FAIL $base: the instrumented binary could not be built ($out/$base.build.log)"
		exit 1
	}
	event "BUILT $base ($((SECONDS - started))s, $exe)"
	mkdir -p "$out/functions"
	index=0
	while IFS= read -r test; do
		reach_test "$exe" "$base" "$index" "$kind" minimal "$test"
		reach_test "$exe" "$base" "$index" "$kind" full "$test"
		index=$((index + 1))
	done <"$out/$base.tests"
	# Every function the binary instruments, executed or not, from the
	# profile of its first test: the census's coverage target is checked
	# against them.
	"$tools/llvm-cov" export -format=text -instr-profile="$out/raw/$base/minimal/0.profdata" "$exe" |
		python3 tests/reach-map.py functions "$PWD" >"$out/functions/$base.json"
}
each_suite reach_suite

event "INDEX $out/reach.json"
python3 tests/reach-map.py index "$out" "${bases[@]}"
event "DONE reach map: $out/reach.json"
