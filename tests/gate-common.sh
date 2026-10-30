# Sourced by the evidence gates (tests/miri-owned.sh, tests/reach-map.sh,
# tests/mutation-evidence.sh): their one definition of an input closure, of
# the mutation domains' features, of the Miri gate's selection and models,
# of the tests a suite runs under Miri, and of what a passing run and an
# aborting one are. Run from the repository root in the configured
# development shell.
# shellcheck shell=bash

# Every input a gate's evidence depends on, one digest line each: the
# sources (the crate, the derive crate, the tests, their registries and
# records), the manifests, the flake and its patches, and the locks.
snapshot() {
	find src dcbor-derive/src tests -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.txt' -o -name '*.sh' -o -name '*.py' -o -name '*.json' \) -print0 |
		LC_ALL=C sort -z | xargs -0 sha256sum
	sha256sum Cargo.toml flake.nix nix/*.patch
	for file in Cargo.lock flake.lock; do
		if [[ -f "$file" ]]; then sha256sum "$file"; fi
	done
}

# The identity of a gate's run: the snapshot, the shell's configuration
# (the toolchain and fork revisions), the compiler and Cargo, and each line
# the caller adds (its features, flags and selection), digested. Writes
# `$1/identity-inputs.txt` and `$1/identity.txt`; the extra lines are read
# from standard input.
identity() {
	local logs="$1"
	{
		source_identity || return 1
		cat
	} >"$logs/identity-inputs.txt"
	sha256sum "$logs/identity-inputs.txt" | cut -d' ' -f1 >"$logs/identity.txt"
}

# What every gate's identity begins with, whatever the gate: the snapshot,
# the shell's configuration, the toolchain's store path (its components, the
# forked library, miri, llvm-tools, change it without changing its version),
# the compiler and Cargo. Two gates' evidence combines only when this part
# of their identities is equal (`same_source`).
source_identity() {
	: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
	snapshot
	printf 'configuration\t%s\n' "$DCBOR_CONFIGURATION"
	printf 'toolchain\t%s\n' "$(rustc --print sysroot)"
	rustc -vV
	cargo -V
}

# Whether the gate whose logs are `$1` ran over this source and toolchain:
# its identity's inputs begin with exactly this `source_identity`.
same_source() {
	local current lines
	current="$(source_identity)" || return 1
	lines="$(wc -l <<<"$current")"
	[[ -s "$1/identity-inputs.txt" ]] &&
		[[ "$(head -n "$lines" "$1/identity-inputs.txt")" == "$current" ]]
}

# Host isolation stays on: entropy, the environment and clocks are Miri's
# deterministic emulation, its entropy drawn from the seed's RNG, so a run is
# a function of its inputs and its seed. Disabling isolation would hand the
# interpreted test the host's randomness (std's `RandomState`, so every
# hash map's layout), its clock and its whole environment, and would make
# `-Zmiri-env-forward` a no-op. No selected test reads a file: the one
# recorded oracle a selected test reads, a tightness family's record
# (`tests/data/tightness`), is compiled in (`src/bounded.rs`, `variant!`).
#
# Miri forwards one variable per flag: a comma-separated list would name a
# single variable that does not exist, and each would silently fall back to
# its default inside the interpreter. DCBOR_RIGOR selects the verification
# layer, DCBOR_CLASS_COVERAGE the class inventory, DCBOR_WITNESS the witness
# sizes; each is forwarded, and nothing else of the host's environment is
# visible.
#
# Alignment is checked symbolically: against the alignment each allocation
# was requested with and the offset into it, not the integer address, which
# can satisfy an alignment by chance. Cursors stored in a `Slot`'s inline
# bytes, and values placed in records and metadata blocks, are checked
# against the alignment their storage guarantees.
MIRI_STRICT="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-env-forward=DCBOR_RIGOR -Zmiri-env-forward=DCBOR_CLASS_COVERAGE -Zmiri-env-forward=DCBOR_WITNESS"

# The aliasing models every Miri verdict is given under.
MIRI_MODELS=(stacked tree)

# The seeds a `race` suite's tests run under, one Miri process each
# (`-Zmiri-seed`): the seed's RNG picks the thread schedule (preemption at
# basic-block ends, the next thread when one blocks), allocation addresses
# and weak-memory outcomes, so each seed is one schedule explored. One run
# is one execution; a race test's claim rests on as many as are run here,
# not on every interleaving. DCBOR_MIRI_SEEDS, a positive count, 64 by
# default (the range Miri's own `-Zmiri-many-seeds` defaults to); the seeds
# are 0 through one less.
miri_seeds() {
	local count="${DCBOR_MIRI_SEEDS:-64}"
	if ! [[ "$count" =~ ^[1-9][0-9]*$ ]]; then
		printf 'DCBOR_MIRI_SEEDS=%s: a positive number of seeds\n' "$count" >&2
		return 2
	fi
	seq 0 $((count - 1))
}

# One progress line of a gate, on standard output: a timestamp, then the
# event (PLAN, BUILD, BUILT, START, PASS, FAIL, DONE) and its subject, so a
# gate's log shows what is planned, what is running and since when, and
# how each run ended, while it runs.
event() {
	printf '%s %s\n' "$(date +%FT%T%z)" "$*"
}

# Miri's sysroot and build cache, keyed by the toolchain (its store path, as
# `rustc --print sysroot` names it). cargo-miri keeps one sysroot for every
# toolchain unless MIRI_SYSROOT names one (cargo-miri setup.rs), rebuilds it
# when the toolchain changes, and cargo's freshness check of the build cache
# does not cover the sysroot: dependencies built against a previous
# toolchain's std are then reused and refused by rustc as missing crates
# (E0463). A cache per toolchain holds only artifacts of its own std. With
# MIRI_SYSROOT set, `cargo miri test` skips setup and expects the sysroot
# built, so this builds it (`cargo miri setup`, cached when unchanged).
# Every Miri run of the gates is `miri_command`'s command, after this.
miri_prepare() {
	local toolchain
	toolchain="$(basename "$(rustc --print sysroot)")" || return 1
	MIRI_TARGET_DIR="$PWD/target/miri-toolchains/$toolchain"
	export MIRI_SYSROOT="$MIRI_TARGET_DIR/sysroot"
	cargo miri setup
}

# The command every Miri run of the gates starts with, into the array
# `miri_cmd`: `cargo miri test` with the toolchain's own build cache
# (`--target-dir`, to which cargo-miri appends `miri`: util.rs
# `get_target_dir`). An array, not a function, so a run can be timed by GNU
# `time`, which executes programs. Refused before `miri_prepare`.
miri_command() {
	: "${MIRI_TARGET_DIR:?call miri_prepare before running Miri}"
	: "${MIRI_SYSROOT:?call miri_prepare before running Miri}"
	miri_cmd=(cargo miri test --target-dir "$MIRI_TARGET_DIR")
}

# The MIRIFLAGS of model `$1`, strict provenance included, the caller's own
# MIRIFLAGS after them.
miri_flags() {
	case "$1" in
	stacked) printf '%s %s' "$MIRI_STRICT" "${MIRIFLAGS:-}" ;;
	tree) printf '%s -Zmiri-tree-borrows %s' "$MIRI_STRICT" "${MIRIFLAGS:-}" ;;
	*)
		printf 'unknown Miri model: %s; the models are %s\n' "$1" "${MIRI_MODELS[*]}" >&2
		return 2
		;;
	esac
}

# The cargo features of mutation domain `$1`, into the array `features`:
# every feature, or the no_std build. Unknown domains are refused.
domain_features() {
	case "$1" in
	all-features) features=(--all-features) ;;
	no_std) features=(--no-default-features --features no_std) ;;
	*)
		printf 'unknown mutation domain: %s; the domains are all-features and no_std\n' "$1" >&2
		return 2
		;;
	esac
}

# Each suite of tests/miri-suites.txt: calls `$1` with the suite, its base
# name (unique across domains), its filter, its kind (`test`, `race` or
# `abort`), its domain, then its cargo selection, the domain's features
# first. A `race` suite is an integration test binary whose tests race
# threads: Miri runs each once per seed (`miri_seeds`), each seed a schedule
# of its own. Unknown domains and targets are refused.
each_suite() {
	local callback="$1" domain target suite filter base kind features
	local selection
	while read -r domain target suite filter; do
		case "$domain" in
		'' | '#'*) continue ;;
		esac
		domain_features "$domain" || return 2
		case "$target" in
		lib)
			selection=("${features[@]}" --lib)
			filter="$suite"
			kind="test"
			;;
		test)
			selection=("${features[@]}" --test "$suite")
			kind="test"
			;;
		race)
			selection=("${features[@]}" --test "$suite")
			kind="race"
			;;
		abort)
			selection=("${features[@]}" --test "$suite")
			kind="abort"
			;;
		*)
			printf 'unknown Miri target: %s\n' "$target" >&2
			return 2
			;;
		esac
		base="$domain-$suite${filter:+-$filter}"
		# Called plainly: under `||` the callback's body would run with
		# errexit suspended.
		"$callback" "$suite" "$base" "$filter" "$kind" "$domain" "${selection[@]}"
	done <tests/miri-suites.txt
}

# Whether test `$2` is one a selection line of filter `$1` names: the test
# itself, or a test of the module it names (`a::b` names `a::b::c`; a filter
# ending in `::` names that module's tests). libtest's filter matches any
# substring, so `hash_map_schema::t` also matches `std_hash_map_schema::t`; a
# line selects only what it names.
names_test() {
	local filter="$1" test="$2"
	case "$filter" in
	'') return 0 ;;
	*::) [[ "$test" == "$filter"* ]] ;;
	*) [[ "$test" == "$filter" || "$test" == "$filter::"* ]] ;;
	esac
}

# The tests of kind `$3` suite selection `$4...` runs under Miri, by full
# name, narrowed by filter `$2` to the tests it names (`names_test`), written
# to `$1`, nonempty. A test the filter matches only as a substring of its
# name is dropped from this line, and written to `$1.unnamed`: a test the gate
# runs has a line naming it. Of kind `test`, those Miri ignores are excluded
# (a `cfg_attr(miri, ignore)` drops out here); of kind `abort`, the ignored
# tests are the scenarios, each ending its own process. Listing runs in the
# interpreter, so it is Miri's own view of the suite.
listed_under_miri() {
	local out="$1" filter="$2" kind="$3" all ignored listed test
	shift 3
	local narrowed=() miri_cmd
	if [[ -n "$filter" ]]; then narrowed=("$filter"); fi
	miri_command || return 2
	ignored="$(MIRIFLAGS="$(miri_flags stacked)" "${miri_cmd[@]}" "$@" -- "${narrowed[@]}" --ignored --list --format terse 2>>"$out.err")" || return 1
	case "$kind" in
	test | race)
		all="$(MIRIFLAGS="$(miri_flags stacked)" "${miri_cmd[@]}" "$@" -- "${narrowed[@]}" --list --format terse 2>>"$out.err")" || return 1
		listed="$(LC_ALL=C comm -23 \
			<(sed -n 's/: test$//p' <<<"$all" | LC_ALL=C sort) \
			<(sed -n 's/: test$//p' <<<"$ignored" | LC_ALL=C sort))"
		;;
	abort) listed="$(sed -n 's/: test$//p' <<<"$ignored" | LC_ALL=C sort)" ;;
	*)
		printf 'unknown suite kind: %s\n' "$kind" >&2
		return 2
		;;
	esac
	: >"$out"
	: >"$out.unnamed"
	while IFS= read -r test; do
		[[ -z "$test" ]] && continue
		if names_test "$filter" "$test"; then
			printf '%s\n' "$test" >>"$out"
		else
			printf '%s\n' "$test" >>"$out.unnamed"
		fi
	done <<<"$listed"
	if [[ ! -s "$out" ]]; then
		printf 'the line of filter %s names no test this suite runs under Miri\n' "${filter:-(none)}" >>"$out.err"
		return 1
	fi
}

# The libtest arguments that select test `$2` of a suite of kind `$1`: an
# abort scenario is an ignored test.
selecting() {
	case "$1" in
	test | race) printf '%s\n' --exact "$2" ;;
	abort) printf '%s\n' --ignored --exact "$2" ;;
	*)
		printf 'unknown suite kind: %s\n' "$1" >&2
		return 2
		;;
	esac
}

# A successful empty libtest selection is not qualification.
executed() {
	grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "$1"
}

# A native run of an abort scenario through cargo, log `$1`: the test binary
# killed by SIGABRT (cargo-util's `exit_status_to_string`).
aborted_natively() {
	grep -Fq 'signal: 6, SIGABRT' "$1"
}

# A Miri run of an abort scenario, log `$1`: the interpreted program
# aborted (Miri's `TerminationInfo::Abort`, reported as an abnormal
# termination), and Miri reported neither undefined behavior nor an
# unsupported operation, which also end a run.
aborted_under_miri() {
	grep -Fq 'abnormal termination' "$1" &&
		! grep -Fq 'Undefined Behavior' "$1" &&
		! grep -Fq 'unsupported operation' "$1"
}
