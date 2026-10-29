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
	: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
	{
		snapshot
		printf 'configuration\t%s\n' "$DCBOR_CONFIGURATION"
		# The toolchain's store path: its components (the forked library,
		# miri, llvm-tools) change it without changing its version.
		printf 'toolchain\t%s\n' "$(rustc --print sysroot)"
		rustc -vV
		cargo -V
		cat
	} >"$logs/identity-inputs.txt"
	sha256sum "$logs/identity-inputs.txt" | cut -d' ' -f1 >"$logs/identity.txt"
}

# Miri forwards one variable per flag: a comma-separated list would name a
# single variable that does not exist, and each would silently fall back to
# its default inside the interpreter. DCBOR_RIGOR selects the verification
# layer, DCBOR_CLASS_COVERAGE the class inventory, DCBOR_WITNESS the witness
# sizes; every one is forwarded, so the interpreted test runs what the
# native one runs. Isolation is disabled (`IsolatedOp::Allow`, Miri's
# `-Zmiri-disable-isolation`) for the same reason: a test whose oracle is a
# recorded file (the tightness families, `tests/data/tightness`) reads it
# under Miri as it does natively, where isolation would end the run as an
# unsupported `open` before any assertion.
MIRI_STRICT="-Zmiri-strict-provenance -Zmiri-disable-isolation -Zmiri-env-forward=DCBOR_RIGOR -Zmiri-env-forward=DCBOR_CLASS_COVERAGE -Zmiri-env-forward=DCBOR_WITNESS"

# The aliasing models every Miri verdict is given under.
MIRI_MODELS=(stacked tree)

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
# name (unique across domains), its filter, its kind (`test` or `abort`), its
# domain, then its cargo selection, the domain's features first. Unknown
# domains and targets are refused.
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

# The tests of kind `$3` suite selection `$4...` runs under Miri, by full
# name, narrowed by filter `$2`, written to `$1`, nonempty. Of kind `test`,
# those Miri ignores are excluded (a `cfg_attr(miri, ignore)` drops out
# here); of kind `abort`, the ignored tests are the scenarios, each ending its
# own process. Listing runs in the interpreter, so it is Miri's own view of
# the suite.
listed_under_miri() {
	local out="$1" filter="$2" kind="$3" all ignored
	shift 3
	local narrowed=() miri_cmd
	if [[ -n "$filter" ]]; then narrowed=("$filter"); fi
	miri_command || return 2
	ignored="$(MIRIFLAGS="$(miri_flags stacked)" "${miri_cmd[@]}" "$@" -- "${narrowed[@]}" --ignored --list --format terse 2>>"$out.err")" || return 1
	case "$kind" in
	test)
		all="$(MIRIFLAGS="$(miri_flags stacked)" "${miri_cmd[@]}" "$@" -- "${narrowed[@]}" --list --format terse 2>>"$out.err")" || return 1
		LC_ALL=C comm -23 \
			<(sed -n 's/: test$//p' <<<"$all" | LC_ALL=C sort) \
			<(sed -n 's/: test$//p' <<<"$ignored" | LC_ALL=C sort) >"$out"
		;;
	abort) sed -n 's/: test$//p' <<<"$ignored" | LC_ALL=C sort >"$out" ;;
	*)
		printf 'unknown suite kind: %s\n' "$kind" >&2
		return 2
		;;
	esac
	[[ -s "$out" ]]
}

# The libtest arguments that select test `$2` of a suite of kind `$1`: an
# abort scenario is an ignored test.
selecting() {
	case "$1" in
	test) printf '%s\n' --exact "$2" ;;
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
