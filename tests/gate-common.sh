# Sourced by the evidence gates (tests/miri-owned.sh, tests/reach-map.sh,
# tests/mutation-evidence.sh, tests/concurrency-models.sh, tests/controls.sh,
# tests/proofs.sh, tests/record-evidence.sh, tests/profile-codec.sh,
# fuzz/qualify.sh): their one definition of the process group a gate runs
# in, of an input closure, of the mutation domains' features, of the Miri
# gate's selection and models, of the tests a suite runs under Miri, of what
# a passing run and an aborting one are, of the commit evidence is of, its
# copies, and applying a planted diff to one. Run from the repository root
# in the configured development shell.
# shellcheck shell=bash

# Every process a gate starts ends with it. A gate calls
# `own_process_group "$@"` on the line after sourcing this file, from the
# repository root its first line changed to. The call runs the gate again,
# with the same arguments, as the leader of a process group of its own
# (bash job control, `set -m`), under this process, its supervisor, which
# stays in the caller's group and owns the gate's group:
#
# - a termination, interruption or hangup of the supervisor is sent to the
#   whole group (every cargo, test binary, checker and copy the gate
#   launched), and the supervisor exits with the gate's status;
# - when the gate exits, whatever of its group outlives it is terminated;
# - inside the group a watcher terminates the group once the gate's parent
#   is no longer its supervisor: the supervisor was killed outright
#   (SIGKILL, which no trap sees). The watcher survives SIGTERM long enough
#   to escalate to SIGKILL after one second, including for resistant children.
# - before the gate starts work it defines its workloads' confinement
#   (`gate_confinement`): each checker, test and build it runs is confined
#   to a memory-capped scope of its own, the gate itself never.
#
# The launch marker is consumed before starting work. A marked child whose
# parent already died exits instead of starting another supervisor. Nested
# gates inherit no marker and create their own supervisor and group.
own_process_group() {
	local supervisor="${DCBOR_GATE_SUPERVISOR:-}" parent
	if [[ -n "$supervisor" ]]; then
		unset DCBOR_GATE_SUPERVISOR
		[[ "$supervisor" == "$PPID" ]] || exit 143
		local ready
		# EOF before readiness refuses the launch. The pipe handshake does
		# not depend on the caller's inherited signal dispositions.
		IFS= read -r ready < <(
			stop_group() {
				trap '' TERM INT HUP
				kill -TERM 0
				sleep 1
				kill -KILL 0
			}
			trap stop_group TERM INT HUP
			printf '%s\n' ready
			while read -r parent < <(ps -o ppid= -p "$$") && [[ "$parent" == "$supervisor" ]]; do
				sleep 1
			done
			stop_group
		) || exit 1
		[[ "$ready" == ready ]] || exit 1
		gate_confinement || exit 2
		return 0
	fi
	local script leader="" status stopping=0
	script="$PWD/$(basename "$(dirname "$0")")/$(basename "$0")"
	trap 'stopping=1; if [[ -n "$leader" ]]; then kill -TERM -- "-$leader" 2>/dev/null || :; fi' TERM INT HUP
	set -m
	DCBOR_GATE_SUPERVISOR=$$ bash "$script" "$@" &
	leader=$!
	set +m
	if ((stopping)); then
		kill -TERM -- "-$leader" 2>/dev/null || :
	fi
	while :; do
		status=0
		wait "$leader" || status=$?
		[[ -d "/proc/$leader" ]] || break
	done
	kill -TERM -- "-$leader" 2>/dev/null || :
	exit "$status"
}

# Every workload a gate runs (a checker, a test binary, a build: each cargo,
# cargo-miri, cargo-kani, cargo-mutants, cargo-fuzz and profile run) is
# confined to a memory-capped scope of its own by the one workload launcher,
# tests/workload.sh, which execs it in place, so it keeps its PID, parent,
# group and session (termination is forwarded to it as to any of the
# gate's group) and its exit status or signal. The gate's own processes
# (its supervisor, watcher, script and the gate tool judging the run) stay
# outside every workload's scope: a memory-cgroup OOM chooses its victim
# only among the workload's processes, so the recorder survives a runaway
# checker by construction, whatever the kernel chooses inside the scope.
# Defines the prefix array `confined`, which every workload command of a
# script starts with, and exports the cap (DCBOR_GATE_MEMORY) and the
# launcher (DCBOR_GATE_WORKLOAD), by which the gate tool launches each run
# it judges (tests/gate, `process::workload`). Called by
# `own_process_group` before work starts.
gate_confinement() {
	local memory
	memory="$(gate_memory)" || return 1
	[[ -x "$PWD/tests/workload.sh" ]] || {
		printf 'gate confinement needs the workload launcher %s\n' "$PWD/tests/workload.sh" >&2
		return 1
	}
	export DCBOR_GATE_MEMORY="$memory"
	export DCBOR_GATE_WORKLOAD="$PWD/tests/workload.sh"
	confined=("$DCBOR_GATE_WORKLOAD")
}

# The memory cap of each workload's scope (`gate_confinement`), on standard
# output: DCBOR_GATE_MEMORY, a systemd byte size, `48G` unless the host sets
# one. Refused, with no gate started, when the user's systemd manager that
# enforces it is not running or its programs are not on PATH.
gate_memory() {
	local tool
	for tool in systemd-run systemctl; do
		if ! command -v "$tool" >/dev/null; then
			printf 'gate confinement needs %s on PATH, a program of the host systemd manager.\n' "$tool" >&2
			return 1
		fi
	done
	case "$(systemctl --user is-system-running 2>/dev/null || true)" in
	running | degraded) ;;
	*)
		printf 'gate confinement needs a running user systemd manager (systemctl --user).\n' >&2
		return 1
		;;
	esac
	printf '%s\n' "${DCBOR_GATE_MEMORY:-48G}"
}

# Every input a gate's evidence depends on, one digest line each: the whole
# input closure, every file of the repository git tracks or would track (the
# crates and their manifests, the derive crate, the tests, the examples, the
# fuzz crate, records, registries, planted controls, lint configuration, the
# flake, its patches and the locks), sorted by path; only what `.gitignore`
# excludes, build output and logs, is not an input. A file tracked but
# deleted from the working tree is named as deleted. A hand-picked list of
# patterns is no closure: one missed the derive crate's manifest. The one
# snapshot of every gate, profile and campaign (tests/profile-codec.sh,
# fuzz/qualify.sh), each identity built by `identity` and each source
# checked unchanged by `same_source`.
snapshot() {
	local file
	git -C "$PWD" ls-files -z --cached --others --exclude-standard --deduplicate |
		LC_ALL=C sort -z |
		while IFS= read -r -d '' file; do
			if [[ -f "$file" ]]; then
				sha256sum -- "$file"
			else
				printf 'deleted  %s\n' "$file"
			fi
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
# the shell's configuration, the Unicode version dCBOR normalizes and
# stabilizes text by and the dCBOR draft revision it implements (each read
# from the library through the gate tool, never written here, so
# `gate_prepare` comes first), the toolchain's store path
# (its components, the forked library, miri, llvm-tools, change it without
# changing its version), the compiler and Cargo. Two gates' evidence
# combines only when this part of their identities is equal (`same_source`).
source_identity() {
	: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
	local unicode draft sysroot
	unicode="$(gate unicode-version)" || return 1
	draft="$(gate dcbor-draft)" || return 1
	# Read before printing: a substitution as a printf argument would record
	# an empty value when the command failed.
	sysroot="$(rustc --print sysroot)" || return 1
	[[ -n "$unicode" && -n "$draft" && -n "$sysroot" ]] || return 1
	snapshot || return 1
	printf 'configuration\t%s\n' "$DCBOR_CONFIGURATION"
	printf 'unicode\t%s\n' "$unicode"
	printf 'dcbor-draft\t%s\n' "$draft"
	printf 'toolchain\t%s\n' "$sysroot"
	rustc -vV || return 1
	cargo -V || return 1
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
# layer, DCBOR_CLASS_COVERAGE the inventory (each matrix's stop classes and
# the boundary valuations its runs reached, tests/gate `inventory`),
# DCBOR_WITNESS the witness sizes; each is forwarded, and nothing else of the
# host's environment is visible.
#
# Alignment is checked symbolically: against the alignment each allocation
# was requested with and the offset into it, not the integer address, which
# can satisfy an alignment by chance. Cursors stored in a `Slot`'s inline
# bytes, and values placed in records and metadata blocks, are checked
# against the alignment their storage guarantees.
MIRI_STRICT="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-env-forward=DCBOR_RIGOR -Zmiri-env-forward=DCBOR_CLASS_COVERAGE -Zmiri-env-forward=DCBOR_WITNESS"

# The aliasing models every Miri verdict is given under, into the array
# `MIRI_MODELS`: read from the gate tool's one list (`gate miri models`,
# tests/gate `miri::MIRI_MODELS`), never written here, so `gate_prepare`
# comes first. Each must have its flags (`miri_flags`): a model the gate
# lists and this file cannot run is refused here, before any identity
# records empty flags for it.
miri_models() {
	local listed model
	listed="$(gate miri models)" || return 2
	mapfile -t MIRI_MODELS <<<"$listed"
	((${#MIRI_MODELS[@]} > 0)) || return 2
	for model in "${MIRI_MODELS[@]}"; do
		miri_flags "$model" >/dev/null || return 2
	done
}

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

# The commit a gate's evidence is of: the checkout's HEAD, refused unless the
# tree is clean, so nothing edited and not committed reaches the evidence.
# Writes it to `$1/commit.txt` and into the variable `commit`.
clean_commit() {
	if [[ -n "$(git -C "$PWD" status --porcelain)" ]]; then
		event "FAIL the tree is not clean: evidence is of a commit; nothing was run"
		return 1
	fi
	commit="$(git -C "$PWD" rev-parse HEAD)" || return 1
	printf '%s\n' "$commit" >"$1/commit.txt"
}

# Whether the checkout is still clean at the commit `clean_commit` named:
# evidence taken while it moved is of no one commit.
still_at_commit() {
	[[ -z "$(git -C "$PWD" status --porcelain)" ]] &&
		[[ "$(git -C "$PWD" rev-parse HEAD)" == "$commit" ]]
}

# A copy of the commit `$2` at `$1`, replacing any earlier one: what a
# planted diff (a mutant, a control) is applied to, never the checkout.
copy_of() {
	rm -rf "$1"
	mkdir -p "$1"
	git -C "$PWD" archive "$2" | tar -x -C "$1"
}

# The one invocation of a planted diff: `patch_diff DIFF DIR [FLAG...]` runs
# DIFF against the tree at DIR, a copy of a commit (`copy_of`), exactly
# (`-p0`, no fuzz), the flags naming its direction or a dry run. GNU patch
# places a hunk whose trailing context is shorter than its leading context
# only at the file's end, and one whose leading context is shorter only at
# its start, so every hunk carries equal context on both sides, which the
# gate's table check refuses otherwise (tests/gate `controls::hunk_faults`).
# The applier, the reverser and the preflight below are this one command.
patch_diff() {
	local diff="$1" directory="$2"
	shift 2
	patch -d "$directory" -p0 --batch --fuzz=0 --no-backup-if-mismatch --quiet "$@" <"$diff"
}

# The one applier of a planted diff: `apply_diff DIFF DIR` applies DIFF to
# the copy at DIR. The copy is discarded with the diff in it; nothing is
# reverted, since no tree a gate keeps is ever changed.
apply_diff() {
	patch_diff "$1" "$2"
}

# The one reverser of a planted diff: `revert_diff DIFF DIR` reverses DIFF in
# the copy at DIR, exactly as `apply_diff` applied it, so a control is seen
# green again in the same copy it was seen red in.
revert_diff() {
	patch_diff "$1" "$2" -R
}

# Whether `apply_diff DIFF DIR` would apply DIFF to the copy at DIR: the same
# command run dry, changing nothing.
check_diff() {
	patch_diff "$1" "$2" --dry-run
}

# Every planted control diff (tests/data/controls, every runner and channel)
# checked against a copy at `$1` of the commit `commit` (`clean_commit`)
# before a gate runs any control: a diff that no longer applies is named
# here, in seconds, never after the controls before it in the table have
# run. Each diff that does not apply is named; then the preflight refuses.
preflight_controls() {
	local copy="$1" diff failed=0
	copy_of "$copy" "$commit" || return 2
	for diff in tests/data/controls/*.patch; do
		if ! check_diff "$diff" "$copy"; then
			event "FAIL preflight: the diff does not apply: $diff"
			failed=1
		fi
	done
	rm -rf "$copy"
	return "$failed"
}

# The source state of the copy at `$1` (`copy_of`, which carries no git
# metadata), digested by the gate tool's one implementation (`gate
# tree-digest`, tests/gate `proofs::SourceState`): every entry's raw path,
# kind, executable bit, link target and bytes, so `gate_prepare` comes
# first. A control's copy is recorded before its diff, with it, and after it
# is reversed, and must read back equal.
tree_digest() {
	gate tree-digest "$1"
}

# The gate tool (tests/gate): every decision about what a run produced and
# whether it is evidence is made there, once; the scripts launch it.
# `gate_prepare` builds it once, in a target directory of its own, before a
# script changes its environment: none of the flags or wrappers a gate sets
# for what it measures (the reach map's coverage instrumentation,
# RUSTFLAGS, the profile runtime) reaches the tool, which measures without
# being measured. Built for the host named explicitly, so its path is the
# same whether or not the shell's cargo sets a target. Its standard input is
# never a script's: a call inside a loop reading a file leaves that file to
# the loop.
gate_prepare() {
	local target="$PWD/target/gate-tool" host
	host="$(rustc -vV | sed -n 's/^host: //p')" || return 2
	[[ -n "$host" ]] || return 2
	env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER -u DCBOR_PROFILER \
		"${confined[@]}" cargo build --quiet --package dcbor-gate --bin gate --target "$host" --target-dir "$target" </dev/null ||
		return 2
	GATE_BINARY="$target/$host/debug/gate"
}
gate() {
	: "${GATE_BINARY:?call gate_prepare before the gate tool}"
	"$GATE_BINARY" "$@" </dev/null
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
	"${confined[@]}" cargo miri setup
}

# The command every Miri run of the gates starts with, into the array
# `miri_cmd`: `cargo miri test`, confined (`gate_confinement`), with the
# toolchain's own build cache (`--target-dir`, to which cargo-miri appends
# `miri`: util.rs `get_target_dir`). An array, not a function, so a run can
# be timed by GNU `time`, which executes programs. Refused before
# `miri_prepare`.
miri_command() {
	: "${MIRI_TARGET_DIR:?call miri_prepare before running Miri}"
	: "${MIRI_SYSROOT:?call miri_prepare before running Miri}"
	miri_cmd=("${confined[@]}" cargo miri test --target-dir "$MIRI_TARGET_DIR")
}

# The MIRIFLAGS of model `$1`, strict provenance included, the caller's own
# MIRIFLAGS after them.
miri_flags() {
	case "$1" in
	stacked) printf '%s %s' "$MIRI_STRICT" "${MIRIFLAGS:-}" ;;
	tree) printf '%s -Zmiri-tree-borrows %s' "$MIRI_STRICT" "${MIRIFLAGS:-}" ;;
	*)
		printf 'unknown Miri model: %s; the models are those the gate tool lists (gate miri models), each with its flags here\n' "$1" >&2
		return 2
		;;
	esac
}

# The list `$2` (features, files or tests) of build domain `$1`, from the
# gate's one table of domains (tests/gate, `domains`), into the array
# `domain_list`. Unknown domains are refused by the gate.
domain_list() {
	local listed
	listed="$(gate domain "$1" "$2")" || return 2
	mapfile -t domain_list <<<"$listed"
}

# The cargo features of build domain `$1`, into the array `features`.
domain_features() {
	domain_list "$1" features || return 2
	features=("${domain_list[@]}")
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
