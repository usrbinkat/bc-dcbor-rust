#!/usr/bin/env bash
# The planted controls that run one test (tests/data/controls/controls.tsv,
# runner `native`, or a Miri aliasing model the gate lists, `gate miri
# models`): each control's diff applied to a copy of a clean commit, never
# the checkout, its one test run alone and required to refuse the defect by
# its own rule; then, in the same copy with the diff reversed, the same test
# required to pass, and the copy required to read back as it was before the
# diff. A native control's test is built and run by the gate tool (`control
# run`); a Miri control's runs here under the Miri gate's one command and
# its model's flags (tests/gate-common.sh, `miri_command`, `miri_flags`),
# and the gate tool judges it (`control judge`). Every decision is the gate
# tool's (tests/gate, `controls`): the table and its completeness, each run's
# judgement, and the evidence.
#
# The model checkers' controls are the concurrency gate's
# (tests/concurrency-models.sh). Each control names the toolchain channel
# its suite runs under; this script runs the controls of the channel of the
# shell it runs in, so a control blessed on stable is run from the stable
# shell, and a Miri control, Miri being a nightly component, from the
# nightly one. A Kani control (runner `kani`, one proof harness checked
# alone) runs from the proof shell, whose channel is `kani`: Kani pins its
# own toolchain, so that shell is told apart by `cargo kani` on its PATH,
# never by its compiler's release; the gate tool builds and checks it
# (`control run`, tests/gate/src/controls.rs) as it does a native one.
#
# Usage: tests/controls.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo rustc patch time sha256sum git tar find xargs; do
	if ! command -v "$tool" >/dev/null; then
		printf 'controls prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
		exit 127
	fi
done
if (($# != 0)); then
	echo "usage: tests/controls.sh" >&2
	exit 2
fi
gate_prepare || exit 2
miri_models || exit 2
release="$(rustc -V)" || exit 2
if command -v cargo-kani >/dev/null; then
	channel=kani
else
	case "$release" in
	*nightly*) channel=nightly ;;
	*) channel=stable ;;
	esac
fi
logs="${CONTROL_LOG_DIR:-${TMPDIR:?required, or CONTROL_LOG_DIR: the controls log directory}/controls-$channel}"
mkdir -p "$logs" || exit 2

listed="$(gate control list "$PWD" "$channel" native kani "${MIRI_MODELS[@]}")" || {
	event "FAIL the controls' table is refused; nothing was run"
	exit 1
}
controls=()
mapfile -t controls <<<"$listed"
if ((${#controls[@]} == 0)) || [[ -z "${controls[0]}" ]]; then
	event "DONE no control of one test runs under $channel"
	exit 0
fi

# The Miri models the listed controls run under: each one's flags are part
# of the run's identity, and Miri's sysroot is prepared once for them.
declare -A miri_used=()
for line in "${controls[@]}"; do
	IFS=$'\t' read -r _ _ runner _ <<<"$line"
	if [[ "$runner" != native && "$runner" != kani ]]; then
		miri_used[$runner]=1
	fi
done

{
	printf 'channel\t%s\n' "$channel"
	printf 'control\t%s\n' "${controls[@]}"
	for model in "${!miri_used[@]}"; do
		printf 'model\t%s\tMIRIFLAGS\t%s\n' "$model" "$(miri_flags "$model")"
	done | LC_ALL=C sort
} | identity "$logs" || {
	event "FAIL the run's identity could not be written; nothing was run"
	exit 2
}
echo "identity: $(cat "$logs/identity.txt")"

# The toolchain's own Miri sysroot and build cache, once, before any Miri
# control runs (tests/gate-common.sh).
if ((${#miri_used[@]} > 0)); then
	miri_prepare >"$logs/miri-setup.log" 2>&1 || {
		cat "$logs/miri-setup.log"
		exit 1
	}
fi

# One run of the Miri control whose row is in the variables `name`, `runner`
# (its model), `package`, `features`, `target` and `test`, side `$1`, in the
# copy `$2`, logged in `$3`: the Miri gate's one command (`miri_command`)
# under the model's flags (`miri_flags`), the row's package, features and
# target, its one test selected exactly; the run classified by the gate
# tool's one classifier of a Miri run (`classify miri`), then judged by it
# (`control judge`) as a native run is.
miri_control() {
	local side="$1" copy="$2" directory="$3" flags status outcome
	flags="$(miri_flags "$runner")" || return 2
	local selection=(--manifest-path "$copy/Cargo.toml" --package "$package")
	case "$features" in
	-) ;;
	all) selection+=(--all-features) ;;
	*) selection+=(--features "$features") ;;
	esac
	case "$target" in
	lib) selection+=(--lib) ;;
	*) selection+=(--test "$target") ;;
	esac
	local miri_cmd
	miri_command || return 2
	env MIRIFLAGS="$flags" "${miri_cmd[@]}" "${selection[@]}" -- \
		--exact "$test" --nocapture --test-threads=1 >"$directory/$side.log" 2>&1
	status=$?
	outcome="$(gate classify miri test "$status" "$directory/$side.log")" || return 2
	gate control judge "$side" "$copy" "$logs" "$name" "$runner" "$outcome" "$directory/$side.log"
}

# One run of the listed control, side `$1`, in the copy `$2`, its directory
# `$3`: built and run by the gate tool (native, and a Kani harness, which it
# checks with `cargo kani`), or by `miri_control`.
control_side() {
	if [[ "$runner" == native || "$runner" == kani ]]; then
		gate control run "$1" "$2" "$built" "$logs" "$name" "$runner"
	else
		miri_control "$1" "$2" "$3"
	fi
}

# Evidence is of a commit: every run is of a copy of it.
clean_commit "$logs" || exit 1
copies="$PWD/target/control-copies"
# One build directory for every copy: each copy is the same commit but for
# its diff, so the copies' builds share every unchanged artifact.
built="$PWD/target/control-builds"

status=0
for line in "${controls[@]}"; do
	IFS=$'\t' read -r name diff runner _ package features target test _ <<<"$line"
	# A Miri control's directory and copy name its model too, as the gate
	# tool's do (`controls::directory`): one diff may be a control under
	# each model.
	if [[ "$runner" == native ]]; then
		run="$name"
	else
		run="$name-$runner"
	fi
	directory="$logs/$run"
	copy="$copies/$run"
	mkdir -p "$directory"
	cp "$logs/identity.txt" "$directory/identity.txt"
	copy_of "$copy" "$commit" || exit 2
	tree_digest "$copy" >"$directory/before.sha256" || exit 2
	if ! apply_diff "$diff" "$copy"; then
		event "FAIL $run: the diff does not apply: $diff"
		status=1
		continue
	fi
	tree_digest "$copy" >"$directory/planted.sha256" || exit 2
	event "START $run red ($directory)"
	if control_side red "$copy" "$directory"; then
		event "PASS $run: refused by its own rule"
	else
		event "FAIL $run: not refused by its own rule ($directory/red.judged)"
		status=1
	fi
	if ! revert_diff "$diff" "$copy"; then
		event "FAIL $run: the diff does not reverse: $diff"
		status=1
		continue
	fi
	tree_digest "$copy" >"$directory/after.sha256" || exit 2
	event "START $run green ($directory)"
	if control_side green "$copy" "$directory"; then
		event "PASS $run: restored"
	else
		event "FAIL $run: not restored ($directory/green.judged)"
		status=1
	fi
	rm -rf "$copy"
done
if ! still_at_commit; then
	event "FAIL the checkout moved off $commit during the run"
	status=1
fi
# The verdict over every control of one test of this channel, native or under
# a Miri model: each seen red, then green again, in a copy restored to its
# digest.
if ! gate control evidence "$PWD" "$logs" "$channel"; then
	status=1
fi
event "DONE ${#controls[@]} controls of one test of $commit under $channel; status $status"
exit "$status"
