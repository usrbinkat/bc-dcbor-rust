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
# and the gate tool judges it (`control judge`). Either runs its test at its
# row's layer (the `rigor` column, as DCBOR_RIGOR), never this shell's.
# Every decision is the gate
# tool's (tests/gate, `controls`): the table and its completeness, each run's
# judgement, and the evidence.
#
# The model checkers' controls are the concurrency gate's
# (tests/concurrency-models.sh). Each control names the toolchain channel
# its suite runs under, and this script runs the controls of the one channel
# named on its command line, never inferred: every development shell carries
# `cargo kani` (flake.nix, `maintenance`), so one shell serves its compiler's
# channel and Kani's. A native or Miri control runs under `nightly` or
# `stable`, refused unless this shell's compiler is that channel's release:
# a control blessed on stable from the stable shell, a Miri control, Miri
# being a nightly component, from the nightly one. A Kani control (runner
# `kani`, one proof harness checked alone) runs under `kani`, refused unless
# `cargo kani` is on PATH; Kani pins its own toolchain, and the gate tool
# builds and checks it (`control run`, tests/gate/src/controls.rs) as it
# does a native one.
#
# The runners named after the channel scope the run to their controls
# (`gate control list`, `controls::selected`), every runner when none is
# named, each run's final record naming its channel, its runners and every
# selected control's result (`gate control evidence`, `verdict.json`). The
# verdict is test adequacy's alone: no implementation validation, calibration
# or qualification reads it (tests/red-green.sh runs this track). The run holds
# the checkout's workload lock (target/gate-workload.lock) exclusively from
# before its first control to its verdict: no other control run, proof run
# or calibration of the checkout runs beside it.
#
# With `--only NAME...` after the runners, the run is of those registered
# controls alone, each required to be one the channel and runners select (an
# unknown name refuses the run before anything runs): the same sequence per
# control, its selection in the run's identity, and no final record, since
# a partial run is no channel's verdict.
#
# Usage: tests/controls.sh {nightly|stable|kani} [RUNNER...] [--only NAME...]
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
own_process_group "$@"
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
for tool in cargo rustc patch time sha256sum git tar find xargs flock; do
    if ! command -v "$tool" > /dev/null; then
        printf 'controls prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
        exit 127
    fi
done
usage() {
    echo "usage: tests/controls.sh {nightly|stable|kani} [RUNNER...] [--only NAME...]" >&2
    exit 2
}
(($# >= 1)) || usage
channel="$1"
shift
requested=()
only=()
while (($# > 0)) && [[ "$1" != --only ]]; do
    requested+=("$1")
    shift
done
if (($# > 0)); then
    shift
    (($# > 0)) || usage
    only=("$@")
fi
release="$(rustc -V)" || exit 2
case "$channel" in
    nightly | stable)
        served=stable
        if [[ "$release" == *nightly* ]]; then
            served=nightly
        fi
        if [[ "$channel" != "$served" ]]; then
            printf 'channel %s: this shell compiles with %s, a %s release\n' "$channel" "$release" "$served" >&2
            exit 2
        fi
        ;;
    kani)
        if ! command -v cargo-kani > /dev/null; then
            echo "channel kani: cargo kani is not on PATH; run in a development shell" >&2
            exit 2
        fi
        ;;
    *) usage ;;
esac
gate_prepare || exit 2
miri_models || exit 2
runners=("${requested[@]}")
if ((${#runners[@]} == 0)); then
    runners=(native kani "${MIRI_MODELS[@]}")
fi
mkdir -p "$PWD/target" || exit 2
exec 8> "$PWD/target/gate-workload.lock" || exit 2
if ! flock --nonblock 8; then
    echo "another gate workload holds target/gate-workload.lock; nothing was run" >&2
    exit 2
fi
logs="${CONTROL_LOG_DIR:-${TMPDIR:?required, or CONTROL_LOG_DIR: the controls log directory}/controls-$channel}"
# A run's evidence is created once: an existing log directory is another
# run's, never overwritten. Its parents are created as needed; the directory
# itself only when it does not exist.
mkdir -p "$(dirname "$logs")" || exit 2
mkdir "$logs" || exit 2

listed="$(gate control list "$PWD" "$channel" "${runners[@]}")" || {
    event "FAIL the controls' table is refused; nothing was run"
    exit 1
}
controls=()
mapfile -t controls <<< "$listed"
if ((${#only[@]} > 0)); then
    declare -A wanted=()
    for name in "${only[@]}"; do
        wanted[$name]=1
    done
    kept=()
    for line in "${controls[@]}"; do
        IFS=$'\t' read -r name _ <<< "$line"
        if [[ -n "${wanted[$name]:-}" ]]; then
            kept+=("$line")
            unset "wanted[$name]"
        fi
    done
    if ((${#wanted[@]} > 0)); then
        event "FAIL --only names no control of $channel under ${runners[*]}: ${!wanted[*]}; nothing was run"
        exit 2
    fi
    controls=("${kept[@]}")
fi
if ((${#controls[@]} == 0)) || [[ -z "${controls[0]}" ]]; then
    event "DONE no control of one test runs under $channel"
    exit 0
fi

# The Miri models the listed controls run under: each one's flags are part
# of the run's identity, and Miri's sysroot is prepared once for them.
declare -A miri_used=()
for line in "${controls[@]}"; do
    IFS=$'\t' read -r _ _ runner _ <<< "$line"
    if [[ "$runner" != native && "$runner" != kani ]]; then
        miri_used[$runner]=1
    fi
done

# The Kani a kani channel's controls launch, selected once: its path is
# written to kani-launcher, which every side of every control is given.
kani_identity=""
launcher=-
if [[ "$channel" == kani ]]; then
    launcher="$logs/kani-launcher"
    kani_identity="$(gate proofs-identity "$launcher")" || {
        event "FAIL the Kani the controls launch could not be identified; nothing was run"
        exit 2
    }
fi
{
    printf 'channel\t%s\n' "$channel"
    printf 'runner\t%s\n' "${runners[@]}"
    if ((${#only[@]} > 0)); then
        printf 'only\t%s\n' "${only[@]}"
    fi
    if [[ -n "$kani_identity" ]]; then
        printf '%s\n' "$kani_identity"
    fi
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
    miri_prepare > "$logs/miri-setup.log" 2>&1 || {
        cat "$logs/miri-setup.log"
        exit 1
    }
fi

# One run of the Miri control whose row is in the variables `name`, `runner`
# (its model), `package`, `features`, `rigor`, `target` and `test`, side
# `$1`, in the copy `$2`, logged in `$3`: the Miri gate's one command
# (`miri_command`) under the model's flags (`miri_flags`, which forward
# DCBOR_RIGOR to the interpreted test), the row's package, features and
# target, its one test selected exactly at the row's layer and at the
# Miri gate's minimal witness sizes (tests/miri-owned.sh), both set here
# whatever this shell's environment holds; the run classified by the gate
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
    env MIRIFLAGS="$flags" DCBOR_RIGOR="$rigor" DCBOR_WITNESS=minimal "${miri_cmd[@]}" "${selection[@]}" -- \
        --exact "$test" --nocapture --test-threads=1 > "$directory/$side.log" 2>&1
    status=$?
    outcome="$(gate classify miri test "$status" "$directory/$side.log")" || return 2
    gate control judge "$side" "$copy" "$logs" "$name" "$runner" "$outcome" "$directory/$side.log"
}

# One run of the listed control, side `$1`, in the copy `$2`, its directory
# `$3`: built and run by the gate tool (native, and a Kani harness, which it
# checks with `cargo kani`), or by `miri_control`.
control_side() {
    if [[ "$runner" == native ]]; then
        gate control run "$1" "$2" "$built" "$logs" "$name" "$runner" -
    elif [[ "$runner" == kani ]]; then
        gate control run "$1" "$2" "$built" "$logs" "$name" "$runner" "$launcher"
    else
        miri_control "$1" "$2" "$3"
    fi
}

# Evidence is of a commit: every run is of a copy of it.
clean_commit "$logs" || exit 1
copies="$PWD/target/control-copies"
# Every control diff applied dry to the commit before any control runs.
preflight_controls "$copies/preflight" || {
    event "FAIL a control diff does not apply to $commit; nothing was run"
    exit 1
}
# One build directory for every copy: each copy is the same commit but for
# its diff, so the copies' builds share every unchanged artifact.
built="$PWD/target/control-builds"

status=0
for line in "${controls[@]}"; do
    IFS=$'\t' read -r name diff runner _ package features rigor target test _ <<< "$line"
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
    mkdir "$directory" || exit 2
    cp "$logs/identity.txt" "$directory/identity.txt"
    copy_of "$copy" "$commit" || exit 2
    tree_digest "$copy" > "$directory/before.sha256" || exit 2
    # A Kani control's harness must verify on the unmutated commit first
    # (`controls::verified`): a planted defect in a harness with no verdict
    # (`NoVerdict`, a failure, a short bound) shows nothing, so its red side is
    # never run. The baseline writes no source; the copy's digest after the
    # diff is reversed is still compared with the digest before it.
    if [[ "$runner" == kani ]]; then
        event "START $run baseline ($directory)"
        if control_side baseline "$copy" "$directory"; then
            event "PASS $run: the unmutated harness verified"
        else
            event "FAIL $run: the unmutated harness did not verify; the control is not run ($directory/baseline.judged)"
            status=1
            rm -rf "$copy"
            continue
        fi
    fi
    if ! apply_diff "$diff" "$copy"; then
        event "FAIL $run: the diff does not apply: $diff"
        status=1
        continue
    fi
    tree_digest "$copy" > "$directory/planted.sha256" || exit 2
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
    tree_digest "$copy" > "$directory/after.sha256" || exit 2
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
# The verdict over every selected control of one test of this channel and
# these runners: each seen red, then green again, in a copy restored to its
# digest; and the run's final record (`verdict.json`). A run of `--only`
# controls writes none: it is no channel's verdict.
if ((${#only[@]} > 0)); then
    event "DONE ${#controls[@]} named controls of $commit under $channel; status $status; no verdict.json"
    exit "$status"
fi
if ! gate control evidence "$PWD" "$logs" "$channel" "${runners[@]}"; then
    status=1
fi
event "DONE ${#controls[@]} controls of one test of $commit under $channel; status $status"
exit "$status"
