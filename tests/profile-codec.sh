#!/usr/bin/env bash
# Standalone codec evidence; no downstream workload or acceptance target.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${TMPDIR:?required: the profile log directory}"
: "${DCBOR_CONFIGURATION:?run in the identified development shell}"
logs="$(mktemp -d "$TMPDIR/dcbor-codec-profile.XXXXXX")"
printf 'Codec profile logs: %s\n' "$logs"
operations="${DCBOR_PROFILE_OPERATIONS:-1000}"
repetitions="${DCBOR_PROFILE_REPETITIONS:-1024}"
read -r -a workers <<<"${DCBOR_PROFILE_WORKERS:-1 2 4}"
for value in "$operations" "$repetitions" "${workers[@]}"; do
	[[ "$value" =~ ^[1-9][0-9]*$ ]] || {
		echo 'profile dimensions must be positive integers' >&2
		exit 2
	}
done
[[ "${#workers[@]}" -gt 0 ]] || exit 2
# The profile is evidence of the source it started on: every gate's one
# input closure (tests/gate-common.sh, `source_identity`), checked unchanged
# after every run, the difference written when it moved.
unchanged() {
	if ! same_source "$logs"; then
		source_identity >"$logs/current-identity-inputs.txt"
		diff -u "$logs/identity-inputs.txt" "$logs/current-identity-inputs.txt" >"$logs/source-diff.log" || true
		return 1
	fi
}
# The profile's identity: the gates' one identity, with its dimensions, its
# build and every variable cargo reads for it.
{
	printf 'operations\t%s\trepetitions\t%s\tworkers\t%s\tprocesses_per_case\t3\n' \
		"$operations" "$repetitions" "${workers[*]}"
	printf 'features\tdefault\tprofile\trelease\tallocator\tSystem\n'
	for name in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_OPT_LEVEL CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS; do
		printf '%s\t%s\n' "$name" "${!name-}"
	done
} | identity "$logs"
printf 'Codec profile identity: %s\n' "$(cat "$logs/identity.txt")"
# The host the measurements were taken on, beside the identity: the
# measurements depend on it, the source's evidence does not.
{
	date -u
	uname -a
	if command -v lscpu >/dev/null; then lscpu; fi
	for file in /sys/devices/system/cpu/smt/active /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
		if [[ -r "$file" ]]; then
			printf '%s=' "$file"
			cat "$file"
		fi
	done
} >"$logs/host.log" 2>&1
printf 'STARTED\n' >"$logs/results.txt"
# The exit status every run ends with, recorded beside its results.
finished() {
	local status=$?
	printf 'EXIT %s\n' "$status" >>"$logs/results.txt"
}
trap finished EXIT
cargo build --locked --release --example codec_profile --example reclamation_profile >"$logs/build.log" 2>&1
unchanged
for worker in "${workers[@]}"; do
	for fixture in ascii combining; do
		for storage in private shared; do
			for process in 1 2 3; do
				name="$worker-$fixture-$storage-$process"
				cargo run --locked --quiet --release --example codec_profile -- "$worker" "$operations" "$repetitions" "$fixture" "$storage" >"$logs/$name.tsv" 2>"$logs/$name.stderr"
				unchanged
				printf 'PASS %s\n' "$name" >>"$logs/results.txt"
			done
		done
	done
done
for batch in 1 16 64; do
	for service in 0 1 8; do
		for process in 1 2 3; do
			name="reclamation-$batch-$service-$process"
			cargo run --locked --quiet --release --example reclamation_profile -- "$operations" "$batch" "$service" "$repetitions" >"$logs/$name.tsv" 2>"$logs/$name.stderr"
			unchanged
			printf 'PASS %s\n' "$name" >>"$logs/results.txt"
		done
	done
done
printf 'COMPLETE\n' >>"$logs/results.txt"
printf 'Codec profile complete: %s\n' "$logs"
