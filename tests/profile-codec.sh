#!/usr/bin/env bash
# Standalone codec evidence; no downstream workload or acceptance target.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${TMPDIR:?set TMPDIR to the session scratch directory}"
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
snapshot() {
	find src dcbor-derive/src -type f -name '*.rs' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
	sha256sum Cargo.toml dcbor-derive/Cargo.toml examples/codec_profile.rs examples/reclamation_profile.rs tests/profile-codec.sh
	for file in Cargo.lock flake.nix flake.lock nix/btree-in-place.patch; do
		if [[ -f "$file" ]]; then sha256sum "$file"; fi
	done
}
unchanged() {
	snapshot >"$logs/current-source.sha256"
	diff -u "$logs/source.sha256" "$logs/current-source.sha256" >"$logs/source-diff.log"
}
{
	printf 'configuration=%s\n' "$DCBOR_CONFIGURATION"
	printf 'operations=%s repetitions=%s workers=%s processes_per_case=3\n' "$operations" "$repetitions" "${workers[*]}"
	printf 'features=default profile=release allocator=System\n'
	date -u
	rustc -Vv
	cargo -V
	uname -a
	if command -v lscpu >/dev/null; then lscpu; fi
	for file in /sys/devices/system/cpu/smt/active /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
		if [[ -r "$file" ]]; then
			printf '%s=' "$file"
			cat "$file"
		fi
	done
	for name in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_OPT_LEVEL CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS; do
		printf '%s=%s\n' "$name" "${!name-}"
	done
} >"$logs/environment.log" 2>&1
snapshot >"$logs/source.sha256"
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
