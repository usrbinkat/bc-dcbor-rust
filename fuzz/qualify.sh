#!/usr/bin/env bash
# Recorded, time-bounded campaign over the existing fuzz targets.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

seconds=${FUZZ_SECONDS:-600}
seed=${FUZZ_SEED:-20261019}
for value in "$seconds" "$seed"; do
	if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
		echo 'FUZZ_SECONDS and FUZZ_SEED must be positive integers' >&2
		exit 2
	fi
done

logs=${FUZZ_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/dcbor-fuzz-XXXXXXXX")}
mkdir -p "$logs"
logs=$(cd "$logs" && pwd)
if [[ -e $logs/results.txt ]]; then
	echo "Refusing to overwrite an existing campaign: $logs" >&2
	exit 2
fi
printf 'Campaign logs: %s\n' "$logs"
printf 'STARTED\n' >"$logs/results.txt"
trap 'status=$?; printf "EXIT %s\n" "$status" >> "$logs/results.txt"' EXIT

{
	date -u
	rustc -Vv
	cargo -V
	cargo fuzz --version
	printf 'seconds_per_target=%s seed=%s\n' "$seconds" "$seed"
	for file in flake.nix flake.lock Cargo.toml Cargo.lock fuzz/Cargo.toml fuzz/Cargo.lock; do
		if [[ -f $file ]]; then sha256sum "$file"; fi
	done
	find src dcbor-derive/src fuzz/src fuzz/fuzz_targets -type f -name '*.rs' -print0 |
		sort -z | xargs -0 sha256sum
	sha256sum fuzz/qualify.sh
} >"$logs/environment-and-sources.log" 2>&1

if cargo fuzz build >"$logs/build.log" 2>&1; then
	printf 'BUILD PASS\n' >>"$logs/results.txt"
else
	status=$?
	printf 'BUILD FAIL exit=%s\n' "$status" >>"$logs/results.txt"
	tail -n 80 "$logs/build.log"
	exit "$status"
fi

while read -r target max_len; do
	printf 'Running %s (%ss); log: %s/%s.log\n' "$target" "$seconds" "$logs" "$target"
	if cargo fuzz run "$target" -- \
		-seed="$seed" -max_total_time="$seconds" -max_len="$max_len" \
		-timeout=30 -rss_limit_mb=4096 -print_final_stats=1 \
		>"$logs/$target.log" 2>&1; then
		printf '%s PASS\n' "$target" >>"$logs/results.txt"
	else
		status=$?
		printf '%s FAIL exit=%s\n' "$target" "$status" >>"$logs/results.txt"
		tail -n 80 "$logs/$target.log"
		exit "$status"
	fi
done <<'TARGETS'
numeric 8
text 4096
nested 32
refusals 66
decode 4096
decode_schedule 4096
schema_schedule 1024
representations 256
TARGETS

cat "$logs/results.txt"
printf 'Campaign complete: %s\n' "$logs"
