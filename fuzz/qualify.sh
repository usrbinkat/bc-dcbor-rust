#!/usr/bin/env bash
# Recorded, time-bounded campaign over the existing fuzz targets.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"

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
# The exit status every campaign ends with, recorded beside its results.
finished() {
	local status=$?
	printf 'EXIT %s\n' "$status" >>"$logs/results.txt"
}
trap finished EXIT

# The campaign is evidence of the source it started on: every gate's one
# input closure (tests/gate-common.sh, `source_identity`), checked unchanged
# after every build and every target, the difference written when it moved.
unchanged() {
	if ! same_source "$logs"; then
		printf 'SOURCE CHANGED\n' >>"$logs/results.txt"
		source_identity >"$logs/current-identity-inputs.txt"
		diff -u "$logs/identity-inputs.txt" "$logs/current-identity-inputs.txt" >&2 || true
		exit 1
	fi
}

# Fuzzing checks the existing oracles; inherited recorder settings must not
# turn a campaign into baseline publication or cost-record generation.
unset DCBOR_RECORD_FACTORS DCBOR_RECORD_TRACES DCBOR_COST_MODE DCBOR_COST_DIRECTORY DCBOR_CLASS_COVERAGE
# The campaign's identity: the gates' one identity (tests/gate-common.sh),
# with the fuzzer, its seconds per target and its seed.
{
	printf 'fuzzer\t%s\n' "$(cargo fuzz --version)"
	printf 'seconds_per_target\t%s\tseed\t%s\n' "$seconds" "$seed"
} | identity "$logs"
printf 'Campaign identity: %s\n' "$(cat "$logs/identity.txt")"
date -u >"$logs/started.txt"

if cargo fuzz build >"$logs/build.log" 2>&1; then
	unchanged
	printf 'BUILD PASS\n' >>"$logs/results.txt"
else
	status=$?
	printf 'BUILD FAIL exit=%s\n' "$status" >>"$logs/results.txt"
	cat "$logs/build.log"
	exit "$status"
fi

while read -r target max_len; do
	printf 'Running %s (%ss); log: %s/%s.log\n' "$target" "$seconds" "$logs" "$target"
	if cargo fuzz run "$target" -- \
		-seed="$seed" -max_total_time="$seconds" -max_len="$max_len" \
		-timeout=30 -rss_limit_mb=4096 -print_final_stats=1 \
		>"$logs/$target.log" 2>&1; then
		unchanged
		printf '%s PASS\n' "$target" >>"$logs/results.txt"
	else
		status=$?
		printf '%s FAIL exit=%s\n' "$target" "$status" >>"$logs/results.txt"
		cat "$logs/$target.log"
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
owned_lifecycle 1024
TARGETS

cat "$logs/results.txt"
printf 'Campaign complete: %s\n' "$logs"
