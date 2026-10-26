#!/usr/bin/env bash
# The same production mutation domain, tests, features and toolchain in both
# layers. Timeouts and noncompiling mutants are not counted as caught defects.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
: "${TMPDIR:?set TMPDIR to the session scratchpad}"
for tool in cargo cargo-mutants python3 systemd-run systemctl; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Mutation prerequisite missing from PATH: %s. Re-enter the project development shell.\n' "$tool" >&2
		exit 127
	fi
done
# A mutant can turn a bounded loop into unbounded allocation (one grew a
# test binary past 110 GB). Each layer runs in its own memory-capped scope
# of the user's systemd manager: the kernel kills the runaway test inside
# the scope, which cargo-mutants records as a failed test, and
# OOMPolicy=continue keeps the campaign and every other session running.
# The cap is the host's to choose; there is no uncapped fallback.
: "${DCBOR_MUTATION_MEMORY:=48G}"
case "$(systemctl --user is-system-running 2>/dev/null || true)" in
running | degraded) ;;
*)
	printf 'Mutation containment needs a running user systemd manager (systemctl --user).\n' >&2
	exit 1
	;;
esac
contained=(systemd-run --user --scope --quiet --collect
	--property=MemoryMax="$DCBOR_MUTATION_MEMORY"
	--property=MemorySwapMax=0
	--property=OOMPolicy=continue
	--)
logs="$(mktemp -d "$TMPDIR/dcbor-mutations.XXXXXX")"
printf 'Mutation evidence logs: %s\n' "$logs"
printf '%s\n' "$DCBOR_CONFIGURATION" >"$logs/configuration.txt"
printf 'memory cap per layer: %s, no swap\n' "$DCBOR_MUTATION_MEMORY" | tee "$logs/containment.txt"
export CARGO
CARGO="$(command -v cargo)"
# Invoke the subcommand directly so CARGO remains the active shell's wrapper,
# including its build-std and target settings, in each copied build directory.
snapshot() {
	find src dcbor-derive/src tests -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.txt' -o -name '*.sh' -o -name '*.py' \) -print0 |
		LC_ALL=C sort -z | xargs -0 sha256sum
	sha256sum Cargo.toml flake.nix nix/btree-in-place.patch
	for file in Cargo.lock flake.lock; do
		if [[ -f "$file" ]]; then sha256sum "$file"; fi
	done
}
snapshot >"$logs/source.sha256"
# Mutation runs must never publish or validate baselines against mutated code.
unset DCBOR_RECORD_FACTORS DCBOR_RECORD_TRACES DCBOR_COST_MODE DCBOR_COST_DIRECTORY DCBOR_CLASS_COVERAGE
filters=(--file 'src/bounded/decode/storage.rs'
	--file 'src/bounded/decode/construction/in_place/*.rs'
	--file 'src/bounded/decode/construction/in_place/btree/*.rs'
	--file 'src/bounded/decode/construction/reclamation/*.rs'
	--file 'src/bounded/encoding/writer.rs'
	--file 'src/bounded/text_cursor/initialization.rs')
for layer in fast exhaustive; do
	status=0
	DCBOR_RIGOR="$layer" "${contained[@]}" cargo-mutants mutants --no-config --all-features \
		--no-shuffle --cargo-arg=--offline "${filters[@]}" --output "$logs/$layer" \
		-- --workspace --all-targets >"$logs/$layer.log" 2>&1 || status=$?
	printf '%s\n' "$status" >"$logs/$layer.exit"
	case "$status" in
	0 | 2 | 3) ;;
	*)
		cat "$logs/$layer.log"
		exit "$status"
		;;
	esac
	snapshot >"$logs/$layer-source.sha256"
	diff -u "$logs/source.sha256" "$logs/$layer-source.sha256"
done
python3 tests/mutation-evidence.py "$logs/fast/mutants.out" \
	"$logs/exhaustive/mutants.out" "$logs/comparison.json"
printf 'Mutation evidence: %s\n' "$logs"
