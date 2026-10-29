#!/usr/bin/env bash
# The same production mutation domain, tests, features and toolchain in both
# layers. Timeouts and noncompiling mutants are not counted as caught defects.
# `unsafe fn` bodies are mutated like any other (--mutate-unsafe=true). A
# survivor of both layers in a module holding `unsafe`, or a descendant of
# one, is decided under Miri on the tests that reach it (the reach map,
# tests/reach-map.sh; the judge, tests/miri-owned.sh --judge), against an
# unmutated Miri gate run of the same identity (tests/mutation-evidence.py).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=tests/gate-common.sh
source tests/gate-common.sh
: "${DCBOR_CONFIGURATION:?run in the configured development shell}"
: "${TMPDIR:?required: the campaign's log directory}"
for tool in cargo rustc cargo-mutants cargo-llvm-cov python3 patch time systemd-run systemctl sha256sum; do
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
snapshot >"$logs/source.sha256"
# Mutation runs must never publish or validate baselines against mutated code.
# A wall-clock ceiling decides nothing here: it depends on the host's load,
# not on the mutant (tests/resumable/native_latency.rs).
unset DCBOR_RECORD_FACTORS DCBOR_RECORD_TRACES DCBOR_COST_MODE DCBOR_COST_DIRECTORY DCBOR_CLASS_COVERAGE DCBOR_LATENCY_QUALIFICATION
# The mutation domains (tests/mutation-evidence.py, DOMAINS): each its
# features, the files its mutants are drawn from, and the tests that judge
# them. Every feature compiles all but the code written for builds without
# std; that code is a domain of its own, built as the no_std legs build it.
domains=(all-features no_std)
configure() {
	domain_features "$1"
	case "$1" in
	all-features)
		filters=(--file 'src/bounded/decode/storage.rs'
			--file 'src/bounded/decode/construction/stable.rs'
			--file 'src/bounded/decode/construction/in_place/*.rs'
			--file 'src/bounded/decode/construction/in_place/btree/*.rs'
			--file 'src/bounded/decode/construction/reclamation/*.rs'
			--file 'src/bounded/encoding/writer.rs'
			--file 'src/bounded/text_cursor/initialization.rs')
		tests=(--workspace --all-targets)
		;;
	no_std)
		# The domain's only code compiled without std and never under every
		# feature: the decode scope's abort, in the file that holds it. The
		# derive crate's tests need std, so the package's own targets judge.
		filters=(--file 'src/bounded/decode/construction/reclamation/owned.rs')
		tests=(--package dcbor --all-targets)
		;;
	*)
		printf 'unknown mutation domain: %s\n' "$1" >&2
		exit 2
		;;
	esac
}
# The Miri layer's rigor: the Miri gate's own default layer, the same for
# the reach map, the unmutated baseline and every judgement.
miri_rigor=fast
# The run's identity: one digest over its whole input closure, so evidence
# from different code, toolchain, configuration or domain can never be
# taken for this run's. The snapshot, the shell's configuration (the
# toolchain and fork revisions), the compiler and Cargo (gate-common.sh's
# `identity`); the cargo-mutants version; each domain's features, files and
# test selection; the Miri layer's rigor and each model's flags.
{
	cargo-mutants --version
	printf 'mutate-unsafe\ttrue\n'
	for domain in "${domains[@]}"; do
		configure "$domain"
		printf 'domain\t%s\tfeatures\t%s\tfiles\t%s\ttests\t%s\n' \
			"$domain" "${features[*]}" "${filters[*]}" "${tests[*]}"
	done
	printf 'miri\trigor\t%s\n' "$miri_rigor"
	for model in "${MIRI_MODELS[@]}"; do
		printf 'model\t%s\tMIRIFLAGS\t%s\n' "$model" "$(miri_flags "$model")"
	done
} | identity "$logs"
printf 'Mutation run identity: %s\n' "$(cat "$logs/identity.txt")"
for domain in "${domains[@]}"; do
	configure "$domain"
	mkdir -p "$logs/$domain"
	for layer in fast exhaustive; do
		status=0
		DCBOR_RIGOR="$layer" "${contained[@]}" cargo-mutants mutants --no-config "${features[@]}" \
			--no-shuffle --mutate-unsafe=true --cargo-arg=--offline "${filters[@]}" \
			--output "$logs/$domain/$layer" \
			-- "${tests[@]}" >"$logs/$domain/$layer.log" 2>&1 || status=$?
		printf '%s\n' "$status" >"$logs/$domain/$layer.exit"
		case "$status" in
		0 | 2 | 3) ;;
		*)
			cat "$logs/$domain/$layer.log"
			exit "$status"
			;;
		esac
		snapshot >"$logs/$domain/$layer-source.sha256"
		diff -u "$logs/source.sha256" "$logs/$domain/$layer-source.sha256"
	done
	# A mutant missed by both layers passes only as a declared equivalent
	# of its domain (tests/mutation-equivalents.json, part of the snapshot),
	# or, in a tainted module, when Miri catches it.
	python3 tests/mutation-evidence.py compare "$logs/$domain/fast/mutants.out" \
		"$logs/$domain/exhaustive/mutants.out" tests/mutation-equivalents.json \
		"$domain" "$logs/$domain/comparison.json"
done

# The Miri layer's inputs, on the unmutated tree: the reach map, and the
# Miri gate's per-test record under both models, the judge's baseline.
DCBOR_RIGOR="$miri_rigor" DCBOR_REACH_DIR="$logs/reach" tests/reach-map.sh >"$logs/reach.log" 2>&1 || {
	cat "$logs/reach.log"
	exit 1
}
DCBOR_RIGOR="$miri_rigor" MIRI_LOG_DIR="$logs/miri-baseline" "${contained[@]}" tests/miri-owned.sh \
	>"$logs/miri-baseline.log" 2>&1 || {
	cat "$logs/miri-baseline.log"
	exit 1
}

verdict=0
for domain in "${domains[@]}"; do
	python3 tests/mutation-evidence.py miri-plan "$logs/$domain/comparison.json" \
		"$logs/$domain/fast/mutants.out" "$logs/source.sha256" "$logs/reach" "$logs/$domain/miri-plan"
	DCBOR_RIGOR="$miri_rigor" "${contained[@]}" tests/miri-owned.sh --judge \
		"$logs/$domain/miri-plan/plan.tsv" "$logs/$domain/miri" "$logs/miri-baseline" \
		>"$logs/$domain/miri.log" 2>&1 || {
		cat "$logs/$domain/miri.log"
		exit 1
	}
	snapshot | diff -u "$logs/source.sha256" -
	python3 tests/mutation-evidence.py miri-verdict "$logs/$domain/comparison.json" \
		"$logs/$domain/miri-plan" "$logs/$domain/miri/verdicts.tsv" "$logs/$domain/verdict.json" ||
		verdict=1
done
printf 'Mutation evidence: %s\n' "$logs"
exit "$verdict"
