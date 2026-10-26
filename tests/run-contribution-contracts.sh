#!/usr/bin/env bash
# Invoke through nix develop -c bash tests/run-contribution-contracts.sh.
# Keep compile-contract failures from hiding independent runtime regressions.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
log_dir="${CONTRACT_LOG_DIR:-${TMPDIR:?set TMPDIR to the session scratchpad}/contribution-contracts}"
mkdir -p "$log_dir" || exit 2
status=0
# The verification layer every matrix runs: fast, the default, or
# exhaustive (tests/support/rigor.rs); exported so every suite runs the same
# layer, and printed so the run names it.
export DCBOR_RIGOR="${DCBOR_RIGOR:-fast}"
case "$DCBOR_RIGOR" in
fast | exhaustive) ;;
*)
	echo "DCBOR_RIGOR must be fast or exhaustive" >&2
	exit 2
	;;
esac
echo "rigor: $DCBOR_RIGOR"
# Fork qualification consumes approved local evidence (or DCBOR_COST_BASELINE
# supplied by the artifact store). It never records a baseline during a check.
for evidence in check check-costs; do
	arguments=("$evidence")
	label="$evidence"
	if [[ "$evidence" == check-costs && -n "${DCBOR_COST_REUSE:-}" ]]; then
		arguments+=("$DCBOR_COST_REUSE")
		label="$evidence reused completed run: $DCBOR_COST_REUSE"
	fi
	if bash tests/record-evidence.sh "${arguments[@]}" >"$log_dir/evidence-$evidence.log" 2>&1; then
		echo "PASS evidence-$label"
	else
		echo "FAIL evidence-$evidence ($log_dir/evidence-$evidence.log)"
		status=1
	fi
done
for suite in optional_admission owned_input owned_inspection owned_decode owned_lifecycle_matrix owned_physical_failure contribution_capabilities owned_public_contract owned_pipeline_matrix owned_pipeline_interleavings; do
	started=$SECONDS
	if cargo test --test "$suite" -- --nocapture >"$log_dir/$suite.log" 2>&1; then
		echo "PASS $suite ($((SECONDS - started))s)"
	else
		echo "FAIL $suite ($((SECONDS - started))s, $log_dir/$suite.log)"
		status=1
	fi
done
if cargo test --manifest-path tests/owned_lifetimes/Cargo.toml --doc >"$log_dir/owned_lifetimes.log" 2>&1; then
	echo "PASS owned_lifetimes"
else
	echo "FAIL owned_lifetimes ($log_dir/owned_lifetimes.log)"
	status=1
fi
exit "$status"
