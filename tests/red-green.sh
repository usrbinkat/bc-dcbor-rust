#!/usr/bin/env bash
# Test adequacy: whether each test catches the defect class it claims to,
# run apart from implementation validation (./run_tests.sh), which neither
# runs nor reads anything here, and no calibration or qualification
# (tests/proofs.sh) waits on.
#
# First the evidence tooling's own tests and lints: the record format, the
# model-bounds and census rows, and the gate tool (outcomes, rows, Miri
# results and judgements, bound derivation, the reach map, the mutation
# comparison and verdicts, the cost recorder, the launchers' contracts, the
# proof gate's records). Then the planted controls of the channel given
# (tests/controls.sh, every argument passed through): each control's diff
# seen refused by its own rule, then restored.
#
# Usage: tests/red-green.sh {nightly|stable|kani} [RUNNER...] [--only NAME...]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
(($# >= 1)) || {
    echo "usage: tests/red-green.sh {nightly|stable|kani} [RUNNER...] [--only NAME...]" >&2
    exit 2
}
TOOLING=(dcbor-record dcbor-model-bounds dcbor-census dcbor-gate)
packages=()
for package in "${TOOLING[@]}"; do
    packages+=(-p "$package")
done
echo "=== Evidence tooling tests ==="
cargo test --quiet "${packages[@]}"
cargo clippy "${packages[@]}" --all-targets -- -D warnings
echo "=== Planted controls: $* ==="
exec bash tests/controls.sh "$@"
