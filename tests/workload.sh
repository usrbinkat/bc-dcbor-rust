#!/usr/bin/env bash
# The one launch of a gate's workload (tests/gate-common.sh,
# `gate_confinement`; the gate tool, tests/gate `process::workload`): the
# command given, a checker, a test binary or a build, run in a transient
# scope of its own of the user's systemd manager, its memory capped at
# DCBOR_GATE_MEMORY with no swap. `systemd-run --scope` registers the scope
# and execs the command in place, as this script execs it, so the workload
# keeps the PID, parent, group and session it was started with, and its
# exit status or signal is the caller's to read. The caller (a gate, the
# gate tool judging a run, GNU time measuring one) stays outside the scope:
# an out-of-memory kill chooses its victim among the workload's processes
# alone, so the caller survives to classify the run, complete or not.
# Inside the scope every process remains an eligible victim, a checker's
# driver (kani-driver) as much as its solver (CBMC); OOMPolicy=continue only
# keeps systemd from ending the rest of the workload's tree after a kill, so
# whatever survives may still report, which nothing relies on.
#
# A caller that bounds its workload's time sets DCBOR_WORKLOAD_DEADLINE to
# whole seconds (tests/gate `process::bounded`): the scope's RuntimeMaxSec
# (systemd.scope(5), systemd 244 and later), so the manager stops every
# process of the scope at the deadline, not only the one the caller started.
# The variable is the launcher's alone: the workload does not inherit it.
set -euo pipefail
: "${DCBOR_GATE_MEMORY:?run a workload from a gate (tests/gate-common.sh, gate_confinement)}"
deadline=()
if [[ -n "${DCBOR_WORKLOAD_DEADLINE:-}" ]]; then
    [[ "$DCBOR_WORKLOAD_DEADLINE" =~ ^[1-9][0-9]*$ ]] || {
        echo "DCBOR_WORKLOAD_DEADLINE must be a positive number of seconds: $DCBOR_WORKLOAD_DEADLINE" >&2
        exit 2
    }
    deadline=(--property=RuntimeMaxSec="$DCBOR_WORKLOAD_DEADLINE")
fi
unset DCBOR_WORKLOAD_DEADLINE
exec systemd-run --user --scope --quiet --collect \
    --property=MemoryMax="$DCBOR_GATE_MEMORY" --property=MemorySwapMax=0 --property=OOMPolicy=continue \
    "${deadline[@]}" -- "$@"
