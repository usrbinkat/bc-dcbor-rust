#!/bin/sh
# Linux user-systemd/cgroup-v2 boundary. Fail closed if the service manager or
# required controls are unavailable; never fall back to unconfined execution.
set -eu
if [ "$#" -eq 0 ]; then
	echo "usage: sh examples/run-bounded-worker.sh /absolute/path/to/worker [args...]" >&2
	exit 2
fi
exec systemd-run --user --quiet --wait --pipe --collect --service-type=exec \
	--property=MemoryAccounting=yes \
	--property=MemoryMax=96M \
	--property=MemorySwapMax=0 \
	--property=LimitCPU=2 \
	--property=RuntimeMaxSec=5s \
	--property=TimeoutStopSec=1s \
	--property=KillMode=control-group \
	--property=NoNewPrivileges=yes \
	-- "$@"
