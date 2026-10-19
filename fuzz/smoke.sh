#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo fuzz build
cargo fuzz run numeric -- -runs=1000 -max_len=8
cargo fuzz run text -- -runs=1000 -max_len=4096
cargo fuzz run nested -- -runs=1000 -max_len=32
cargo fuzz run refusals -- -runs=1000 -max_len=66
cargo fuzz run decode -- -runs=1000 -max_len=4096
cargo fuzz run decode_schedule -- -runs=1000 -max_len=4096
cargo fuzz run schema_schedule -- -runs=1000 -max_len=1024
cargo fuzz run representations -- -runs=1000 -max_len=256
