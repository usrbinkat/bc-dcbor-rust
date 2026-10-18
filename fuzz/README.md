# Bounded encoding fuzz targets

For Nix-managed Rust without rustup, use local `nixpkgs` and `rust-overlay`
checkouts. This avoids GitHub registry resolution; uncached toolchain archives
and packages still require downloads. Substitute your checkout paths:

```sh
nix-shell fuzz/shell.nix \
  -I nixpkgs=/workspace/usrbinkat/github.com/NixOS/nixpkgs \
  --arg nixpkgsPath /workspace/usrbinkat/github.com/NixOS/nixpkgs \
  --arg rustOverlayPath /workspace/usrbinkat/github.com/oxalica/rust-overlay \
  --run 'bash fuzz/smoke.sh'
```

The `-I` option also directs nix-shell's own `<nixpkgs>` lookup for
`bashInteractive` to the local checkout; `--arg nixpkgsPath` alone does not.
The shell supplies nightly Rust and `cargo-fuzz`. `smoke.sh` builds all targets
and runs the six smoke checks, stopping on the first failure. Toolchain selection
follows the supplied checkouts; pin their revisions in reproducible CI setups.

Run with `cargo-fuzz` available on PATH and a rustup-installed nightly Rust
toolchain from the repository root. Explicit `rustup run` also works when the
default `cargo` on PATH is a standalone executable rather than a rustup proxy:

```sh
rustup run nightly cargo fuzz build
rustup run nightly cargo fuzz run numeric -- -runs=1000 -max_len=8
rustup run nightly cargo fuzz run text -- -runs=1000 -max_len=4096
rustup run nightly cargo fuzz run nested -- -runs=1000 -max_len=32
rustup run nightly cargo fuzz run refusals -- -runs=1000 -max_len=66
rustup run nightly cargo fuzz run decode -- -runs=1000 -max_len=4096
rustup run nightly cargo fuzz run representations -- -runs=1000 -max_len=256
```

Input sizes and nesting are explicitly bounded. The shared runner checks exact
length, canonical bytes, predicted write work, retry after refusal, and scratch
and output permit release. Output storage is admitted before fallible allocation
and retains its permit until storage is dropped; initialization work is admitted
before filling the buffer. Refusal schedules are derived from input: the low bit
selects preparation or writing, and the remaining bits select the admission
index. A write-phase schedule permits preparation to complete so its refusal is
reachable. Finite work and live-storage limits provide a second bound.

Numeric value preservation and cross-precision identity supplement differential
comparison. Unicode expectations use the upstream normalizer; the independent
Unicode 17 corpus remains in `tests/normalization.rs`. Actual heap-failure and
write-allocation instrumentation lives in `tests/bounded_adversarial.rs`.

`decode` covers malformed bytes, admitted parsing, and refusal cleanup. It calls
the symbolic decoder only after bounded validation has established depth <= 32.
`representations` exercises sorted dynamic maps, symbolic values, explicit tags,
standalone options, and positive/negative bignums. Both cap input size inside the
target, independently of libFuzzer arguments.

For a stable-toolchain source compilation check (not a fuzz execution):

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

These targets are operational only after their build and smoke runs succeed on
the tested tree; adding source files does not establish that verification.
