# Bounded encoding fuzz targets

## Recorded campaign using the project flake

From the repository root:

```sh
nix develop -c bash fuzz/qualify.sh
```

This builds all nine existing targets and runs each for 600 seconds (about
90 minutes total, plus compilation and corpus initialization). Each target uses
seed 20261019, its own input-size ceiling, a 30-second per-input timeout, and a
4096 MiB RSS limit. Existing corpora and crash artifacts are retained.

The script prints its unique temporary log directory. It records toolchain
versions, source hashes, campaign settings, build output, per-target output and
final statistics, and pass/fail status in `results.txt`. It stops on the first
failure and prints that log's tail. Set `FUZZ_LOG_DIR` to choose a persistent
directory; an existing campaign's results are never overwritten.

```sh
FUZZ_SECONDS=60 FUZZ_SEED=42 nix develop -c bash fuzz/qualify.sh
```

This campaign covers every target described below.

The flake's shell supplies everything fuzzing runs: its pinned nightly, built
against the forked standard library every other gate uses, and `cargo-fuzz`.
Its inputs are locked, so once the shell has been realized it starts without
network access (`nix develop --offline`); nothing is resolved from GitHub.
`smoke.sh` builds all targets and runs a short check of each, stopping on the
first failure:

```sh
nix develop -c bash fuzz/smoke.sh
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
`decode_schedule` exercises the retained production decoder: it selects an actual
admission from a baseline, observes refusal, resumes the same cursor, compares
cumulative work and outcome, and separately cancels at that admission. It also
checks proper prefixes and a mutated input, enforcing three-value/64-byte step
bounds and zero retained reservations after destruction.
`schema_schedule` exercises derived schema preparation with nested arrays,
optional fields, normalization, multiple integer-key widths, and sparse dynamic
tables nested as keys and values. Derived records inside table values exercise
header-gap compaction. It requires a
positively observed admission refusal, same-cursor resumption with unchanged
cumulative work, cancellation cleanup, bounded preparation and writer steps,
and exact agreement with the synchronous encoder or a separately constructed
symbolic map oracle.
`representations` exercises sorted dynamic maps, symbolic values, explicit tags,
standalone options, and positive/negative bignums. Both cap input size inside the
target, independently of libFuzzer arguments.
`owned_lifecycle` drives, through the shared driver (`dcbor-test-support`'s
`pipeline`), the owned typed decode of a custom input over arbitrary bytes and
then, for inputs of at most 1024 bytes, the owned pipeline (acquisition,
decoding, owned preparation and emission). The input's first two bytes select
each schedule, a `pipeline::Schedule`: one admission refused and resumed, its
accounting compared with the unobstructed run's (no replay); in the pipeline,
one physical request failed; and one stop at an observed boundary, a cancel in
the decode and a retire or cancel, as the input's fourth byte selects, in the
pipeline. Each run is a single schedule, never grouped with another, so its
boundaries are unclassified (`Classes::none()`); class reduction and its checks
belong to the deterministic matrices. Under normalizing options the decoded
text must equal the symbolic decoder's, and the pipeline must publish exactly
when the input is canonical text. libFuzzer aborts before any unwind, so
unwinding stops are qualified by `tests/owned_pipeline_matrix.rs`.

For a stable-toolchain source compilation check (not a fuzz execution), in
the flake's stable shell:

```sh
nix develop .#stable -c cargo check --manifest-path fuzz/Cargo.toml --bins
```

These targets are operational only after their build and smoke runs succeed on
the tested tree; adding source files does not establish that verification.
