# Bounded encoding contract tests

## Independent correctness

- `numeric_profile.rs`: draft-mcnally-deterministic-cbor-12 §7.1 literals
  through symbolic and bounded encoders, in every exactly representing float
  source precision; all §7.2 rejection vectors; all 65,536 half patterns;
  adjacent single- and double-precision values at every finite normal exponent
  boundary, public extraction refusal for rounded integers, and numeric map-key
  identity across source precisions.
- `normalization.rs`: all five NFC identities for each of 20,034 Unicode
  17.0.0 conformance rows; independently expected long ordered, reversed and
  equal-class combining runs, expansion, and Hangul contraction.
- `derive.rs`: exact bytes for hostile field names and generic fields, alongside
  symbolic/bounded equivalence for the supported derived shapes.
- `dcbor-derive/tests/ui.rs`: downstream compile-pass fixtures with warnings
  denied and compile-fail diagnostics for invalid schemas.
- `bounded_extended.rs`: literal encodings for nullable options, tags, dates,
  bignums and symbolic values; dynamic-map order and canonical collisions;
  borrowed decoder navigation, malformed inputs and 10,000-level nesting;
  supplementary acceptance comparisons over all one- and two-byte inputs.
- `normalization.rs` also bounds the reported work growth of reversed combining
  runs. Canonical ordering now uses stable counting sort, not insertion sorting.

## Adverse resource behavior

`bounded_adversarial.rs` uses public APIs and a thread-local global-allocator
observer in its own integration-test executable. Allocation instrumentation
has a positive control. Inputs and test bookkeeping are constructed before
observation; assertions run after observation.

The battery discovers admission/allocation counts from a successful run, then
refuses **each successive admission** and fails **each successive real heap
request**. It does not hard-code internal buffer sizes or callback counts.
It checks permit release, typed failure propagation, no further admissions
after refusal, admission before heap requests, and old/new reservation overlap.

Writes are checked for real heap requests on success and every refusal, output
canaries, retry with the same preparation, and predicted-work enforcement.
Malformed implementations exercise understated work, cumulative work overflow,
incorrect lengths, missing/unconsumed plans, false fixed predictions, and
fixed-measure overflow. Every head width is checked against every shorter output
length for atomic refusal and against literal payloads for all eight major types.
An isolated growth test checks overlapping old/new permits and preservation of
the old allocation after a failed replacement.

The decoder, dynamic-map preparation, symbolic traversal, tagged/date/bignum
emission and the production output owner have additional admission, actual heap
failure, permit cleanup and allocation-free-write coverage in the same harness.

## Interpretation

These tests do not make arbitrary trait implementations trustworthy. They
cannot detect unreported CPU work, guarantee semantic stability through
interior mutability, or turn requested allocator capacity into a bound on RSS.
They validate the built-in paths and the enforcement boundaries exposed by the
API. The symbolic decoder is not a resource-bounded decoder. The separate
`bounded::decode::decode` API validates into an admitted flat borrowed document.
Its parser and destruction are iterative; it does not allocate symbolic nodes.

The numeric profile changes wire compatibility: wider negative major-type-1
integers are rejected, exactly equal float source types encode identically,
and negative f32 reduction preserves the input value. Direct construction of
`CBORCase::Negative` remains a low-level escape hatch; callers can construct
out-of-profile symbolic values. The bounded encoder accepts `CBOR`, but rejects
out-of-profile negative values and paths exceeding 128 symbolic nodes.

Run the complete workspace battery with:

```sh
cargo test --workspace --all-features
```

The derive crate's UI suite is also runnable independently:

```sh
cargo test -p dcbor-derive --test ui
```

Additional completion gates:

```sh
cargo test -p dcbor
cargo test -p dcbor-derive --doc
cargo check --no-default-features --features no_std,derive
cargo check --no-default-features --features no_std,derive,num-bigint
cargo doc --no-deps
```

`fuzz/README.md` records the six bounded-input fuzz targets and their build and
smoke commands. Source availability is not evidence that those runs succeeded.
The bounded module's executable output-owner example demonstrates separate
output admission, fallible allocation, initialization admission, permit lifetime
and discard on write refusal. It is not a verified external consumer adapter.

`docs/bounded-consumers.md` explains the executable record adapter, borrowed
decoder, and optional Linux worker isolation example. The latter requires
deployment-level cgroup/systemd checks and does not establish an exact RSS bound.
