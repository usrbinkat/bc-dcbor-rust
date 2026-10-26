# Bounded encoding contract tests

## Independent correctness

- `numeric_profile.rs`: draft-mcnally-deterministic-cbor-12 §7.1 literals
  through symbolic and bounded encoders, in every exactly representing float
  source precision; all §7.2 rejection vectors; all 65,536 half patterns;
  adjacent single- and double-precision values at every finite normal exponent
  boundary, public extraction refusal for rounded integers, and numeric map-key
   identity across source precisions; integer-to-float coercion and rejection
   of fractional float-to-integer conversion. Invalid published vectors name
   their exact rejection classes.
- `normalization.rs`: all five NFC identities for each of 20,034 Unicode
  17.0.0 conformance rows; independently expected long ordered, reversed and
   equal-class combining runs, expansion, and Hangul contraction. Both encoders
   must agree on each conformance input; distinct NFD forms must be rejected
   as `NonCanonicalString` by symbolic decoding.
- `derive.rs`: exact bytes for hostile field names and generic fields, alongside
   symbolic/bounded equivalence for the supported derived shapes. Shared record,
   newtype, enum and tagged fixtures exercise their applicable trait paths.
   Typed round trips compare canonical values: a decomposed source label is
   explicitly expected to become NFC. Unit structs retain their distinct null
   construction check. Tagged decoding requires the tag even though ordinary
   conversion and bounded preparation encode the untagged payload.
- `dcbor-derive/tests/ui.rs`: downstream compile-pass fixtures with warnings
  denied and compile-fail diagnostics for invalid schemas.
- `bounded_extended.rs`: literal encodings for nullable options, tags, dates,
   bignums, byte strings, short/long text and symbolic values; dynamic-map order and canonical collisions;
  borrowed decoder navigation, malformed inputs and 10,000-level nesting;
   supplementary acceptance comparisons over all one- and two-byte inputs.
- `encode.rs` retains rendering, integer-width conversion, map accessor,
  tagged round-trip and date conversion assertions not supplied by the bounded
  wire fixtures. `num_bigint.rs` retains independent RFC literal vectors as
  well as conversion, rejection and summarizer contracts; a generated boundary
  sweep is not a replacement for those literal oracles.
- `normalization.rs` also bounds the reported work growth of reversed combining
  runs. Encoding normalizes with the retained normalizer, which orders each
  combining run of two or more parts by two stable counting passes over the
  low and high four bits of the combining class, a counter table of one
  quantum, and leaves a run of one in place; the decoder's synchronous text
  validation orders by stable counting sort over the 256 classes.

## Resource bounds

Every bounded and retained operation has a whole-operation `ResourceBound`
derived from its input, schema or source shape, summed from one term per
place its operation charges, and each is checked against the production
operation it bounds. Each place is checked against its own term, so the slack
of the sum cannot hide an understated term. The same check, with a witnessed
place's term removed, must fail at that place, and that failing scenario ships
beside the passing one. `resumable/COVERAGE.md` maps each bound to its checks:
per place, coverage, and tightness where a test pins it.

Every admission this crate's engines and derive-generated code make goes
through one attributed route; `resumable/CONTRACT.md` (Admission route and
trusted domain) states the route, the trusted domain of user trait
implementations, and the three mechanisms that enforce it.

## Adverse resource behavior

The shared matrix supports `DCBOR_RIGOR=fast` (default) and
`DCBOR_RIGOR=exhaustive`. Both use identical correctness and custody oracles.
Fast resumes every admission refusal in one pass, fails every physical
request, and exercises every stop except those represented by a certified
cleanup class. Exhaustive additionally replays every admission refusal and
every stop independently and compares members of each declared class.
Unclassified boundaries are never sampled.

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
canaries, retry with the same preparation, and the write bound
(`Prepared::write_work`). Sources breaking the schema contract exercise an
encoding longer when prepared than when walked (refused at the arena's cap), a
counted map visiting another count, an entry past its bucket window, and
endless nesting (refused by the walk before any allocation). Already-normal
text and numeric arrays request exactly the plan's arenas, as a byte string of
the same encoded length does. Every head width is checked against every wrong
output length for refusal before admission or writing, and against literal
bytes for all eight major types. An isolated growth test checks overlapping
old/new permits and preservation of the old allocation after a failed
replacement.

The decoder, dynamic-map preparation, symbolic traversal, tagged/date/bignum
emission and publication in place have additional admission, actual heap
failure, permit cleanup and allocation-free-write coverage in the same
harness; each published encoding is checked to hold at least its bytes and at
most what `encode_bound` retains.

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
output admission through `Prepared::encode_owned` (fallible allocation,
initialization admission, permit lifetime and discard on write refusal). It is
not a verified external consumer adapter.

`docs/bounded-consumers.md` explains the executable record adapter, borrowed
decoder, and optional Linux worker isolation example. The latter requires
deployment-level cgroup/systemd checks and does not establish an exact RSS bound.

## Feature selection and measured effectiveness

`run_tests.sh` checks `DCBOR_RIGOR` before running commands. In fast mode,
the feature-local derive/hashbrown/bigint legs omit only `normalization` and
`version-numbers`: Unicode normalization has no behavior selected by those
features, and version synchronization is package metadata. All other test
targets run, including newly added targets. Both omitted targets run in the
full default and workspace legs. `no_std` changes infrastructure and
`multithreaded` changes CBOR's ownership representation, so those legs remain
full. Exhaustive runs every target in every leg, independently checking the
feature-independence assumption. Every target is linted in every leg.
The support crate disables its dependency's defaults so it cannot silently
enable std in a no_std leg through feature unification.

Matrix cost recording and checking are in `data/README.md`. Costs include
schedule selection; they are not inferred from wall-clock duration.

`bash tests/mutation-evidence.sh`, in the configured development shell,
measures both layers against the same cargo-mutants domain: storage,
in-place binding construction/cleanup, owned queue reclamation, owned
emission and normalizer initialization. The shell supplies cargo-mutants
and Python; no installation or source-tree mutation is performed by the
script. Cargo-mutants uses copied build directories and the active Cargo
wrapper. Each layer first requires a successful unmutated baseline.

Each layer runs in its own scope of the user's systemd manager, capped at
`DCBOR_MUTATION_MEMORY` (default `48G`) with no swap and
`OOMPolicy=continue`: a mutant that turns a bounded loop into unbounded
allocation has its test killed inside the scope, recorded as a failed
test, while the campaign and every other session keep running. A host
without a running user manager is refused; the campaign never runs
uncapped. The cap applied is written to `containment.txt` in the logs.

Set `TMPDIR` to the session scratchpad. Logs, source hashes, mutant diffs,
outcomes and `comparison.json` are retained there. The comparator requires
identical planned mutants and diffs, complete outcomes and identical tool
versions. It reports each layer's caught count over the common viable
domain, misses by both, and either direction of detection disagreement.
Timeouts do not count as detections; incomplete runs, viability differences,
an empty viable domain, or detection disagreements fail. Equal detection
does not assert that mutants missed by both layers are harmless. The report
names them explicitly. Evidence applies only to the measured domain.

The comparator's planted-defect checks run with:

```sh
python3 -B tests/mutation_evidence_test.py
```
