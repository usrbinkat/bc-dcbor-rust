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

`fuzz/README.md` records the nine fuzz targets, `owned_lifecycle` among
them, and their build and smoke commands. Source availability is not evidence that those runs succeeded.
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
measures both layers against the same cargo-mutants domain, for each of two
domains: every feature, over storage, in-place binding construction and
cleanup, owned queue reclamation, owned emission and normalizer
initialization; and `no_std`, over the owned scope's reclamation, the only
code of that domain compiled without std and never under every feature.
The shell supplies cargo-mutants (with `--mutate-unsafe`, so `unsafe fn`
bodies are in the domain), cargo-llvm-cov and Python; nothing is installed.
Cargo-mutants uses copied build directories and the active Cargo wrapper.
Each layer first requires a successful unmutated baseline.

Each layer runs in its own scope of the user's systemd manager, capped at
`DCBOR_MUTATION_MEMORY` (default `48G`) with no swap and
`OOMPolicy=continue`: a mutant that turns a bounded loop into unbounded
allocation has its test killed inside the scope, recorded as a failed
test, while the campaign and every other session keep running. A host
without a running user manager is refused; the campaign never runs
uncapped. The cap applied is written to `containment.txt` in the logs.

`TMPDIR` is required: the campaign's log directory. Logs, source hashes,
mutant diffs, outcomes and each domain's `comparison.json` are retained
there, with the run's identity over its whole input closure. The comparator requires
identical planned mutants and diffs, complete outcomes and identical tool
versions. It reports each layer's caught count over the common viable
domain, misses by both, and either direction of detection disagreement.
Timeouts do not count as detections; incomplete runs, viability differences,
an empty viable domain, or detection disagreements fail. A mutant missed by
both layers fails the run unless `mutation-equivalents.json` declares it
equivalent in its domain, by its file, mutation, removed and inserted text,
with the reason no behavior distinguishes it and that reason's scope; a
declaration that matches no mutant or several, a duplicate, one of an
unknown domain, and a declared mutant some layer catches each fail the run.
Evidence applies only to the measured domains.

A native run cannot observe undefined behavior, so a mutant both layers miss
in a module that holds `unsafe`, or in a descendant of one, is decided under
Miri. `tests/unsafe_census.rs` finds those modules from the parsed source (a
module's own `unsafe` tokens, or a crate `macro_rules!` holding `unsafe`
that it invokes). Each suite of the Miri gate's selection
(`tests/miri-suites.txt`) names its mutation domain and is built and run in
that domain's features, so the `no_std` domain's code (the decode scope's
abort) is judged by `no_std` builds; an `abort` suite's scenarios each end
their own process and pass by aborting, natively by SIGABRT and under Miri by
its abnormal termination with no undefined behavior. A survivor is judged
only on tests of its own domain. `tests/reach-map.sh` runs every test of the
selection alone under source-based coverage, built against the forked std,
its profile written in continuous mode so an aborting scenario keeps its
coverage, at the minimal witness sizes Miri runs
(`DCBOR_WITNESS=minimal`) and again at full sizes: it fails when a function
of such a module is reached by no test Miri runs, or when a minimal witness
leaves unexecuted a region its full size executes. Test code, a module the
census finds compiled only under `cfg(test)` or beneath one, is never
mutated, so it is no trust boundary and need not be reached. Every reader
of the census parses its rows through one type (`reach-map.py`
`CensusModule`), which rejects a row of any other shape. The campaign then runs
the Miri gate unmutated (`tests/miri-owned.sh`, one Miri process per test
and model, strict provenance, Stacked and Tree Borrows) as the baseline,
plans each such survivor on exactly the tests whose execution overlaps its
mutated span, and judges it with `tests/miri-owned.sh --judge`, which
applies its diff to the working tree, runs those tests under both models
and reverts it, checking the source snapshot after each. A survivor is then
`caught_under_miri` or `missed_under_miri`; one with no reaching test
(`unreached_under_miri`), a selected test without an unmutated pass under
both models (`no_baseline`), a planned mutant without a verdict
(`undecided`), a verdict for no planned mutant (`stale`) and two for one
(`duplicate`) each fail the run, as does a declared equivalent Miri
catches. Every judgement counts only against a baseline of the same
identity: sources, locks, features, the forked std and both models'
`MIRIFLAGS`.

The comparator's planted-defect checks run with:

```sh
python3 -B tests/mutation_evidence_test.py
```

The reach map's census rows and index verdicts (unreached, test code,
witness loss, a row of another shape) are checked with:

```sh
python3 -B tests/reach_map_test.py
```
