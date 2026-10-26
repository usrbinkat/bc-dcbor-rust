# Resumable dCBOR acceptance contract

## Scope

This contract covers canonical decoding, typed and derive-generated construction,
normalization, encoding preparation, emission, and their resource ownership.
Operations receive complete immutable input. Execution suspension is distinct
from fragmented input delivery.

Acceptance requires cumulative guarantees: semantic correctness, positively
observed suspension, retained useful progress, bounded execution, exact ownership,
and finite completion. Eventual completion alone is insufficient.

## Semantics and publication

- Canonical bytes and decoded values must match independent literal fixtures.
  Encoder/decoder round trips supplement those fixtures.
- Nonminimal heads, malformed payloads, invalid key ordering, duplicate keys,
  invalid schemas, and trailing bytes must be rejected before publication.
- A continuation must publish exactly one completed result. Partial values must
  remain inaccessible as completed results.
- Derived construction must preserve field presence, optional-field behavior,
  unknown-field policy, tag validation, and enum discriminants and lengths.
  The unknown-field policy is the existing derive's: an unknown integer key and
  its value are skipped, never rejected, and known fields are still validated.
  Skipped fields are why identity and signature checks use the original input
  bytes a published value retains, never a re-encoding.
- Normalization must preserve stable combining-class order, composition,
  decomposition, leading marks, and Hangul semantics. QuickOnly must enforce its
  acceptance policy without silently invoking normalization.

## Suspension and retained progress

- Every injected refusal must be positively observed at its selected admission,
  with the expected refusal class and no completed result.
- Resumption must advance the same production continuation. Completed parsing,
  validation, comparison, normalization, construction, and emission must not replay.
  No-replay is proven by the admission trace: a run resumed after a refusal
  admits exactly the unrefused run's calls, in order, with only the refused
  call attempted again. A step that reports progress must have made an
  admission, and a step whose only admission was refused must leave the
  position unchanged.
- Observations must expose the relevant retained positions, including header
  bytes, payload validation, key comparison, storage relocation, construction
  progress, and emitted bytes.
- A refusal must preserve all work successfully admitted before it. A step may
  contain successful admissions before a later refusal; assertions must account
  for that committed progress separately from the refused work.
- Progress, refusal, validation failure, physical allocation failure, bound
  defects, completion, and terminal state must remain distinguishable.
- Invalid input must remain invalid after suspension. Cancellation must release
  the continuation's ownership without affecting independently owned results.

## Execution and resource bounds

- Acceptance schedules give every turn a fresh allowance of one fixed quantum,
  `TURN`: three values and 64 bytes. Unused allowances must not accumulate
  between turns, and consumed work must not be refunded.
- Every progress outcome must represent useful retained work. Completion must
  occur within a deterministic input-derived step bound, with a diagnostic trace
  on failure.
- Work admission must precede the corresponding execution. Actual execution
  bounds must cover scans, copies, comparisons, relocation, normalization,
  field finalization, terminal cleanup, and destruction of partial values.
- Every retained operation must have a whole-operation `ResourceBound` derived
  from its input, schema or source shape: the work it reports, the sum of its
  allocation requests, the most it holds at once, old and new storage during
  growth included, and what its publication retains, on success or at any
  failure and its cleanup. Bounds compose with checked arithmetic and are
  refused, never saturated, on overflow. The next unit of any operation is
  bounded by the quantum: a count a source announces (an entry cursor's node
  moves, the values a source inspects) is admitted in units of at most the
  quantum's values, never in one a turn cannot hold. Its step bound is the
  values and requested bytes of its whole-operation bound, since every step
  admits a value or makes one allocation request alone.
- Each bound must be shown to cover its operation on every engine path and to
  be tight within a constant factor on the inputs that maximize it. A bound is
  a sum of terms, one per place its operation charges, because the slack of a
  whole sum can hide an understated term. Every admission and allocation
  request is made at a place. Each place's work, requests, peak and retained
  bytes must be within its own term on every measured run. Each charged place
  has a witness run, and that run, checked by the same rule against its terms
  with that place's term removed, must fail at that place: the passing check
  and the failing one ship together. A charge's rate is defined once and read
  by both the engine that admits it and the term that counts it.
- Bound observation must itself be bounded and must not advance the operation:
  a source's shape is walked under admission, allocation-free.
- A source breaking its schema contract (a counted field map visiting another
  count, a counted unordered map ending before its count, an entry past its
  bucket window, an encoding longer when prepared than when its shape was
  walked) must be classified as a defect, separately from caller refusal, and
  detected before the work it would leave unbounded: the plan's arena refuses
  growth past the walked extent.
- A counted unordered map ends once its declared entries are yielded: its
  source is asked for nothing further, so no bucket after its last entry is
  scanned. Its source is trusted to state the count of the entries it holds:
  entries beyond the declared count are never requested, so a source
  declaring fewer than it holds is not detected.
- Deadline schedules must cover expiration before the first admission and
  between admissions. Admitted work must not be revoked mid-unit.
- Long disordered combining sequences must satisfy a total ordering-work bound
  linear in the sequence, as well as the per-turn bound.
- Measured execution latency must supplement callback accounting. Reported small
  charges alone do not establish bounded execution.

## Admission route and trusted domain

- Every admission an engine of this crate makes, and every admission
  derive-generated code makes, goes through one route: a charge rule's
  `admit` (`Unit`, `Capped`, `Scan`, `Rate`), whose admission carries its
  place, or, in generated decoding code, the public helpers built on those
  rules (`bounded::decode::visits`,
  `bounded::decode::construction::in_place::step`). Generated encoding code
  admits nothing: it is a `Schema`, whose instructions the engine admits.
- User implementations of the public traits (`Budget`, `Allocator`,
  `InPlace`, `Reclaim`, `Resumable`) are trusted to admit their own work, as
  those traits document. A `Schema` (and an `Entries` cursor) is trusted to
  keep each instruction to constant work and to announce what it examines
  beyond it (`Instruction::Inspect`, `Entries::moves`). Test code standing in
  for such an implementation says so at the item that does it.
- A direct `Budget::traverse` call fails `clippy -D warnings` at its span
  (`clippy.toml`). Each sanctioned call carries an item-level
  `#[expect(clippy::disallowed_methods, reason = ...)]` naming why: the route
  itself, the forwarding implementations, and each stand-in. No crate-level
  exemption exists, so derive output stays checked wherever it expands. An
  exemption whose call is gone, or a configured path that no longer
  resolves, leaves an expectation unfulfilled, which fails the same check.
- In this crate's test builds the route marks each admission as routed, and
  the attribution policy refuses any admission that is not, naming the
  values and bytes, the places entered and the route to use. The mark ends
  with its admission, unwinding included.
- Allocations are not routed. They are covered by attribution: an
  allocation request made at no place fails the coverage check.

## Allocation and ownership

- Physical allocations must be admitted before allocation. Reservations must
  cover live requested storage, metadata, and old/new overlap during growth.
- Physical allocation failure and policy refusal must be tested independently.
  Every observed physical allocation must be individually fail-able, with the
  selected failure positively observed and propagated.
- Failed growth must preserve existing values and their reservations until
  replacement succeeds or the owner is destroyed.
- Completed fields must survive later suspension as actual values, not merely
  as retained permits. Destruction observations must verify their lifetime.
- Capacity must be observed across input retention, parser scratch, partial
  fields, completed output, parser destruction, and output destruction.
- Output storage must remain charged after parser and decoder destruction and
  release its reservation only with its owner. Storage must be destroyed before
  the reservation protecting it is released.
- Cancellation at every suspended stage must restore exactly the owned capacity.
  Concurrent continuations must recover the full shared capacity; reacquiring
  that capacity must succeed and one additional unit must fail.
- A reservation can be split into two owners and two reservations of the same
  storage merged into one. Live and peak storage are unchanged by either; a
  zero-byte split owns nothing; a refused split or merge leaves every
  reservation unchanged; each owner releases exactly what it holds.
- A storage refusal caused by another owner's reservation leaves the refused
  operation, and everything it holds, unchanged; once that owner releases, on
  any thread, the same operation resumes without replay.
- Compile-fail tests must enforce input immutability, output-owner lifetimes,
  and preparation-plan and destination borrows held by resumable writers.

## Test independence and required schedules

The test harness owns fixtures, budgets, refusal schedules, allocation observation,
and assertions. It must drive production operations without implementing a second
parser, normalizer, constructor, or encoder.

Required schedules include:

| Group | Required observations |
| --- | --- |
| Decoder | Refusal before and after the header; exact retained payload and key offsets; child completion once; late invalidity without publication |
| Construction | Every admission boundary; completed field retention; nested generic and derived schemas; bounded copies and finalization |
| Text | Literal semantic fixtures across refusal and cancellation; exhaustive scalar quick-check parity; long disordered runs |
| Encoding | Separate preparation and emission; retained destination prefix; guard bytes; no allocation during prepared emission |
| Ownership | Intermediate live capacity and physical storage; failed growth; cancellation; cross-thread output lifetime; concurrent recovery |
| Bounds | Each work dimension; overflow; deterministic deadlines; bound defects; execution latency and total-work limits |
| Fuzzing | Malformed inputs, nesting, truncations, mutations, changing resource schedules, cancellation, semantic agreement, and finite termination |

Negative controls must demonstrate that allocation and work-bound instrumentation
detect deliberate violations. Fault matrices must exercise all selected cases.

## Prior-art requirements

- `/workspace/usrbinkat/github.com/facebook/rocksdb/db/log_test.cc`:
  `RetriableLogTest.NonBlockingReadFullRecord`, `TailLog_PartialHeader`, and
  `TailLog_FullHeader` establish positively observed interruption around header
  boundaries followed by exact output from the same retained reader.
- `/workspace/usrbinkat/github.com/tokio-rs/tokio/tokio-util/tests/length_delimited.rs`:
  `read_single_frame_multi_packet` and `read_multi_frame_multi_packet` establish
  independently scripted boundaries, distinct intermediate outcomes, and ordered
  literal outputs. dCBOR schedules apply these assertions to execution suspension.
- `/workspace/usrbinkat/github.com/unicode-rs/unicode-normalization/src/test.rs`:
  `test_nfc` and `test_nfd` establish explicit semantic fixtures across input
  iterator shapes. `Decompositions::sort_pending` in the adjacent `decompose.rs`
  establishes stable ordering within combining sequences.
- `/workspace/usrbinkat/github.com/tokio-rs/tokio/tokio/tests/sync_semaphore_owned.rs`:
  `merge`, `split`, and `stress_test` establish intermediate ownership accounting,
  zero-sized and refused transfers, final-owner release, and exact capacity
  reacquisition after concurrent work.

## Verification

The executable acceptance target is `tests/resumable_contract.rs`; its module
declarations identify the registered test groups. The owned lifecycle has its
own targets, listed in `COVERAGE.md`. Every target drives production
operations through the shared `dcbor-test-support` crate (`tests/support`),
compiled once for every test binary and fuzz target.

Stock toolchain: every feature except `custom-std-collections`, which enables
`#![feature(hashmap_bucket_access, btree_stepped_cursor)]` and is rejected on
the stable channel.

```sh
cargo test --features derive,hashbrown --test resumable_contract
cargo test --workspace --features derive,hashbrown,multithreaded,num-bigint
cargo clippy --workspace --all-targets --features derive,hashbrown,multithreaded,num-bigint -- -D warnings
cargo fmt --all --check
./run_tests.sh
```

`run_tests.sh` tests and lints the crate under every stock feature set, then
every workspace member's own targets, then checks formatting; any failing
test, any clippy warning and any formatting difference fails the run. Code
compiled only under some features, and the single admission route
(`clippy.toml`), are thereby checked in every build that compiles them. It
runs from any directory.

The recorded admission baselines (`tests/data/admission-traces.txt`, and
`tests/data/admission-traces.num-bigint.txt` where bignums are encoded) are
rewritten from the current build only deliberately, with every gating feature
enabled; a change to them states the trace delta it carries:

```sh
DCBOR_RECORD_TRACES=1 cargo test --features derive,hashbrown --test resumable_contract traces::
DCBOR_RECORD_TRACES=1 cargo test --features derive,hashbrown,num-bigint --test resumable_contract traces::
```

Over the flake's standard library the ordered-collection schemas walk trees
by the stepped cursor, whose admissions differ from the iterator's, so their
baselines are kept apart (`admission-traces.custom-std.txt` and
`admission-traces.custom-std.num-bigint.txt`) and recorded in the default
shell:

```sh
DCBOR_RECORD_TRACES=1 cargo test --features custom-std-collections,derive,hashbrown --test resumable_contract traces::
DCBOR_RECORD_TRACES=1 cargo test --features custom-std-collections,derive,hashbrown,num-bigint --test resumable_contract traces::
```

Standard-library toolchain from the flake, whose `library/` is the
`usrbinkat/rust` commit pinned in `flake.lock`: its std exposes
`hashmap_bucket_access` and `BTreeMap::stepped_cursor`
(`btree_stepped_cursor`), which the ordered-collection schemas walk.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Unsafe code is qualified under Miri with `tests/miri-owned.sh` in the flake's
default shell, whose toolchain carries Miri and builds its sysroot from the
same patched library. The separate fuzz workspace
must be built and executed with coverage instrumentation and sanitizers using
the commands in `fuzz/README.md`; `fuzz/smoke.sh` and `fuzz/qualify.sh` run
every target.

Downstream consumers qualify their own integration through these public
boundaries.
