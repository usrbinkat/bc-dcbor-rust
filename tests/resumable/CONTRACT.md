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
- Normalization must preserve stable combining-class order, composition,
  decomposition, leading marks, and Hangul semantics. QuickOnly must enforce its
  acceptance policy without silently invoking normalization.

## Suspension and retained progress

- Every injected refusal must be positively observed at its selected admission,
  with the expected refusal class and no completed result.
- Resumption must advance the same production continuation. Completed parsing,
  validation, comparison, normalization, construction, and emission must not replay.
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

- Acceptance schedules use fresh allowances of at most three values and 64 bytes
  per turn. Unused allowances must not accumulate between turns, and consumed
  work must not be refunded.
- Every progress outcome must represent useful retained work. Completion must
  occur within a deterministic input-derived step bound, with a diagnostic trace
  on failure.
- Work admission must precede the corresponding execution. Actual execution
  bounds must cover scans, copies, comparisons, relocation, normalization,
  field finalization, terminal cleanup, and destruction of partial values.
- Next-unit bounds must compose with checked arithmetic and include additional
  live storage at peak overlap. Bound observation must itself be bounded and
  must not advance the operation.
- Underestimated bounds must be classified separately from caller refusal and
  detected before the offending work or write.
- Deadline schedules must cover expiration before the first admission and
  between admissions. Admitted work must not be revoked mid-unit.
- Long disordered combining sequences must satisfy an O(n log n) or better total
  ordering-work bound as well as the per-turn bound.
- Measured execution latency must supplement callback accounting. Reported small
  charges alone do not establish bounded execution.

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
declarations identify the registered test groups.

Stock toolchain: every feature except `custom-std-collections`, which enables
`#![feature(hashmap_bucket_access)]` and is rejected on the stable channel.

```sh
cargo test --features derive,hashbrown --test resumable_contract
cargo test --workspace --features derive,hashbrown,multithreaded,num-bigint
cargo clippy --workspace --all-targets --features derive,hashbrown,multithreaded,num-bigint -- -D warnings
cargo fmt --all --check
```

Standard-library toolchain built from `usrbinkat/rust` branch
`feat/bounded-collection-access`, whose std exposes `hashmap_bucket_access`:

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The separate fuzz workspace must be built and executed with coverage
instrumentation and sanitizers using the commands in `fuzz/README.md`.

Downstream qualification must exercise real Kappa wiring for recovery, settlement,
and sustained publication on both backends, preserving canonical identities,
replay ownership, dense epochs, increasing timestamps, genesis plus 8 x 32
publications, head 257, and the 256-unsettled ceiling.
