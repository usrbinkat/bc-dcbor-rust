# Consumer integration

`examples/bounded_record.rs` contains runnable before/after publication adapters.
`tests/bounded_examples.rs` executes their literal wire, resource-refusal, transport-failure and
reservation-cleanup assertions in the workspace suite. The module documentation also runs
before/after dynamic-map and borrowed-decoder examples as doctests.

```sh
cargo run --features derive --example bounded_record
```

## Ownership and errors

`bounded::encode(&value, &mut allocator)` returns `Encoded<A::Permit>`. Its bytes are borrowed with
`AsRef<[u8]>`; the output allocation is freed before its permit. The output is the preparation's own
plan arena, published in place: its permit holds at least the encoding's bytes and at most what
`bounded::encode_bound` retains for the value's shape (its extent and a widest head per map). A
caller needing storage of exactly the encoding's length prepares with `bounded::prepare` and writes
with `Prepared::encode_owned(&mut policy)`, under a policy that may differ from the preparation's:
the output's release is admitted first, its storage is then requested from that policy at exactly
the encoding's length, its permit minted by the call and published with the bytes, and then the
write is admitted. A caller cannot supply a permit of another size. `encoding::owned_emit_bound`
bounds it, the output's release, storage and retained bytes included. Retain the owner while
hashing, signing, transmitting or persisting its bytes. Encoding failure discards the partial
buffer. Transmission is a separate operation: a writer can fail after transmitting a prefix and may
need application framing or a storage transaction.

`BoundedError::Refused` preserves the allocator's refusal type; heap failure, arithmetic overflow,
duplicate canonical keys, profile errors and invariant failures are distinct. `decode::DecodeError`
separates resource failures from malformed bytes and nesting refusal. Both error families implement
`Display` and `Error` when the refusal implements `Debug + Display`.

Each `Limits` instance is driven by one worker at a time. `Limits::share()` creates an independent
policy over the same atomic live-storage pool, and reservations may be released on another thread.
Sharing preserves the storage ceiling, but creates unlimited work and requested-byte allowances and
does not inherit the original deadline. `Limits` is the measurement instrument; a service governs
with `governance`.

## Governing a group of operations

`governance::Governor::new(ceilings)` is a group under aggregate `Ceilings`: the lifetime work of
every operation together, their cumulative requested bytes, and their live storage.
`Governor::operation(ceilings)` makes one operation's `OperationBudget`, under ceilings of its own
(its live ceiling at most the group's), a quantum per unit (`TURN`) and turns its scheduler grants
(`turn`, `turn_with`, `exhaust`). An operation run in one call that no scheduler steps
(`decode::decode_typed`, `encode`) runs `unscheduled`, bounded by the ceilings alone.

Every admission is decided by one accounting core: the operation's ceilings, quantum and turn first,
then the group's ceilings, and only then is anything committed, so a refusal at either level commits
nothing at either. A refusal names what it exhausted, and `LimitRefusal::recovery` says what the
caller does next: `NextTurn` for a spent turn or a `Contended` group admission (another operation of
the group was admitting at that instant; nothing was admitted), `CapacityRelease` for live storage
held elsewhere, `Stop` for an exhausted lifetime allowance or an impossible unit or request. Group
admission never blocks.

Cleanup is never refused for either level's lifetime ceilings: it returns what an operation holds.
Each cleanup unit is still at most one quantum and spends the operation's turn. It is accounted
apart (`OperationBudget::cleanup_used`, `Governor::cleanup_used`); `used` at either level is both,
and `remaining` the foreground's allowance alone. A governed permit releases its bytes from both its
operation's and its group's live totals when it drops, on any thread. Existing input allocations and
a policy's own counters are outside an operation's storage accounting.

An operation's foreground admissions are held to its standing before anything else.
`OperationBudget::cancellation()` and `Governor::cancellation()` return a `Cancellation` that
cancels one operation or every operation of the group, from any thread; it is sticky, and every
later foreground admission is refused `LimitRefusal::Cancelled`. Under `std`,
`OperationBudget::deadline(Some(instant))` refuses every foreground admission
`LimitRefusal::Deadline` from that instant of the monotonic clock on. A cancellation is named before
the deadline; both stop the operation, and neither refuses its cleanup. `Limits::expire_at_call` is
the test instrument's simulated expiry at a call index, not a clock.

## Interpreting codec performance evidence

Admission bounds and the test suite's cost records count logical work and requested storage. They do
not establish a nanosecond cost, a throughput ceiling, or a foreground-latency bound. Passing the
concurrent lifecycle tests establishes the exercised ownership and accounting contracts, not
measured multicore scaling.

For codec measurements, record actual input/output bytes, values per operation, calls to the
continuation's `step`, admission attempts, successful admissions, refusals, and admission-free
release steps separately. `AdmissionTrace` records admission callbacks, not scheduler turns, and
retains only a recent window. Neither its retained entries nor its total callback count is a
complete count of continuation steps.

Elapsed operation time divided by step count is average elapsed cost per step, including useful
codec work and stalls. It is not dispatch overhead. Isolating dispatch requires paired kernels
performing equivalent useful work with different dispatch-boundary counts, while preserving
canonicality and refusal semantics. For UTF-8 comparisons, include a validation-only baseline and
report bytes actually validated, time and instructions per byte, and branch misses; do not infer an
algorithmic speedup from modeled dispatch costs.

Measure preparation, emission, parsing, construction and reclamation CPU service demand separately
from wall time. Measure independent-operation scaling at fixed payload distributions and stated
worker counts. Measure large-document parallelism separately at a fixed total CPU allocation. Under
retirement pressure, record pending bytes, oldest pending age, cleanup service rate, resource
refusals and active-operation tail latency.

Attach the dCBOR capability being qualified to each result, together with exact dCBOR,
compiler/standard-library fork, dependency and allocator identities, hardware and workload
configuration. Distinguish measurements, derivations and unmeasured hypotheses. Superseded results
must retain explicit links to their corrections. The fork's performance evidence must be
reproducible using its own public interfaces and standalone codec workloads.

## Implementing the traits

`Budget`, `Releasing`, `Allocator`, `InPlace`, `Reclaim`, `DecodeInput` and `Resumable` are trusted
extension points: an implementation reports its own work with `Budget::traverse` before doing it,
makes no allocation it has not requested, and states its own cost. A policy implementing `Releasing`
states its cleanup admission, `Releasing::reclaim`, which every cleanup unit reaches through the
engine's cleanup capability: it must not refuse cleanup for the foreground's lifetime allowances or
deadline, or an operation could never return what it holds.

`Schema` (and the `unsafe` `Entries`) reports nothing itself. The engine admits every instruction it
requests; an implementation keeps each instruction to constant work and announces any more it does
before the instruction that needs it: `Instruction::Inspect` for values examined to choose the next
instruction, `Entries::moves` for a cursor's node moves per step. A hash map hands its table to the
engine (`Instruction::Buckets`): only the engine inspects its buckets, over the sealed set of tables
whose bucket accessors this crate's forks provide, each window of controls admitted before it is
inspected. The engine checks what it can observe (a counted map's count, an entry offered where no
unordered map takes one, an encoding longer than its walked extent) and refuses a violation as
`BoundedError::PlanMismatch`. Nothing can detect work an implementation does without announcing it.

A hand-written `InPlace` states its `COST` with the public cost helpers: `unit(bytes)` for one
admitted unit of a value and `bytes` bytes, `held(bytes)` for an allocation held for the value's
life, `ResourceBound::checked_add` and `checked_mul` and `ConstructionCost::checked_add` and
`larger` to compose them, and `ConstructionCost::fixed`, `checked_per_byte` and `checked_children`.
Every checked composition is `None` when a quantity does not fit in `u64`; a `COST` takes it through
`const_cost!`, so an overflowing cost fails to compile where its binding is first used. Derived
decoding bindings admit only through the public helpers built on this crate's charge rules
(`bounded::decode::construction::in_place::step`) and state their costs from the same rules
(`STEP_COST`), so a derived binding's runtime charge and its cost are one definition. Derived
encoding admits nothing itself: it generates a `Schema`, announcing its optional fields' presence
checks.

This repository lints every direct `Budget::traverse` and `Releasing::reclaim` call (`clippy.toml`),
exempting only the route, the cleanup capability, and code standing in for a user implementation. A
consumer crate can hold its own engine code to the same rule by adding the same `disallowed-methods`
entry to its `clippy.toml`.

## Wire semantics

- Standalone `Option<T>` is nullable: `None` is null, `Some(v)` is `v`. Consequently `None` and
  `Some(null)` have the same bytes. Derived optional map fields still omit `None`.
- Dynamic Rust maps sort canonical encoded keys and refuse collisions, including NFC-equivalent
  source keys. They retain a complete encoding in preparation.
- `Tagged { tag, value }` explicitly tags a bounded representation. There is no blanket conversion
  through the allocating `CBORTaggedEncodable` method.
- Dates and feature-gated bignums preserve this crate's symbolic wire semantics.
- Symbolic CBOR is accepted up to `bounded::SYMBOLIC_DEPTH` (128) frames per nesting path, the root
  and each element, key, value and tagged item one frame deeper; the symbolic decoder refuses deeper
  input (`Error::DepthLimit`). Out-of-profile negative arguments are refused. Construction and
  destruction of that existing symbolic input are caller operations.
- The bounded decoder produces a flat borrowed document and validates canonical dCBOR structure.
  Semantic interpretation of arbitrary tags is application work.
- `decode::decode_bound` and `decode_bound_with` bound what decoding any input of a given length
  reports and holds, so a caller can admit the whole decoding as one unit. A schema whose texts are
  always ASCII decodes under `Options::quick_only`, which refuses text the NFC quick check does not
  prove (`DecodeError::UnprovenText`) instead of normalizing it; its bound is at most four values
  per input byte.

Numeric corrections can change historical hashes/signatures. Applications must test their actual
persisted fixtures; these examples do not establish compatibility with an external consumer's
existing records.

## Typed domains above dCBOR conformance

dCBOR itself requires only that text be in NFC (draft section 2.5); a decoder accepts every NFC
text, whatever version of Unicode assigned its code points. The types below layer stricter rules on
top. They never sit inside the decoder: a value the decoder accepts and a typed domain refuses is
still valid dCBOR.

### Stabilized text

`StabilizedText` is NFC text that holds only code points assigned in the Unicode version this crate
pins (`dcbor::UNICODE_VERSION`, the pinned `unicode-normalization`'s). A code point unassigned today
may be assigned by a later version with a decomposition or a combining class, and NFC text holding
it could then stop being normal; text holding none keeps the same normal form under every later
version (UAX #15, section 12, the normalization process for stabilized strings). `is_assigned`
answers for one code point.

- Construction (`StabilizedText::new`, `TryFrom<String>`, `TryFrom<CBOR>`) refuses text not in NFC
  (`Error::NonCanonicalString`), then its first unassigned code point
  (`Error::UnassignedCodePoint`).
- Bounded decoding (`InPlace`) checks the decoded text, which the decoder has already proved NFC, in
  windows of at most a quantum ending on a scalar, each admitted before it is inspected (one value
  and the window's bytes), before the binding allocates anything of its own (the document is already
  parsed and held by the caller). A refusal is `DecodeError::Invalid(Error::UnassignedCodePoint)`,
  of class `Invalid`. The text is then built and reclaimed exactly as a `String` is. Its `COST` is a
  `String`'s plus that check: one more value per window and every byte inspected once more.
- Bounded encoding writes its text, as a `String` does.
- `Option<StabilizedText>` decodes in bounded mode: its placeholder is the empty text
  (`StabilizedText::empty`).

The assigned set is generated at build time (`build.rs`) from the package's one copy of that
version's `DerivedAge.txt` (`data/unicode`), and the build fails unless its version equals the
pinned normalization's. The version is part of every evidence gate's identity. Moving the pin means
moving `data/unicode/<version>/DerivedAge.txt` and `tests/data/NormalizationTest.txt` with it;
anything else fails to build or fails the conformance suite.

### ASCII text

`AsciiText` is text holding only ASCII code points, U+0000 to U+007F: identifiers, names and tokens
read by machines. Every ASCII text is in NFC, and the NFC quick check proves it (every ASCII code
point is `NFC_Quick_Check=Yes` with combining class 0) under every Unicode version, so an ASCII
text's canonical form never depends on Unicode data.

- Construction (`AsciiText::new`, `TryFrom<String>`, `TryFrom<CBOR>`) refuses the first code point
  at or past U+0080 (`Error::NonAsciiText`). `AsciiText::empty` is the empty text.
- Bounded decoding declares the wire profile `Options::quick_only(0)` (`TextPolicy::QuickOnly`): a
  text the quick check cannot prove is refused as `DecodeError::UnprovenText` before any
  normalization runs, so decoding a type made of ASCII text never pays for normalization. A derived
  record or sequence of ASCII fields composes the profile (`Options::either`, `Options::nested`);
  one `String` field restores strict validation. A quick-proven text that is not ASCII reaches the
  binding, which refuses it as `DecodeError::Invalid(Error::NonAsciiText)`. The check is
  `StabilizedText`'s engine (`in_place/checked.rs`) under the ASCII rule: the same windows,
  admissions and `COST`.
- `Option<AsciiText>` decodes in bounded mode, its placeholder the empty text.
- Its CDDL is `tstr .regexp "[\u0000-\u007F]*"`, checked against both decoders by the independent
  validator (`tests/cddl`).

### Fixed-length byte string

`FixedBytes<N>` is a byte string of exactly `N` bytes: a digest, a key, an identifier whose length
its type fixes. It is a CBOR byte string (major type 2), unlike `[u8; N]`, which is an array of `N`
integers. Its bytes are held inline, so it owns no allocation.

- Construction (`FixedBytes::new`, `from_slice`, `TryFrom<&[u8]>`, `TryFrom<CBOR>`) refuses a byte
  string of another length as `Error::WrongLength { expected, actual }`, and any other value as
  `Error::WrongType`.
- Bounded decoding (`InPlace`) refuses a node of another length or kind in one admitted unit, before
  anything is written, then copies the document's bytes into the value's own place in units of at
  most a quantum, each admitted before it is copied. Nothing is allocated, and cleanup is one unit
  whatever was copied. Its `COST` is one value per quantum and every byte once, plus the last copy
  and the cleanup unit; its wire profile is a scalar's (no nesting, no text).
- Bounded encoding writes the byte string's head and its bytes.
- Its CDDL is `bstr .size N` (RFC 8610, section 3.8.1).

### Minimal big integer

`MinimalBigInt` is an integer of any size with exactly one encoding, in every build: a plain integer
(major type 0 or 1) inside dCBOR's integer range, `[-2^63, 2^64 - 1]`, and a bignum (tag 2 or 3)
outside it, whose byte string has no leading zero byte. Decoding then encoding is byte-identical, so
one value has one identity.

dCBOR places no rule on tags 2 and 3 beyond those on every byte string (draft 18, section 8.5,
"Limiting Principles"): the decoder keeps `c2 41 01` and `c2 42 00 01` as two distinct tagged byte
strings, and `BigInt`'s conversion keeps its own wire behaviour. `MinimalBigInt` refuses, as
`Error::NonCanonicalNumeric`, a bignum whose byte string is empty or has a leading zero byte, and
then one whose value a plain integer carries (`c2 40`, `c2 41 01`, `c3 41 00`); anything but an
integer or a bignum is `Error::WrongType`.

Its identity is its bytes, so it holds them: whether it is negative, and the argument `n` of its
encoding, big-endian, with no leading zero byte (the value is `n`, or `-1 - n` when negative, as
major type 1 and tag 3 both mean). `from_parts` builds one, `as_parts` reads one; `u64` and `i64`
convert in.

- Bounded encoding writes the plain integer's head inside the range, and outside it the tag's head
  and the magnitude as a byte string.
- Bounded decoding (`InPlace`) reads the node, and a tag's byte string, checking the length and
  first byte in the one unit that writes the sign; then builds the magnitude exactly as a byte
  string is built, from the document's bytes or the plain integer's argument. A refusal is
  `DecodeError::Invalid`, made before the binding allocates its own magnitude or metadata; the
  document it reads, already parsed and held by the caller, is accounted by the parse, not by this
  guarantee. Its `COST` is a byte string's and one write of a `bool`.
- With `num-bigint`, `BigInt` converts to and from it, and `BigUint` into it, at the symbolic edge,
  outside any policy: the magnitude's bytes are the vector num-bigint's `to_bytes_be` allocates,
  moved in without a second copy.

## Hidden callback work and process limits

An in-process Rust trait cannot intercept work that its implementation does not report or announce.
Neither the admitted work nor requested allocator capacity is a hard CPU-time/RSS guarantee.

For native callbacks that are outside the cooperative trust boundary, run the operation in a worker
process. `examples/run-bounded-worker.sh` supplies a Linux user-systemd launcher with a 96 MiB
cgroup memory limit, disabled swap, a two-second per-process CPU limit, and a five-second service
runtime limit. The controls continue to apply when code ignores its budget. Failure to start the
service is an error; the script does not retry without isolation.

```sh
cargo build --example bounded_worker
sh examples/run-bounded-worker.sh "$PWD/target/debug/examples/bounded_worker" < record.cbor > validated.cbor
```

The example worker accepts at most 1 MiB, validates under finite work/storage limits and a nesting
limit, then publishes the original canonical bytes. Its standard-I/O runtime is covered by the
process boundary, not by the library's allocation permits. Check the exit status before publishing
the output file.

This launcher requires working user-systemd and delegated cgroup-v2 memory controls. `MemoryMax` is
cgroup memory accounting, **not a precise process RSS ceiling**; CPU-limit granularity and service
termination scheduling also apply. It is resource containment, not a security sandbox. Enforcement
on a deployment requires actual runaway CPU/memory and timeout probes there. No such successful
deployment run is recorded by merely adding this launcher.
