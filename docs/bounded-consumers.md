# Consumer integration

`examples/bounded_record.rs` contains runnable before/after publication adapters.
`tests/bounded_examples.rs` executes their literal wire, resource-refusal,
transport-failure and reservation-cleanup assertions in the workspace suite.
The module documentation also runs before/after dynamic-map and borrowed-decoder
examples as doctests.

```sh
cargo run --features derive --example bounded_record
```

## Ownership and errors

`bounded::encode(&value, &mut allocator)` returns `Encoded<A::Permit>`. Its bytes
are borrowed with `AsRef<[u8]>`; the output allocation is freed before its permit.
The output is the preparation's own plan arena, published in place: its permit
holds at least the encoding's bytes and at most what `bounded::encode_bound`
retains for the value's shape (its extent and a widest head per map). A caller
needing storage of exactly the encoding's length prepares with
`bounded::prepare` and writes with `Prepared::encode_owned`, admitting that
output separately. Retain the owner while hashing, signing, transmitting or
persisting its bytes. Encoding failure discards the partial buffer.
Transmission is a separate operation: a writer can fail after transmitting a
prefix and may need application framing or a storage transaction.

`BoundedError::Refused` preserves the allocator's refusal type; heap failure,
arithmetic overflow, duplicate canonical keys, profile errors and invariant
failures are distinct. `decode::DecodeError` separates resource failures from
malformed bytes and nesting refusal. Both error families implement `Display`
and `Error` when the refusal implements `Debug + Display`.

Each `Limits` instance is driven by one worker at a time. `Limits::share()`
creates an independent policy over the same atomic live-storage pool, and
reservations may be released on another thread. Sharing preserves the storage
ceiling, but creates unlimited work and requested-byte allowances and does not
inherit the original deadline. A service requiring aggregate CPU-work,
requested-byte, or deadline authority must supply that authority through its
`Allocator`/`Budget` implementation or scheduler. The encoder has no global
policy. Existing input allocations and the policy's own counter are outside the
operation's storage accounting.

## Interpreting codec performance evidence

Admission bounds and the test suite's cost records count logical work and
requested storage. They do not establish a nanosecond cost, a throughput
ceiling, or a foreground-latency bound. Passing the concurrent lifecycle tests
establishes the exercised ownership and accounting contracts, not measured
multicore scaling.

For codec measurements, record actual input/output bytes, values per operation,
calls to the continuation's `step`, admission attempts, successful
admissions, refusals, and admission-free release steps separately.
`AdmissionTrace` records admission callbacks, not scheduler turns, and retains
only a recent window. Neither its retained entries nor its total callback
count is a complete count of continuation steps.

Elapsed operation time divided by step count is average elapsed cost per step,
including useful codec work and stalls. It is not dispatch overhead. Isolating
dispatch requires paired kernels performing equivalent useful work with
different dispatch-boundary counts, while preserving canonicality and refusal
semantics. For UTF-8 comparisons, include a validation-only baseline and report
bytes actually validated, time and instructions per byte, and branch misses;
do not infer an algorithmic speedup from modeled dispatch costs.

Measure preparation, emission, parsing, construction and reclamation CPU
service demand separately from wall time. Measure independent-operation scaling at
fixed payload distributions and stated worker counts. Measure large-document
parallelism separately at a fixed total CPU allocation. Under retirement
pressure, record pending bytes, oldest pending age, cleanup service rate,
resource refusals and active-operation tail latency.

Attach the dCBOR capability being qualified to each result, together with exact
dCBOR, compiler/standard-library fork, dependency and allocator identities,
hardware and workload configuration. Distinguish measurements, derivations and
unmeasured hypotheses. Superseded results must retain explicit links to their
corrections. The fork's performance evidence must be reproducible using its own
public interfaces and standalone codec workloads.

## Implementing the traits

`Budget`, `Allocator`, `InPlace`, `Reclaim`, `DecodeInput` and `Resumable` are
trusted extension points: an implementation reports its own work with
`Budget::traverse` before doing it, makes no allocation it has not requested,
and states its own cost.

`Schema` (and the `unsafe` `Entries`) reports nothing itself. The engine admits
every instruction it requests; an implementation keeps each instruction to
constant work and announces any more it does before the instruction that needs
it: `Instruction::Inspect` for values examined to choose the next instruction,
`Entries::moves` for a cursor's node moves per step. The engine checks what it
can observe (a counted map's count, an entry's bucket window, an encoding
longer than its walked extent) and refuses a violation as
`BoundedError::PlanMismatch`. Nothing can detect work an implementation does
without announcing it.

A hand-written `InPlace` states its `COST` with the public cost helpers:
`unit(bytes)` for one admitted unit of a value and `bytes` bytes, `held(bytes)`
for an allocation held for the value's life, `plus`, `times` and `larger`
to compose them, and `ConstructionCost::fixed`, `per_byte` and `children`.
Derived decoding bindings admit only through the public helpers built on this
crate's charge rules (`bounded::decode::visits`,
`bounded::decode::construction::in_place::step`) and state their costs from
the same rules (`STEP_COST`), so a derived binding's runtime charge and its
cost are one definition. Derived encoding admits nothing itself: it generates
a `Schema`, announcing its optional fields' presence checks.

This repository lints every direct `Budget::traverse` call (`clippy.toml`),
exempting only the route itself and code standing in for a user
implementation. A consumer crate can hold its own engine code to the same
rule by adding the same `disallowed-methods` entry to its `clippy.toml`.

## Wire semantics

- Standalone `Option<T>` is nullable: `None` is null, `Some(v)` is `v`. Consequently
  `None` and `Some(null)` have the same bytes. Derived optional map fields still
  omit `None`.
- Dynamic Rust maps sort canonical encoded keys and refuse collisions, including
  NFC-equivalent source keys. They retain a complete encoding in preparation.
- `Tagged { tag, value }` explicitly tags a bounded representation. There is no
  blanket conversion through the allocating `CBORTaggedEncodable` method.
- Dates and feature-gated bignums preserve this crate's symbolic wire semantics.
- Symbolic CBOR is accepted up to 128 nodes per nesting path. Out-of-profile
  negative arguments are refused. Construction and destruction of that existing
  symbolic input are caller operations.
- The bounded decoder produces a flat borrowed document and validates canonical
  dCBOR structure. Semantic interpretation of arbitrary tags is application work.
- `decode::decode_bound` and `decode_bound_with` bound what decoding any input of
  a given length reports and holds, so a caller can admit the whole decoding as
  one unit. A schema whose texts are always ASCII decodes under
  `Options::quick_only`, which refuses text the NFC quick check does not prove
  (`DecodeError::UnprovenText`) instead of normalizing it; its bound is at most
  four values per input byte.

Numeric corrections can change historical hashes/signatures. Applications must
test their actual persisted fixtures; these examples do not establish compatibility
with an external consumer's existing records.

## Hidden callback work and process limits

An in-process Rust trait cannot intercept work that its implementation does not
report or announce. Neither the admitted work nor requested allocator capacity
is a hard CPU-time/RSS guarantee.

For native callbacks that are outside the cooperative trust boundary, run the
operation in a worker process. `examples/run-bounded-worker.sh` supplies a Linux
user-systemd launcher with a 96 MiB cgroup memory limit, disabled swap, a two-second
per-process CPU limit, and a five-second service runtime limit. The controls
continue to apply when code ignores its budget. Failure to start the service is
an error; the script does not retry without isolation.

```sh
cargo build --example bounded_worker
sh examples/run-bounded-worker.sh "$PWD/target/debug/examples/bounded_worker" < record.cbor > validated.cbor
```

The example worker accepts at most 1 MiB, validates under finite work/storage
limits and a nesting limit, then publishes the original canonical bytes. Its
standard-I/O runtime is covered by the process boundary, not by the library's
allocation permits. Check the exit status before publishing the output file.

This launcher requires working user-systemd and delegated cgroup-v2 memory
controls. `MemoryMax` is cgroup memory accounting, **not a precise process RSS
ceiling**; CPU-limit granularity and service termination scheduling also apply.
It is resource containment, not a security sandbox. Enforcement on a deployment
requires actual runaway CPU/memory and timeout probes there. No such successful
deployment run is recorded by merely adding this launcher.
