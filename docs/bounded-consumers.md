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
Retain that owner while hashing, signing, transmitting or persisting its bytes.
Encoding failure discards the partial buffer. Publication is a separate operation:
a writer can fail after transmitting a prefix and may need application framing or
a storage transaction.

`BoundedError::Refused` preserves the allocator's refusal type; heap failure,
arithmetic overflow, duplicate canonical keys, profile errors and invariant
failures are distinct. `decode::DecodeError` separates resource failures from
malformed bytes and nesting refusal. Both error families implement `Display`
and `Error` when the refusal implements `Debug + Display`.

`Limits` is a single-threaded convenience policy. A cross-thread service supplies
its own `Allocator`/permit ownership implementation; the encoder has no global
policy. Existing input allocations and the policy's own counter are outside the
operation's storage accounting.

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
report. `WriteWork` enforcement catches excessive **reported** work. Neither
that counter nor requested allocator capacity is a hard CPU-time/RSS guarantee.

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
