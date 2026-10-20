# Owned decoding

`bounded::decode::construction::OwnedTypedDecoder` retains its input through an
`OwnedInitialized<I, A>` resource handle. `I: DecodeInput<A>` promises immutable
bytes and implements incremental `Reclaim<A>` for input storage, evidence, and
reservations. `ByteString` supplies a built-in binding.

The scheduler retains `OwnedDecodeOwner<A>`. Its constructor is allocation-free;
`initialize_step` admits and allocates the stable scope. `allocate_step` creates
an uninitialized owning record, retaining its allocation admission across a
refusal. Resource bindings initialize the record at `destination()`, maintaining
its cursor, then call unsafe `publish()` only after complete initialization.
These low-level operations have the same safety obligations as the borrowed
`Record` API. Input must already have this custody before being passed to the
decoder; passing a plain generic value would permit its arbitrary destructor to
run when cancellation occurs before lifecycle allocation.

`OwnedTypedDecoder::new(input, options)` creates only a small controller. Call
`step` with a fresh work allowance each turn. A refusal retains progress.
`OwnedDecodeStep::Complete` yields a movable `OwnedTypedValue`; `value()` borrows
the stable destination. The decoder can then be dropped independently.

## Ownership and access

| Holder | Authority |
| --- | --- |
| Scheduler's owner | Step queued cleanup; close admission and drain shutdown |
| Decoder record handle | Exclusive access to partially initialized lifecycle state |
| Output record handle | Shared typed access after construction and scratch release |
| Intrusive queue / active slot | Exclusive cleanup access after handle retirement |

Parser continuations retain offsets, scalar progress, and owned scratch. Header,
UTF-8, normalization, and key comparison borrow input only during a step. Arena
views are temporary and always paired with the operation's immutable input.
Publication transfers the record handle without moving the typed destination.

Drop of a record handle enqueues its existing record without allocating or
destroying the payload. Cleanup runs value, arena, parser, and input retirement
phases. The input record then runs its own incremental cleanup in the same queue.
Cancellation uses this path, including cancellation during partial initialization.
An aborting decoder steps its scope until it is empty, so other live records in
that scope must also be retired before it can report `Finished`.

Drop all decoder/output handles, then call `shutdown_step` until `Done`.
The scope allocation and its reservation are released only when the queue is
empty and no other owning handle remains. Dropping the final cleanup authority
before explicit shutdown is an invariant failure; it never triggers a hidden
synchronous drain. These handles are single-threaded.

The borrowed `TypedDecoder`, `DecodeOwner`, `Document`, and text/header cursor
interfaces remain available. No lifetime extension or self-referential consumer
wrapper is used by the owned API.
