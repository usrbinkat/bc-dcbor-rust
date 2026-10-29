# Owned decoding

Owned decoding retains every operation's state in stable records held by one
decode scope, so an operation can be stepped across turns, moved between
threads, cancelled, or dropped at any point without running an unadmitted
destructor or allocation. The interfaces live in
`bounded::decode::construction`; owned encoding of a decoded value lives in
`bounded::encoding`.

## Owned B-tree maps

With `custom-std-collections`, `BTreeMap<K, V>` supports owned construction,
transfer, preparation and incremental reclamation. `K` implements both
`InPlace<A>` and `TreeKey`; `V` implements `InPlace<A>`. Thread transfer also
requires the existing `Transferable` and `TransferableSchema` contracts.
Built-in `TreeKey` bindings cover `String`, `ByteString`, booleans, and the
signed and unsigned 8-, 16-, 32- and 64-bit integers, plus `usize`.

Construction sorts document indices by the keys' Rust ordering before
allocating the final tree shape. This matters for text and integer keys:
canonical CBOR key order is not necessarily Rust `Ord` order. Keys and values
are then built in their final node slots; publication neither inserts nor
moves entries. `TreeKey` is unsafe because its allocation-free source view
must agree with the constructed key's ordering and comparison-work bound.

The retained state records every partially initialized child, node allocation
and permit. Reclamation detaches a published map, reclaims values and keys in
reverse construction order, and releases child nodes before parents. Each
node's allocation is freed before its permit. The sorting and custody arenas
are reclaimed through the same `Storage` state machine as other bindings.
Child construction states are held in `ManuallyDrop`: reclamation never invokes
their Rust destructors. Removing an exhausted entry is a separate admitted
phase, so refusal at that boundary cannot repeat either child's cleanup.

The fork API is `btree_in_place`. The custom shell applies
`nix/btree-in-place.patch` to the pinned fork and records the patch's SHA-256
in `DCBOR_CONFIGURATION`. Re-enter the custom shell after changing this patch;
an existing shell retains its previous standard-library source. Stock-std
builds retain borrowed B-tree encoding but do not expose this owned binding.

## The scope

`DecodeOwner<'s, A>` is the cleanup authority of one scope. `new` allocates
nothing. `initialize_step` admits and allocates the scope block and initializes
its terminal cleanup dispatch in separately admitted writes; a
refusal retains the admission for the next call, and a closed authority refuses
with `PlanMismatch`. `'s` is the scope's data lifetime: every payload outlives
it, and no handle, operation or the owner itself can outlive it. Owned inputs
use `'static`; a borrowed input binds the scope to its borrow.

`step` performs one unit of queued cleanup. `Reclaimed::Waiting` means nothing
can advance: no record is queued while handles still hold records, or a
retiring thread has published its record and not yet linked it. A waiting call
performs no unit; an admission already granted for the next removal is
retained. `shutdown_step` closes allocation and drains the queue, then releases
the scope block once it holds the only remaining reference; after `Done` the
authority is closed and initialization refuses with `PlanMismatch`.

Initializing an owned scope requires `A: TerminalAllocator`. This unsafe policy
capability constructs an allocation-free, non-refusing cleanup policy from the
scope's retained permit. `Limits` implements it without creating new counters,
logging allocations, or consulting the scheduler's refusal schedule.

Dropping the authority closes the scope and runs the same queued reclamation
state machine with that terminal policy. Live handles keep their values and the
scope alive; retiring them continues cleanup, including on another thread. The
last reference frees the empty scope before releasing its permit. A partially
initialized scope exposes no handles and releases its block directly. Terminal
cleanup never invokes payload or construction-state destructors; a violating
binding that unwinds or refuses terminal cleanup aborts rather than unwinding
through an owner destructor. Explicit `step` and `shutdown_step` retain their
ordinary refusal and quantum behavior.

## Operations

Every owned operation is an `Operation`, the one retained controller: it
allocates one stable record in the scope, its allocation admission retained in
an `Acquisition` across refusals; initializes the record's resource-free prefix
in admitted units; advances it; and publishes it as a pointer-sized handle.
Construction allocates nothing. Each implements `Resumable`: `step` returns
`Step::Progress`, `Step::Complete` with the published handle, or
`Step::Finished`, and `position` observes the record's allocation,
initialization, cancellation, the scope's outstanding records and the task's
own progress without allocating.

| Operation | Built by | Publishes |
| --- | --- | --- |
| `InputAcquisition` | `owner.copy_input(bytes)` | `OwnedInitialized<ByteString>`: an independent copy, at most 64 bytes copied per admitted unit; the source is borrowed only while copying |
| `InputBorrow` | `owner.borrow_input(bytes)` | `OwnedInitialized<Borrowed>`: the borrowed bytes recorded without copying |
| `DocumentDecoder` | `DocumentDecoder::parse(input, options)` | `OwnedDocument`: the node arena paired with its own input |
| `Construction` | `Construction::construct(document)` | `TypedValue<T>`: `T` built in place in its record |
| `TypedDecoder` | `TypedDecoder::new(input, options)` | a parse, then a construction from the parsed document |
| `OwnedPreparation` | `OwnedPreparation::prepare(value)` | `OwnedPrepared`: the value's plan kept in place beside the value |

A custom input implements the unsafe `DecodeInput<A>`: immutable bytes for its
whole live lifetime, `Send`, and incremental `Reclaim<A>` for its storage,
evidence and reservations, declaring with `Reclaim::remaining` the most
cleanup calls each state can still take: the scope refuses a record's call
beyond that count as a defect, so no drain runs unbounded. The count reads
the value through its slot observed, a `PeekSlot`: no write and no exclusive
access to the value's bytes, since a published value may still be borrowed
when it is read; only the record's own custody stays reachable
(`Place::custody`). `owner.allocate_step` creates its uninitialized record;
`OwnedRecord::destination` issues the record's `Slot`: its `Place`, the root
of its provenance, and its cursor, paired. Construction, cleanup and the count
take slots through safe signatures; the `unsafe trait` contracts hold each
implementation sound for every call a slot's holder can make, in any order.
The binding initializes the value through the slot's place (`write`, or raw
projections of its parts), never through a reference over the whole value,
maintains its cursor, and calls the unsafe `publish` only once it is
complete. Every access through the place takes the cursor, borrowed: shared
for a read, exclusively for a write, so a write under a live read, or two
exclusive accesses at once, does not compile. A custom binding admits its own
work through `Budget::traverse` before doing it, as `DecodeInput`, `Reclaim`
and `InPlace` document; it is trusted to do so, and its cost is its own to
state.

A custom `Reclaim` also makes its custody observable: its `State` implements
`Custody`, whose observation is a projection of that one state, never a
second record kept beside it. The observation distinguishes every state
whose cleanup differs: what is initialized, which allocations, blocks and
permits are held or awaiting release, how many cleanup units remain, and
what an active child holds (a parent embeds its active child's whole
observation). It holds counts and phases, never an address; taking it needs
the state's exclusive custody and admits, allocates and changes nothing.
`Custody` has no default. A binding may also declare a `Reduction`, a class
map under which two states of one class take each cleanup unit, admitted or
refused, with the same outcome, release and calls, into states again of one
class; it is optional, has no default, and states its argument where it is
declared. Verification uses the observation to check cleanup and the
reduction to choose which stops it runs (`tests/OWNED-CONTRIBUTION.md`).

The engine's own records follow the same rule. Metadata initialized field by
field (a parser, a preparation, their arenas and engines) is written through a
`Slot` of the destination and its units initialized, one field per admitted
unit, each nested part over a child slot of its own units; a parse record's
arena is transferred and released through a slot pairing it with its parts
transferred and released. No engine step takes a raw destination pointer.

A cleanup step must not unwind: unwound half done, it would leave its state
recording what it no longer holds. A policy's release observer
(`Limits::observe_releases`) runs inside cleanup steps, held to their
contract: bounded, nonblocking work that allocates nothing. One that panics
aborts the process rather than unwind out of the release.

## Documents and values

`OwnedDocument::root` and `with_document` give views borrowed from the handle,
always over the document's own input; the caller cannot substitute bytes.
`bytes` and `input` borrow the retained input, custom evidence included.
`into_input` gives up the document and keeps its input handle, without
copying; the arena is retired through the scope queue.

A construction builds `T` in its final stable record through `InPlace`; the
value never moves. Once built, the document's input handle moves into the
value's record without copying and the document's record, holding only its
arena, is retired. `TypedValue::value` borrows the value, and `bytes` the
original input it was decoded from: identity and signature checks run over
these, never over a re-encoding, which may differ when decoding skipped
unknown fields.

An `OwnedPrepared` plan holds its source value until it is retired.
`into_writer` emits the plan in chunks borrowed from it (`OwnedEmitStep`:
`Progress`, `Chunk`, `Complete`, then `Finished`); emission allocates nothing.

## Cancellation and retirement

`cancel`, or a terminal error, switches an operation to its operation-local
cleanup: subsequent steps reclaim its own record, partial initialization
included, and any resource the task still holds, in place and in admitted
units, then return `Step::Finished`. This cleanup neither waits for nor spends
work on any other record in the scope. Published handles have the same
operation-local cleanup through their `reclaim_step`.

Dropping an operation or a handle at any point only retires its record: a
wait-free push onto the scope's intrusive queue, with no allocation, traversal
or destructor. The scope's `step` later reclaims it. Every handle may move to,
and retire on, any thread when its payload and `A::Permit` are `Send`; the
push precedes the release of the handle's scope reference, so the stepping
thread that observes the last reference also observes every push.

## Bounds

Every owned operation has a whole-operation `ResourceBound`, derived from its
input or source: the work it reports, the storage it requests, what it holds
at its peak and what its publication retains, on success or at any failure and
the cleanup after it. Each turn admits at most one quantum (`TURN`), and every
step admits at least one value or makes one allocation request alone, so an
operation completes within the bound's values and requested bytes in turns.

Each bound is a sum of terms, one per place its operation charges: the
operation's record, its initialization, its task and its release, and within
the task the task's own places. A record's cleanup, in place or through the
scope queue, is its operation's task's. A record holding another operation's
handle (a parse's input, a construction's document or input) charges that
handle's cleanup at its own place, accounted by the other operation's bound.

| Operation | Bound |
| --- | --- |
| `DecodeOwner` | `scope_bound()`: the scope block, its initialization and its release |
| `InputAcquisition` | `copy_bound(len)`: the copy's construction and cleanup, and, cancelled, the scope reference retired |
| `InputBorrow` | `borrow_bound()`: its completion or its cancelled retirement, and the borrow's cleanup |
| `DocumentDecoder` | `parse_bound(len, options)`: the retained parse, the arena's transfer, publication, and the record's cleanup, an emptied input slot included |
| `Construction` | `construction_bound(len)`: `InPlace::COST`, detachment, publication, and the record's cleanup, its emptied slots included |
| `TypedDecoder` | `typed_decode_bound(len, options)` |
| `OwnedPreparation` | `encoding::owned_prepare_bound(shape)`, from `encoding::Shape::of` the value |

## Borrowed interfaces

The borrowed interfaces remain available: the synchronous `decode`,
`decode_with` and `decode_typed`; the retained `cursor::Decoder` and its
`Document`; the string, header and text cursors; and the borrowed
`encoding::Preparation`, `Prepared` and `Writer`. No lifetime extension or
self-referential consumer wrapper is used by the owned interfaces.
