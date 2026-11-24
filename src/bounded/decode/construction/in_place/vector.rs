//! Stable sequence elements with retained per-element cleanup records.
//!
//! Vectors and fixed-size arrays both decode a CBOR array and share one element
//! engine: a vector's elements live in an admitted payload allocation, an
//! array's in the destination itself, which must declare exactly `N` elements,
//! as `[T; N]` encodes.
extern crate alloc;
use super::*;
use crate::bounded::boundary::{Bound, Predicate, boundary};
use crate::bounded::decode::construction::reclamation::{Custody, Peek, Place, Reduction, Uniform};
use crate::bounded::decode::construction::stable::{self, Installed, Stack, Ticket};
use crate::sync::{Atomics, Representation};
use alloc::vec::Vec;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

/// Where a sequence's construction or cleanup is: the metadata's payload
/// slot initialized, the container header written, its payload's reservation,
/// release and allocation for a vector, each element's record pushed, built
/// and committed, completion;
/// then, reclaiming, each element newest first, the container released and
/// the payload's permit and metadata freed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// The block and child stack exist; the payload-permit slot is unwritten.
    Initializing,
    Empty,
    /// The container is initialized; its payload's reservation unit is next.
    Initialized,
    /// The reservation unit admitted; the payload's release is next.
    ReleasePayload,
    /// Both admitted; the payload's allocation is next.
    AllocatePayload,
    Next,
    Child,
    Commit,
    Complete,
    Reclaim,
    BufferFreed,
}

/// What the metadata block's acquisition writes, whole: the element records,
/// each holding its element's state, and the length of the initialized
/// prefix. Records are pushed one per element in slot order, each once the
/// one before it is committed, so record `i` holds an element of the prefix
/// exactly when `i < committed`: only the newest can be outside it. The
/// count is the one record of which elements are committed.
struct Head<E, P> {
    children: Stack<E, P>,
    /// Elements in the initialized prefix.
    committed: usize,
}

struct Meta<E, P> {
    head: Head<E, P>,
    // Written in its own admitted unit. An allowed 16-byte permit can make
    // Option<P> 32 bytes, so the complete metadata need not fit one quantum.
    payload: MaybeUninit<Option<P>>,
}

impl<E, P> Representation for Head<E, P> {
    type In<S: Atomics> = Self;
}

impl<E, P> Representation for Meta<E, P> {
    type In<S: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds
/// ([`stable::Contract`]): the header, whole, and the allocation permit
/// written, the payload slot holding no initialized bytes until
/// `Initializing` advances; and the whole block. The one definition its
/// installation and the sequence's cost read.
const fn contract<E, P>() -> stable::Contract<Head<E, P>, Meta<E, P>, P> {
    stable::Contract::of()
}

/// The construction state of a sequence whose elements' states are `E`, with
/// permits of `P`: its metadata, once installed; the ticket of its own
/// acquisition pending, the metadata block's or the payload's ([`Ticket`]),
/// whose credit is the operation's; its phase; and the document index of the
/// next element, once the array's header is read. Only the sequence engine
/// reads or changes it.
pub struct State<E, P> {
    meta: Option<Installed<Meta<E, P>, P>>,
    ticket: Option<Ticket>,
    // Control belongs to the continuation, including before installation and
    // after release. It also tracks which metadata fields are initialized,
    // without reading the allocation to discover its initialization state.
    phase: Phase,
    position: usize,
}

impl<E, P> State<E, P> {
    /// Nothing installed, no header read.
    pub const INITIAL: Self = Self {
        meta: None,
        ticket: None,
        phase: Phase::Initializing,
        position: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// element records (each an `E`), the payload permit and plain counters, as
// the auto traits would derive through `Installed` and `Stack`; stated once
// here so a nested sequence's proof is one obligation per level.
unsafe impl<E: Send, P: Send> Send for State<E, P> {}

/// What a sequence's construction holds: no metadata block, or the block,
/// holding the element records. Progress alone: an acquisition bound for
/// the block, the payload or the next record is the root pending's custody,
/// reported by its observation (`CustodySink::bound`), never by this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SequenceObservation<E> {
    Unallocated,
    Held(SequenceCustody<E>),
}

/// A sequence's custody once its metadata is held, `E` an element's
/// observation: the phase; the document index of the next element; the
/// elements in the initialized prefix; the element records held; whether
/// the payload's permit is held; and the newest record, the element under
/// construction or cleanup whenever one is, whole. Every record before the
/// newest holds a committed element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SequenceCustody<E> {
    pub phase: Phase,
    pub position: usize,
    pub committed: usize,
    pub records: usize,
    pub payload: bool,
    pub newest: Option<ElementObservation<E>>,
}

/// One element record: whether its element entered the initialized prefix,
/// and the element's own observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ElementObservation<E> {
    pub committed: bool,
    pub element: E,
}

impl<E: Custody, P> Custody for State<E, P> {
    type Observation = SequenceObservation<E::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return SequenceObservation::Unallocated;
        };
        let meta = installed.get();
        let (committed, records) = (meta.head.committed, meta.head.children.len());
        SequenceObservation::Held(SequenceCustody {
            phase: self.phase,
            position: self.position,
            committed,
            records,
            // SAFETY: every phase after Initializing has written the slot;
            // short-circuiting keeps observation from reading it before then.
            payload: self.phase != Phase::Initializing
                && unsafe { meta.payload.assume_init_ref() }.is_some(),
            // The newest record is in the prefix exactly when every record
            // is ([`Head`]).
            newest: meta.head.children.top().map(|child| ElementObservation {
                committed: records == committed,
                element: child.state.observe(),
            }),
        })
    }
}

/// The cleanup classes of a sequence ([`Reduction`]), `C` its elements'
/// class. A written container's classes keep what its cleanup reads:
/// whether its payload's permit is held, the elements committed, and the
/// newest record's element, whether committed and its class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SequenceClass<C> {
    /// No metadata: one unit completes cleanup.
    Unallocated,
    /// The block alone, its payload slot unwritten: released without
    /// admission, completing cleanup.
    Initializing,
    /// No container written: one unit marks it freed.
    Empty,
    /// The container written, in any phase before cleanup: one unit enters
    /// cleanup, keeping everything else.
    Written {
        payload: bool,
        committed: usize,
        newest: Option<(bool, C)>,
    },
    /// In cleanup: the newest record's element reclaimed, popped, then the
    /// next; with none, the container released.
    Reclaim {
        payload: bool,
        committed: usize,
        newest: Option<(bool, C)>,
    },
    /// The container released: the permit, if held, and the metadata are
    /// released without admission, completing cleanup.
    Freed { payload: bool },
}

// Cleanup (`reclaim_sequence`) reads the metadata's presence and the phase,
// grouped as above; in `Reclaim`, the newest record's element through its
// own cleanup, then, once it is done, the committed count and the
// records' count: the newest record is outside the prefix exactly when the
// records exceed the count ([`Head`]), so its slot is the count's, and
// otherwise the count's predecessor, leaving the prefix (the container is
// released only with none). The class keeps the committed count and, for the
// newest record, whether the records equal it, which is that same fact: a
// record is pushed in `Next` once the one before it is committed, so the
// records are the count or one more. So every record below the newest holds
// a committed element, complete, of the elements' one complete class
// ([`Uniform`]): the committed count and the newest record fix every
// record. The element's own relation is a simulation of its cleanup, and a
// record is popped exactly when its element's cleanup reports done, after
// which the newest is the committed record below it, of the complete class,
// or none. The payload's permit is released in `Freed` without admission
// and never read before. The document position and a pending acquisition,
// whose credit the operation settles at its cleanup entry, are never read
// by cleanup, so the relation is a simulation of cleanup.
impl<E: Uniform, P> Reduction for State<E, P> {
    type Class = SequenceClass<E::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        let custody = match observation {
            SequenceObservation::Unallocated => return SequenceClass::Unallocated,
            SequenceObservation::Held(custody) => custody,
        };
        let newest = custody
            .newest
            .map(|newest| (newest.committed, E::class(&newest.element)));
        let (payload, committed) = (custody.payload, custody.committed);
        match custody.phase {
            Phase::Initializing => SequenceClass::Initializing,
            Phase::Empty => SequenceClass::Empty,
            Phase::BufferFreed => SequenceClass::Freed { payload },
            Phase::Reclaim => SequenceClass::Reclaim {
                payload,
                committed,
                newest,
            },
            Phase::Initialized
            | Phase::ReleasePayload
            | Phase::AllocatePayload
            | Phase::Next
            | Phase::Child
            | Phase::Commit
            | Phase::Complete => SequenceClass::Written {
                payload,
                committed,
                newest,
            },
        }
    }
}

/// Where a sequence keeps its elements. Every access to the container takes
/// `custody`, the sequence's construction state, which the container's place
/// is paired with ([`Place`]).
///
/// # Safety
/// After `initialize`, and `reserve` of `count` elements when not `INLINE`,
/// `elements(place, custody).add(i)` is stable storage of element `i` for
/// every `i` below `count`, owned only by this sequence, and `peek_elements`
/// observes the same storage. An element's place is rooted where the element
/// lives: a vector's heap buffer, a separate allocation, so borrowing the
/// vector's header leaves it valid; an array's own bytes, projected without
/// any borrow. `set_len` records the committed prefix without running a
/// destructor. `release` frees only the container's own storage, and only
/// once its committed prefix is empty.
unsafe trait Sequence<T>: Sized {
    /// Elements live in the destination itself; no payload is reserved.
    const INLINE: bool;
    /// The step that checks the array and initializes the container header.
    const HEADER: Unit<Caller>;
    /// The step that releases the container's own storage.
    const RELEASE: Unit<Caller>;
    /// Whether a CBOR array of `count` elements has this representation.
    fn accepts(count: usize) -> bool;
    /// # Safety
    /// `place` is uninitialized and unique; `custody` is its own.
    unsafe fn initialize<C: ?Sized>(place: Place<Self>, custody: &mut C);
    /// Physically reserve `count` elements; false on allocation failure.
    ///
    /// # Safety
    /// The container is initialized and empty; `custody` is its own.
    unsafe fn reserve<C: ?Sized>(place: Place<Self>, custody: &mut C, count: usize) -> bool;
    /// Element 0's place, for the elements' construction and cleanup: each
    /// element's is `add(index)` from it.
    ///
    /// # Safety
    /// As the trait contract; `custody` is the container's own.
    unsafe fn elements<C: ?Sized>(place: Place<Self>, custody: &mut C) -> Place<T>;
    /// Element 0's place, observed: what a count reads, borrowing no part of
    /// the container exclusively.
    ///
    /// # Safety
    /// As [`Self::elements`], with the container initialized.
    unsafe fn peek_elements<C: ?Sized>(place: Peek<Self>, custody: &C) -> Peek<T>;
    /// The elements the container's storage holds room for: below it, an
    /// element's place lies within that storage.
    ///
    /// # Safety
    /// The container is initialized; `custody` is its own.
    unsafe fn capacity<C: ?Sized>(place: Peek<Self>, custody: &C) -> usize;
    /// # Safety
    /// Exactly the first `len` elements are initialized; `custody` is the
    /// container's own.
    unsafe fn set_len<C: ?Sized>(place: Place<Self>, custody: &mut C, len: usize);
    /// # Safety
    /// The container is initialized and its committed prefix is empty;
    /// `custody` is its own.
    unsafe fn release<C: ?Sized>(place: Place<Self>, custody: &mut C);
}

// SAFETY: elements live in the reserved spare capacity, a separate allocation
// that cannot move while construction holds the only access to the header;
// their places are rooted at the buffer pointer `Vec` hands out, which its
// documentation keeps valid across later borrows of the header. Release
// drops an empty Vec, freeing only its buffer.
unsafe impl<T> Sequence<T> for Vec<T> {
    const INLINE: bool = false;
    const HEADER: Unit<Caller> = sized::<Vec<T>>();
    const RELEASE: Unit<Caller> = sized::<Vec<T>>();

    fn accepts(_: usize) -> bool {
        true
    }

    unsafe fn initialize<C: ?Sized>(place: Place<Self>, custody: &mut C) {
        // SAFETY: forwarded from the caller: an empty, uninitialized
        // destination, its write admitted by the header unit.
        unsafe { place.write(custody, Vec::new()) };
    }

    unsafe fn reserve<C: ?Sized>(place: Place<Self>, custody: &mut C, count: usize) -> bool {
        // SAFETY: the header is initialized and empty, so no element place
        // exists; the buffer it reserves is a separate allocation.
        unsafe { place.with_mut(custody, |vector| vector.try_reserve_exact(count)) }.is_ok()
    }

    unsafe fn elements<C: ?Sized>(place: Place<Self>, custody: &mut C) -> Place<T> {
        // SAFETY: the borrow covers the header alone, in which no element
        // place lies; `as_mut_ptr` forms no reference to the buffer and
        // permits writes through the nonnull pointer it returns, the start of
        // the reserved capacity.
        unsafe {
            let buffer = place.with_mut(custody, Vec::as_mut_ptr);
            Place::root(NonNull::new_unchecked(buffer.cast::<MaybeUninit<T>>()))
        }
    }

    unsafe fn peek_elements<C: ?Sized>(place: Peek<Self>, custody: &C) -> Peek<T> {
        // SAFETY: the header is initialized and read through a shared
        // borrow; `as_ptr` forms no reference to the buffer. The observing
        // place writes nothing through the pointer, as `as_ptr` requires.
        unsafe {
            let buffer = place.get(custody).as_ptr().cast_mut();
            Place::root(NonNull::new_unchecked(buffer.cast::<MaybeUninit<T>>()))
        }
    }

    unsafe fn capacity<C: ?Sized>(place: Peek<Self>, custody: &C) -> usize {
        // SAFETY: forwarded from the caller: the header is initialized, read
        // through a shared borrow.
        unsafe { place.get(custody) }.capacity()
    }

    unsafe fn set_len<C: ?Sized>(place: Place<Self>, custody: &mut C, len: usize) {
        // SAFETY: forwarded from the caller; the borrow covers the header
        // alone, in which no element place lies.
        unsafe { place.with_mut(custody, |vector| vector.set_len(len)) };
    }

    unsafe fn release<C: ?Sized>(place: Place<Self>, custody: &mut C) {
        // SAFETY: no live elements remain; only the backing buffer is freed.
        // Its payload reservation is released by the following phase.
        unsafe { place.drop_in_place(custody) };
    }
}

// SAFETY: element `i` is the destination's own `i`th slot, projected from its
// place by pointer arithmetic alone; the array has no header or buffer, and
// its committed prefix is recorded in the metadata.
unsafe impl<T, const N: usize> Sequence<T> for [T; N] {
    const INLINE: bool = true;
    const HEADER: Unit<Caller> = STEP;
    const RELEASE: Unit<Caller> = STEP;

    fn accepts(count: usize) -> bool {
        count == N
    }

    unsafe fn initialize<C: ?Sized>(_: Place<Self>, _: &mut C) {}

    unsafe fn reserve<C: ?Sized>(_: Place<Self>, _: &mut C, _: usize) -> bool {
        // Inline storage is the destination itself.
        true
    }

    unsafe fn elements<C: ?Sized>(place: Place<Self>, _: &mut C) -> Place<T> {
        // SAFETY: `[T; N]` lays out element 0 at its start.
        unsafe { place.cast::<T>() }
    }

    unsafe fn peek_elements<C: ?Sized>(place: Peek<Self>, _: &C) -> Peek<T> {
        // SAFETY: as `elements`, in the observing mode.
        unsafe { place.cast::<T>() }
    }

    unsafe fn capacity<C: ?Sized>(_: Peek<Self>, _: &C) -> usize {
        N
    }

    unsafe fn set_len<C: ?Sized>(_: Place<Self>, _: &mut C, _: usize) {}

    unsafe fn release<C: ?Sized>(_: Place<Self>, _: &mut C) {}
}

/// The cost of sequence `Q` of elements `T` of cost `element`, whose states
/// are `E`, with permits of `P`. Fixed: the metadata block, held for the
/// value's life, initialized in two bounded writes; the header write; when
/// the elements are not inline, the payload reservation unit and the payload's
/// release, admitted before it is
/// allocated; the final unit; then cleanup's transition, the container's
/// release and the metadata's. Per element, each at least one byte: its
/// custody record, held, and its commit; its record's release; and its
/// storage, held when it is not the destination's own. The elements' own
/// costs compose as children ([`ConstructionCost::checked_children`]). None
/// when a quantity does not fit in `u64`.
const fn sequence_cost<T, Q: Sequence<T>, E, P>(
    element: ConstructionCost,
) -> Option<ConstructionCost> {
    let meta = contract::<E, P>();
    let child = Stack::<E, P>::RECORD;
    let release = stable::release_cost::<P>();
    let storage = if Q::INLINE { 0 } else { size_of::<T>() };
    let payload = if Q::INLINE {
        ConstructionCost::ZERO.fixed
    } else {
        cost!(STEP_COST.checked_add(release))
    };
    let header = cost!(
        cost!(meta.write().checked_add(sized::<Option<P>>().bound()))
            .checked_add(Q::HEADER.bound())
    );
    let build = cost!(header.checked_add(cost!(payload.checked_add(STEP_COST))));
    // The transition, the container's release and the metadata's.
    let cleanup = cost!(cost!(STEP_COST.checked_add(Q::RELEASE.bound())).checked_add(release));
    let record = cost!(cost!(child.write().checked_add(STEP_COST)).checked_add(release));
    let each = cost!(record.checked_add(cost!(held(child.block()).checked_add(held(storage)))));
    let fixed = cost!(cost!(build.checked_add(cleanup)).checked_add(held(meta.block())));
    let per_byte = cost!(ConstructionCost::checked_per_byte(each));
    let own = cost!(ConstructionCost::fixed(fixed).checked_add(per_byte));
    own.checked_add(cost!(element.checked_children()))
}

/// The construction state of a sequence of `T`, its elements' own states,
/// parts of the sequence's, in its records.
type SequenceState<T, A> =
    State<<T as Reclaim<A>>::State, <A as crate::bounded::Releasing>::Permit>;

/// The payload permit's slot in a sequence's metadata, for
/// [`stable::allocate_payload`]: refused before `Initializing`'s unit wrote
/// it, so it is never read unwritten.
fn payload<E, P, R>(state: &mut State<E, P>) -> Result<&mut Option<P>, BoundedError<R>> {
    if state.phase == Phase::Initializing {
        return Err(BoundedError::PlanMismatch);
    }
    let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
    // SAFETY: every phase after Initializing has written the slot.
    Ok(unsafe { meta.payload.assume_init_mut() })
}

/// One admitted construction unit of sequence `Q` in the context's slot,
/// from the context's node, an array. Without metadata the state is
/// `INITIAL`, so construction begins; any phase past construction is
/// refused. Each element is built as a part ([`build_part`]), its context
/// projected from this one's slot. The recorded `position` is the next
/// element's node: this sequence's own progress through its children, the
/// one record of which node its current element continues from.
fn build_sequence<'b, T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    ctx: Context<'b, '_, '_, '_, Q, SequenceState<T, A>, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, Q>, A> {
    let mut ctx = ctx;
    let assembly = ctx.assembly();
    let index = ctx.index();
    let node = ctx.node();
    let position = ctx.slot().custody().position;
    let current = ctx.node_at(position);
    let (mut slot, pending) = ctx.acquiring();
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        if state.phase != Phase::Initializing {
            return Err(BoundedError::PlanMismatch.into());
        }
        // SAFETY: the header, the stack and count, is written whole at its
        // field; MaybeUninit permits the payload slot to remain unwritten
        // until the next phase.
        unsafe {
            stable::install::<Meta<T::State, A::Permit>, Head<T::State, A::Permit>, A>(
                const { contract::<T::State, A::Permit>() },
                &mut state.meta,
                pending,
                &mut state.ticket,
                || Head {
                    children: Stack::new(),
                    committed: 0,
                },
                |meta| ptr::addr_of_mut!((*meta).head),
                a,
            )?
        };
        return Ok(Building::Progress);
    }
    // Element 0's place and the storage's room, taken under the sequence's
    // custody before its metadata is borrowed: an element building needs
    // both, and its place lies in the container's storage, outside the
    // metadata.
    // SAFETY: in `Child` the container is initialized and its storage
    // reserved.
    let elements = (state.phase == Phase::Child).then(|| unsafe {
        let capacity = Q::capacity(place.observe(), &*state);
        (Q::elements(place, &mut *state), capacity)
    });
    let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
    if state.phase == Phase::Initializing {
        const { sized::<Option<A::Permit>>() }.admit(a)?;
        meta.payload.write(None);
        state.phase = Phase::Empty;
        return Ok(Building::Progress);
    }
    if state.phase == Phase::Empty {
        Q::HEADER.admit(a)?;
        let Some(Kind::Array(count)) = node.map(|n| n.kind()) else {
            return Err(wrong_type());
        };
        if !Q::accepts(usize::try_from(count).map_err(|_| BoundedError::Overflow)?) {
            return Err(wrong_type());
        }
        // SAFETY: no container has yet been initialized at this destination.
        unsafe { Q::initialize(place, state) };
        state.phase = if Q::INLINE {
            Phase::Next
        } else {
            Phase::Initialized
        };
        state.position = index.checked_add(1).ok_or(BoundedError::Overflow)?;
        return Ok(Building::Progress);
    }
    let Some(Kind::Array(count)) = node.map(|n| n.kind()) else {
        return Err(wrong_type());
    };
    let count = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
    match state.phase {
        Phase::Initialized => {
            STEP.admit(a)?;
            state.phase = Phase::ReleasePayload;
        }
        Phase::ReleasePayload => {
            stable::admit_release(pending, &mut state.ticket, a)?;
            state.phase = Phase::AllocatePayload;
        }
        Phase::AllocatePayload => {
            let bytes = count
                .checked_mul(size_of::<T>())
                .ok_or(BoundedError::Overflow)?;
            let bytes = u64::try_from(bytes).map_err(|_| BoundedError::Overflow)?;
            // The ticket moves out of the state for the call, which borrows
            // the state as the payload's custody, and back whatever the call
            // returns.
            let mut ticket = state.ticket.take();
            let allocated = stable::allocate_payload(
                state,
                payload,
                bytes,
                // SAFETY: AllocatePayload follows the container's
                // initialization, and no element is reserved yet: it is
                // empty.
                |state| unsafe { Q::reserve(place, state, count) },
                pending,
                &mut ticket,
                a,
            );
            state.ticket = ticket;
            allocated?;
            state.phase = Phase::Next;
        }
        Phase::Next => {
            // The node holds exactly the elements its count claims: `position`,
            // the next element's node, is inside the array's subtree exactly
            // while an element remains. A child beyond the count is refused
            // before it is built, and fewer children than the count before a
            // record is pushed for one that does not exist; both are
            // `PlanMismatch`, nothing changed, since a decoded document's
            // array node always holds its count.
            let end = super::super::next_index(node.ok_or_else(wrong_type)?);
            let inside = boundary!(a, Predicate::ArenaLength, state.position, end).is_lt();
            if boundary!(a, Predicate::ArenaLength, meta.head.committed, count).is_eq() {
                if inside {
                    return Err(BoundedError::PlanMismatch.into());
                }
                STEP.admit(a)?;
                state.phase = Phase::Complete;
                // SAFETY: the container was initialized in `Empty` and, for a
                // vector, its storage reserved for `count` elements; every
                // element of the prefix entered it in `Commit`, which follows
                // only a `Done` whose record, confined by its brand to the
                // step that minted it, `build_part` verified against the
                // place this sequence projected for that element; the prefix
                // now holds `count` elements, recorded by `set_len`, and the
                // slot is not reclaimed: its cleanup is refused while it
                // builds.
                return Ok(Building::Done(unsafe { assembly.assemble() }));
            }
            if !inside {
                return Err(BoundedError::PlanMismatch.into());
            }
            meta.head.children.push(T::INITIAL, pending, a)?;
            state.phase = Phase::Child;
        }
        Phase::Child => {
            let (elements, capacity) = elements.ok_or(BoundedError::PlanMismatch)?;
            let committed = meta.head.committed;
            // The element's slot lies within the storage reserved: a count
            // read at a later step that would pass it is refused here, before
            // any place outside the storage exists.
            if Bound::new(Predicate::ArenaLength, capacity).reached(a, committed) {
                return Err(BoundedError::PlanMismatch.into());
            }
            // SAFETY: `committed` is below the storage's capacity; reserved
            // storage cannot move during child construction; the newest
            // record, held in this sequence's metadata, holds the state of
            // exactly this slot, the first past the committed prefix.
            let element = unsafe {
                ctx.part(position, |slot| {
                    let meta = slot
                        .into_parts()
                        .1
                        .meta
                        .as_mut()
                        .ok_or(BoundedError::PlanMismatch)?;
                    let record = meta
                        .get()
                        .head
                        .children
                        .top()
                        .ok_or(BoundedError::PlanMismatch)?;
                    Ok::<_, BoundedError<A::Refusal>>(Slot::new(
                        elements.add(committed),
                        &mut record.state,
                    ))
                })
            }?;
            if build_part::<T, A>(element, a)? == Built::Done {
                ctx.slot().custody().phase = Phase::Commit;
            }
        }
        Phase::Commit => {
            // Only the newest record is past the committed prefix, and it is
            // the element built: one record more than the prefix.
            if meta.head.children.len() != meta.head.committed + 1 {
                return Err(BoundedError::PlanMismatch.into());
            }
            STEP.admit(a)?;
            let node = current.ok_or_else(wrong_type)?;
            state.position = super::super::next_index(node);
            meta.head.committed += 1;
            let committed = meta.head.committed;
            // SAFETY: the child returned Done at slot `committed - 1`.
            unsafe { Q::set_len(place, state, committed) };
            state.phase = Phase::Next;
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Building::Progress)
}

/// One admitted cleanup unit of sequence `Q` in `slot`, following the
/// retained child records in reverse order, each element as a part
/// ([`reclaim_part`]). Partial children never enter the committed prefix;
/// committed elements leave it only after their own cleanup returns Done,
/// and the container is released empty. Every path that releases the
/// metadata leaves the state `INITIAL`. No build follows: the root's session
/// refuses every build once its cleanup began, and a parent holding this
/// sequence as a part reclaims it only from its own cleanup phases.
fn reclaim_sequence<T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    mut slot: Slot<'_, Q, SequenceState<T, A>>,
    a: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
        // The metadata's acquisition, if pending, had its credit settled at
        // the operation's cleanup entry: the ticket is forgotten.
        state.ticket = None;
        state.position = 0;
        return Ok(Reclaimed::Done);
    }
    // Element 0's place, taken under the sequence's custody before its
    // metadata is borrowed, as in `build`.
    // SAFETY: entering `Reclaim` proves the container is initialized.
    let elements =
        (state.phase == Phase::Reclaim).then(|| unsafe { Q::elements(place, &mut *state) });
    let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
    match state.phase {
        Phase::Initializing => {
            // No child or payload exists. Only the acquired block is freed,
            // using its prepaid release; the unwritten slot is never read.
            unsafe { stable::uninstall(&mut state.meta) };
            state.position = 0;
            return Ok(Reclaimed::Done);
        }
        Phase::Empty => {
            STEP.admit(a)?;
            state.phase = Phase::BufferFreed;
        }
        Phase::Initialized
        | Phase::ReleasePayload
        | Phase::AllocatePayload
        | Phase::Next
        | Phase::Child
        | Phase::Commit
        | Phase::Complete => {
            STEP.admit(a)?;
            // A payload's or a record's acquisition pending had its credit
            // settled at the operation's cleanup entry: the tickets are
            // forgotten.
            state.ticket = None;
            meta.head.children.abandon();
            state.phase = Phase::Reclaim;
        }
        Phase::Reclaim => {
            let elements = elements.ok_or(BoundedError::PlanMismatch)?;
            let records = meta.head.children.len();
            if records == 0 {
                if meta.head.committed != 0 {
                    return Err(BoundedError::PlanMismatch);
                }
                Q::RELEASE.admit(a)?;
                // SAFETY: entering Reclaim proves the container is initialized,
                // and no element remains.
                unsafe { Q::release(place, state) };
                state.phase = Phase::BufferFreed;
                return Ok(Reclaimed::Progress);
            }
            // The newest record is in the prefix exactly when every record
            // is ([`Head`]).
            let committed = records == meta.head.committed;
            let slot = if committed {
                if boundary!(a, Predicate::ArenaLength, meta.head.committed, 0).is_eq() {
                    return Err(BoundedError::PlanMismatch);
                }
                meta.head.committed - 1
            } else {
                meta.head.committed
            };
            let child = meta.head.children.top().ok_or(BoundedError::PlanMismatch)?;
            // SAFETY: a partial slot was reserved before its record was pushed;
            // committed slots lie inside the prefix; the record holds the
            // state of exactly this slot.
            let destination = unsafe { Slot::new(elements.add(slot), &mut child.state) };
            if reclaim_part::<T, A>(destination, a)? == Reclaimed::Done {
                // The element is reclaimed completely: its record is freed in
                // the same step, a release its push paid for.
                meta.head.children.pop();
                if committed {
                    meta.head.committed = slot;
                    // SAFETY: the reclaimed element leaves the prefix without
                    // running a destructor.
                    unsafe { Q::set_len(place, state, slot) };
                }
            }
        }
        Phase::BufferFreed => {
            // The payload's permit, if one was granted, and the metadata are
            // released: both releases were paid for by their acquisitions.
            // SAFETY: Initializing is handled separately; every other phase
            // follows the admitted initialization of this slot.
            drop(unsafe { meta.payload.assume_init_mut() }.take());
            // SAFETY: no children or payload allocation remain.
            unsafe { stable::uninstall(&mut state.meta) };
            state.position = 0;
            state.phase = Phase::Initializing;
            return Ok(Reclaimed::Done);
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim_sequence`] still takes from `slot`'s state: no
/// metadata or only the block, one; nothing written, two; written, one to
/// enter `Reclaim`, then every element's own calls ([`remaining_part`]),
/// the container's release and the metadata's; in
/// `Reclaim`, the latter three; freed, one. `None` when the count does not
/// fit in `u64`.
fn remaining_sequence<T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    mut slot: PeekSlot<'_, Q, SequenceState<T, A>>,
) -> Option<u64> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        return Some(1);
    }
    // Without an initialized container no element record exists.
    match state.phase {
        Phase::Initializing | Phase::BufferFreed => return Some(1),
        Phase::Empty => return Some(2),
        _ => {}
    }
    // Element 0's place, observed under the sequence's custody before its
    // metadata is borrowed.
    // SAFETY: every remaining phase follows the container's initialization.
    let elements = unsafe { Q::peek_elements(place, &*state) };
    let meta = state.meta.as_mut()?.get();
    let mut drain = Some(0u64);
    // The records are pushed one per element in slot order, so the record
    // `records - 1 - n`, visited `n`th newest first, holds slot
    // `records - 1 - n`.
    let mut slot = meta.head.children.len();
    meta.head.children.for_each(|child| {
        slot -= 1;
        // SAFETY: every recorded slot was reserved, in an initialized
        // container, before its record was pushed; the record's state
        // describes that slot.
        let destination = unsafe { Slot::new(elements.add(slot), child) };
        drain = drain.and_then(|drain| drain.checked_add(remaining_part::<T, A>(destination)?));
    });
    // Each record's own calls, then the container's release and the metadata's.
    let reclaiming = drain?.checked_add(2)?;
    if state.phase == Phase::Reclaim {
        Some(reclaiming)
    } else {
        reclaiming.checked_add(1)
    }
}

/// The permits sequence `Q` in `slot` owns ([`Reclaim::observe_permits`]),
/// reported inside the caller's open group: its metadata block's; its
/// payload's, once its slot is written and a permit granted; then, newest
/// first, each element record's block and the element's own
/// ([`observe_part`]), each record paired with its slot as the cleanup count
/// pairs them. Without an initialized container no record exists; once it
/// is released none remains.
fn permits_sequence<T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    mut slot: PeekSlot<'_, Q, SequenceState<T, A>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    sink.permit(installed.permit(), None);
    if state.phase == Phase::Initializing {
        return PermitsObserved::Complete;
    }
    // SAFETY: every phase after Initializing has written the payload slot.
    if let Some(payload) = unsafe { installed.get().payload.assume_init_ref() } {
        sink.permit(payload, None);
    }
    if matches!(state.phase, Phase::Empty | Phase::BufferFreed) {
        return PermitsObserved::Complete;
    }
    // Element 0's place, observed under the sequence's custody before its
    // metadata is borrowed.
    // SAFETY: every remaining phase follows the container's initialization.
    let elements = unsafe { Q::peek_elements(place, &*state) };
    let Some(installed) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    let children = &mut installed.get().head.children;
    let mut index = children.len();
    let mut whole = PermitsObserved::Complete;
    children.for_each_record(|permit, child| {
        index -= 1;
        sink.permit(permit, None);
        // SAFETY: every recorded slot was reserved, in an initialized
        // container, before its record was pushed; the record's state
        // describes that slot.
        let element = observe_part::<T, A>(unsafe { Slot::new(elements.add(index), child) }, sink);
        whole = observed_all([whole, element]);
    });
    whole
}

// SAFETY: admission, state, done, escape, provenance and order: the shared
// sequence engine's (`build_sequence`, the one engine of `Vec` and arrays):
// admission: the metadata, the header, the payload reservation, each child
// record and every element step (`build_part`) are admitted before they run.
// state: a child record is pushed before its element acquires anything and
// describes that element until reclamation, partials included. done: `Done`
// once the declared count of elements is built and the length committed;
// more or fewer children than declared are refused. escape: element places
// lie in the reserved buffer the header owns and are never returned.
// provenance: the engine initializes the header and each spare-capacity
// child in final storage, through places derived from the slot's. order: a
// build past completion or once cleanup began is refused `PlanMismatch`,
// nothing changed. cost: `sequence_cost` of the sequence's parts over
// `T::COST`.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for Vec<T> {
    /// The sequence's own parts (`sequence_cost`) over each element's cost.
    const COST: ConstructionCost =
        crate::const_cost!(sequence_cost::<T, Self, T::State, A::Permit>(T::COST));

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        build_sequence::<T, Self, A>(ctx, a)
    }
}

// SAFETY: initial: `State::INITIAL`, nothing installed, no child recorded.
// state: the metadata, the header's phase, the payload's permit and each
// child's record describe everything acquired. admission: each cleanup unit
// of the shared engine (`reclaim_sequence`), and each child's own
// (`reclaim_part`), is admitted before it runs, a refusal changing nothing.
// cleanup: the engine reclaims every recorded child through its own binding,
// newest first, then frees the buffer without dropping elements, allocating
// nothing and never unwinding. done: `Done` once every child is reclaimed and
// the buffer and metadata released. order: a step after `Done` reports
// `Done`; the count and observation read only recorded children. depth: one
// level above `T`'s, exact. count: `remaining_sequence` counts every child's
// remaining and the engine's own units.
unsafe impl<T: InPlace<A>, A: Allocator> Reclaim<A> for Vec<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = SequenceState<T, A>;
    const INITIAL: Self::State = State::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_sequence::<T, Self, A>(slot, cleanup)
    }

    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        remaining_sequence::<T, Self, A>(slot)
    }

    fn observe_permits(
        slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        permits_sequence::<T, Self, A>(slot, sink)
    }
}

// SAFETY: admission, state, done, escape, provenance and order: the shared
// sequence engine's, as for Vec, with each element built in the destination's
// own slot: admission: each child record and element step is admitted before
// it runs. state: a child record is pushed before its element acquires
// anything and describes it until reclamation. done: `Done` once exactly `N`
// elements are built; another count is refused. escape: element places lie
// within the array's own place and are never returned. provenance: each
// element's place is projected from the slot's. order: a build past
// completion or once cleanup began is refused `PlanMismatch`, nothing
// changed. cost: `sequence_cost` over `T::COST`, with no storage of its own.
unsafe impl<T: InPlace<A>, A: Allocator, const N: usize> InPlace<A> for [T; N] {
    /// As for `Vec`, with no storage of its own.
    const COST: ConstructionCost =
        crate::const_cost!(sequence_cost::<T, Self, T::State, A::Permit>(T::COST));

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        build_sequence::<T, Self, A>(ctx, a)
    }
}

// SAFETY: initial: `State::INITIAL`, no child recorded. state: each child's
// record describes everything acquired. admission: each cleanup unit, the
// engine's and each child's, is admitted before it runs, a refusal changing
// nothing. cleanup: as for Vec, each recorded child reclaimed through its own
// binding, newest first; the array owns no storage of its own to release;
// nothing is allocated and nothing unwinds. done: `Done` once every child is
// reclaimed. order: a step after `Done` reports `Done`; the count and
// observation read only recorded children. depth: one level above `T`'s,
// exact. count: `remaining_sequence`.
unsafe impl<T: InPlace<A>, A: Allocator, const N: usize> Reclaim<A> for [T; N] {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = SequenceState<T, A>;
    const INITIAL: Self::State = State::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_sequence::<T, Self, A>(slot, cleanup)
    }

    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        remaining_sequence::<T, Self, A>(slot)
    }

    fn observe_permits(
        slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        permits_sequence::<T, Self, A>(slot, sink)
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::super::text::BufferState;
    use super::*;
    use crate::bounded::decode::construction::Written;
    use crate::bounded::decode::{DecodeError, decode};
    use crate::bounded::{LimitRefusal, Limits, Reservation, WriteWork};

    // Instantiate both write boundaries: the metadata's two units and the
    // parent's child record containing this continuation. u128 exercises a
    // full-size permit without Reservation's pointer niche, including its
    // stronger alignment on targets that give it 16-byte alignment.
    // A sequence whose elements' state is `S` records each element's state:
    // the metadata and the record of `S`, and, nested, the record of a
    // sequence of such sequences.
    fn layouts<S, P>() {
        let _ = const { contract::<S, P>() };
        let _ = const { sized::<Option<P>>() };
        let _ = const { Stack::<S, P>::RECORD };
        let _ = const { Stack::<State<S, P>, P>::RECORD };
    }

    #[test]
    fn metadata_and_nested_child_writes_fit_at_the_permit_boundary() {
        layouts::<Written, Reservation>();
        layouts::<BufferState<Reservation>, Reservation>();
        layouts::<State<BufferState<Reservation>, Reservation>, Reservation>();
        layouts::<Written, [u8; 16]>();
        layouts::<Written, u128>();
        layouts::<State<Written, u128>, u128>();
        let cost = crate::const_cost!(sequence_cost::<u8, Vec<u8>, Written, u128>(
            ConstructionCost::ZERO
        ));
        assert!(cost.bound::<()>(1).is_ok());
    }

    /// A sequence's cost evaluated at run time is the constant its vector
    /// and array are charged, and what separates them is a vector's own
    /// storage: its elements' bytes held per byte, its payload's
    /// reservation step and release once. An array's storage is the
    /// destination itself, so reserving it requests nothing and succeeds.
    #[test]
    fn a_vectors_cost_exceeds_an_arrays_by_its_own_storage() {
        let element = <u64 as InPlace<Limits>>::COST;
        let vector = sequence_cost::<u64, Vec<u64>, Written, Reservation>(element)
            .expect("a vector's cost fits in u64");
        let array = sequence_cost::<u64, [u64; 3], Written, Reservation>(element)
            .expect("an array's cost fits in u64");
        assert_eq!(vector, <Vec<u64> as InPlace<Limits>>::COST);
        assert_eq!(array, <[u64; 3] as InPlace<Limits>>::COST);
        let meta = contract::<Written, Reservation>();
        let constant = const { contract::<Written, Reservation>() };
        assert_eq!(meta.write(), constant.write());
        assert_eq!(meta.block(), constant.block());
        assert_eq!(
            vector.per_byte.allocated - array.per_byte.allocated,
            PER_BYTE_SCALE * size_of::<u64>() as u64,
            "a vector holds its elements' storage per byte"
        );
        assert_eq!(
            vector.fixed.values - array.fixed.values,
            STEP_COST.values + stable::release_cost::<Reservation>().values,
            "a vector reserves and releases its payload once"
        );
        let mut storage = MaybeUninit::<[u64; 3]>::uninit();
        let mut custody = ();
        // SAFETY: the test owns the destination; the array's reserve reads
        // and writes nothing.
        let reserved = unsafe {
            <[u64; 3] as Sequence<u64>>::reserve(
                Place::root(NonNull::from(&mut storage)),
                &mut custody,
                3,
            )
        };
        assert!(reserved, "an array's storage is the destination itself");
    }

    type Bytes = Session<<Vec<u8> as Reclaim<Limits>>::State>;

    /// The pending credit of a construction under [`Limits`].
    type Credit = stable::Pending<<Limits as crate::bounded::Budget>::Origin>;

    /// A vector of bytes' destination and its session, initial, and the
    /// pending credit of its construction, its owner made by its first
    /// acquisition entry.
    fn destination() -> (MaybeUninit<Vec<u8>>, Bytes, Credit) {
        (
            MaybeUninit::uninit(),
            Session::new(<Vec<u8> as Reclaim<Limits>>::INITIAL),
            stable::Pending::deferred(),
        )
    }

    /// One engine unit of construction of the vector in `slot` from the root
    /// of `document`, its acquisitions' credit held in `pending`.
    fn step(
        document: &crate::bounded::decode::Document<'_, Reservation>,
        slot: &mut Slot<'_, Vec<u8>, Bytes>,
        pending: &mut Credit,
        policy: &mut Limits,
    ) -> ConstructResult<Built, Limits> {
        build::<Vec<u8>, Limits>(Context::root(document, slot.reborrow(), pending), policy)
    }

    #[test]
    fn unwritten_payload_slot_is_observable_and_reclaimed_without_reading_it() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let (mut value, mut session, mut pending) = destination();
        // SAFETY: the test owns the destination and pairs it with its initial
        // session; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut session) };
        assert_eq!(
            step(&document, &mut slot, &mut pending, &mut policy).unwrap(),
            Built::Progress,
            "the session binds the root"
        );
        policy.turn();
        assert_eq!(
            step(&document, &mut slot, &mut pending, &mut policy).unwrap(),
            Built::Progress,
        );
        assert_eq!(
            slot.custody().inner.observe(),
            SequenceObservation::Held(SequenceCustody {
                phase: Phase::Initializing,
                position: 0,
                committed: 0,
                records: 0,
                payload: false,
                newest: None,
            })
        );
        assert!(pending.is_idle(), "the installed block's acquisition ended");
        policy.turn();
        assert_eq!(
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap(),
            Reclaimed::Progress,
            "cleanup begins in its own unit"
        );
        assert_eq!(slot.custody().stage(), Stage::Cleaning);
        let attempts = policy.attempts();
        policy.exhaust();
        assert_eq!(
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.attempts(), attempts, "release was prepaid");
        assert_eq!(policy.live_bytes(), 0);
        assert_eq!(slot.custody().stage(), Stage::Released);
        assert_eq!(
            slot.custody().inner.observe(),
            SequenceObservation::Unallocated
        );
    }

    /// A sequence reclaimed to `Done` is released: its state is `INITIAL`
    /// again, a further cleanup reports `Done` admitting nothing, and a
    /// further build is refused, nothing changed, instead of beginning anew.
    #[test]
    fn a_released_sequence_refuses_every_later_build_and_admits_nothing() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::unlimited();
        let (mut value, mut session, mut pending) = destination();
        // SAFETY: the test owns the destination and pairs it with its initial
        // session; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut session) };
        crate::bounded::within_steps("an empty vector's construction", 16, || {
            match step(&document, &mut slot, &mut pending, &mut policy).unwrap() {
                Built::Done => core::ops::ControlFlow::Break(()),
                Built::Progress => core::ops::ControlFlow::Continue(()),
            }
        });
        let declared = remaining::<Vec<u8>, Limits>(slot.observe())
            .expect("an empty vector's cleanup count fits in u64");
        crate::bounded::within_steps("an empty vector's cleanup", declared, || {
            match reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy))
                .unwrap()
            {
                Reclaimed::Done => core::ops::ControlFlow::Break(()),
                _ => core::ops::ControlFlow::Continue(()),
            }
        });
        assert_eq!(slot.custody().stage(), Stage::Released);
        assert_eq!(slot.custody().inner.phase, Phase::Initializing);
        assert_eq!(
            slot.custody().inner.observe(),
            SequenceObservation::Unallocated
        );
        let attempts = policy.attempts();
        assert_eq!(
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap(),
            Reclaimed::Done,
            "a step after Done"
        );
        assert!(matches!(
            step(&document, &mut slot, &mut pending, &mut policy),
            Err(DecodeError::Resource(BoundedError::PlanMismatch))
        ));
        assert_eq!(
            policy.attempts(),
            attempts,
            "nothing admitted after release"
        );
        assert_eq!(slot.custody().stage(), Stage::Released);
        assert_eq!(policy.live_bytes(), 0);
    }

    /// A sequence whose cleanup began refuses every build, admitting
    /// nothing and changing nothing: in `Reclaim`, and in `BufferFreed`
    /// before its metadata is released. As a part no build reaches it then
    /// (its parent steps it only from the parent's own build phases), and at
    /// the root its session refuses first; this is the sequence's own guard,
    /// reached here directly, as a parent's build would reach it.
    #[test]
    fn a_sequence_in_cleanup_refuses_a_build_and_admits_nothing() {
        let mut parser = Limits::unlimited();
        // [1]
        let document = decode(&[0x81, 0x01], 1, &mut parser).unwrap();
        let mut policy = Limits::unlimited();
        let (mut value, mut session, mut pending) = destination();
        // SAFETY: the test owns the destination; every access to it is
        // through this place for the rest of the test.
        let place = unsafe { Place::root(NonNull::from(&mut value)) };
        {
            // SAFETY: the test owns the destination and pairs it with its
            // initial session; every access is through slots of this place.
            let mut slot = unsafe { Slot::new(place, &mut session) };
            while step(&document, &mut slot, &mut pending, &mut policy).unwrap() != Built::Done {}
            // The session's begin unit, then the sequence's own entry into
            // `Reclaim`.
            for _ in 0..2 {
                reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy))
                    .unwrap();
            }
        }
        // The sequence's own build, as a parent reaches it, from `phase`.
        fn refused_at(
            document: &crate::bounded::decode::Document<'_, Reservation>,
            place: Place<Vec<u8>>,
            session: &mut Bytes,
            pending: &mut Credit,
            policy: &mut Limits,
            phase: Phase,
        ) {
            assert_eq!(session.inner.phase, phase);
            let before = session.inner.observe();
            let attempts = policy.attempts();
            // SAFETY: the same place, paired with its sequence's own state.
            let slot = unsafe { Slot::new(place, &mut session.inner) };
            let result = build_sequence::<u8, Vec<u8>, Limits>(
                Context::root(document, slot, pending),
                policy,
            );
            assert!(
                matches!(
                    result,
                    Err(DecodeError::Resource(BoundedError::PlanMismatch))
                ),
                "a build in {phase:?}: {result:?}"
            );
            assert_eq!(
                policy.attempts(),
                attempts,
                "a build in {phase:?} admitted work"
            );
            assert_eq!(
                session.inner.observe(),
                before,
                "a build in {phase:?} moved"
            );
        }
        refused_at(
            &document,
            place,
            &mut session,
            &mut pending,
            &mut policy,
            Phase::Reclaim,
        );
        // SAFETY: as above.
        let mut slot = unsafe { Slot::new(place, &mut session) };
        while slot.custody().inner.phase != Phase::BufferFreed {
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap();
        }
        refused_at(
            &document,
            place,
            &mut session,
            &mut pending,
            &mut policy,
            Phase::BufferFreed,
        );
        // SAFETY: as above.
        let mut slot = unsafe { Slot::new(place, &mut session) };
        assert_eq!(
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap(),
            Reclaimed::Done
        );
        assert_eq!(policy.live_bytes(), 0);
    }

    #[test]
    fn payload_slot_initialization_refusal_preserves_partial_custody() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let (mut value, mut session, mut pending) = destination();
        // SAFETY: the test owns the destination and pairs it with its initial
        // session; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut session) };
        assert_eq!(
            step(&document, &mut slot, &mut pending, &mut policy).unwrap(),
            Built::Progress,
            "the session binds the root"
        );
        policy.turn();
        assert_eq!(
            step(&document, &mut slot, &mut pending, &mut policy).unwrap(),
            Built::Progress,
        );
        let before = slot.custody().observe();
        let live = policy.live_bytes();
        let used = policy.used();
        let attempt = policy.attempts();
        let refusals = policy.scheduled_refusals();
        policy.turn();
        policy.refuse_next();
        let result = step(&document, &mut slot, &mut pending, &mut policy);
        assert!(
            matches!(
                &result,
                Err(DecodeError::Resource(BoundedError::Refused(
                    LimitRefusal::Scheduled(index)
                ))) if *index == attempt
            ),
            "payload-slot initialization: {result:?}"
        );
        assert_eq!(policy.attempts(), attempt + 1);
        assert_eq!(policy.scheduled_refusals(), refusals + 1);
        assert_eq!(policy.used(), used);
        assert_eq!(slot.custody().observe(), before);
        assert_eq!(policy.live_bytes(), live);
        policy.turn();
        assert_eq!(
            step(&document, &mut slot, &mut pending, &mut policy).unwrap(),
            Built::Progress,
        );
        assert_eq!(slot.custody().inner.phase, Phase::Empty);
        assert_eq!(policy.attempts(), attempt + 2);
        assert_eq!(policy.scheduled_refusals(), refusals + 1);
        assert_eq!(
            policy.used(),
            used.checked_then(WriteWork::new(1, size_of::<Option<Reservation>>() as u64))
                .unwrap()
        );
        assert_eq!(policy.live_bytes(), live);
        // Cleanup begins in its own unit, then marks the empty container
        // freed; the releases were prepaid.
        for _ in 0..2 {
            policy.turn();
            assert_eq!(
                reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy))
                    .unwrap(),
                Reclaimed::Progress,
            );
        }
        policy.exhaust();
        assert_eq!(
            reclaim::<Vec<u8>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut policy)).unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.live_bytes(), 0);
    }
}
