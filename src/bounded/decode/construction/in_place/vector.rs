//! Stable sequence elements with retained per-element cleanup records.
//!
//! Vectors and fixed-size arrays both decode a CBOR array and share one element
//! engine: a vector's elements live in an admitted payload allocation, an
//! array's in the destination itself, which must declare exactly `N` elements,
//! as `[T; N]` encodes.
extern crate alloc;
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Peek, Place};
use crate::bounded::decode::construction::stable::{self, Installed, Stack};
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

/// One element's custody record: its state, and whether it entered the
/// initialized prefix.
struct Element<E> {
    state: E,
    committed: bool,
}

/// What the metadata block's acquisition writes, whole: the element records
/// and the length of the initialized prefix.
struct Head<E, P> {
    children: Stack<Element<E>, P>,
    /// Elements in the initialized prefix.
    committed: usize,
}

struct Meta<E, P> {
    head: Head<E, P>,
    // Written in its own admitted unit. An allowed 16-byte permit can make
    // Option<P> 32 bytes, so the complete metadata need not fit one quantum.
    payload: MaybeUninit<Option<P>>,
}

/// Acquisition writes the header, whole, and the allocation permit. The
/// payload slot has no initialized bytes until `Initializing` advances.
const fn metadata<E, P>() -> stable::Metadata {
    stable::Metadata::header::<Head<E, P>, Meta<E, P>, P>()
}

/// The construction state of a sequence whose elements' states are `E`, with
/// permits of `P`: its metadata, once installed; what that installation has
/// admitted; its phase; and the document index of the next element, once the
/// array's header is read. Only the sequence engine reads or changes it.
pub struct State<E, P> {
    meta: Option<Installed<Meta<E, P>, P>>,
    admitted: stable::Admitted,
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
        admitted: stable::Admitted::Nothing,
        phase: Phase::Initializing,
        position: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// element records (each an `E`), the payload permit and plain counters, as
// the auto traits would derive through `Installed` and `Stack`; stated once
// here so a nested sequence's proof is one obligation per level.
unsafe impl<E: Send, P: Send> Send for State<E, P> {}

/// What a sequence's construction holds: no metadata block, with the
/// admissions held toward it; or the block, holding the element records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SequenceObservation<E> {
    Unallocated(Admitted),
    Held(SequenceCustody<E>),
}

/// A sequence's custody once its metadata is held, `E` an element's
/// observation: the phase; the document index of the next element; the
/// elements in the initialized prefix; the element records held and the
/// admissions held toward the next; whether the payload's permit is held;
/// and the newest record, the element under construction or cleanup
/// whenever one is, whole. Every record before the newest holds a committed
/// element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SequenceCustody<E> {
    pub phase: Phase,
    pub position: usize,
    pub committed: usize,
    pub records: usize,
    pub admitted: Admitted,
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
            return SequenceObservation::Unallocated(self.admitted);
        };
        let meta = installed.get();
        SequenceObservation::Held(SequenceCustody {
            phase: self.phase,
            position: self.position,
            committed: meta.head.committed,
            records: meta.head.children.len(),
            admitted: meta.head.children.admitted(),
            // SAFETY: every phase after Initializing has written the slot;
            // short-circuiting keeps observation from reading it before then.
            payload: self.phase != Phase::Initializing
                && unsafe { meta.payload.assume_init_ref() }.is_some(),
            newest: meta.head.children.top().map(|child| ElementObservation {
                committed: child.state.committed,
                element: child.state.state.observe(),
            }),
        })
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
/// costs compose as children ([`ConstructionCost::children`]).
const fn sequence_cost<T, Q: Sequence<T>, E, P>(element: ConstructionCost) -> ConstructionCost {
    let meta = size_of::<stable::Held<Meta<E, P>, P>>();
    let child = stable::Metadata::whole::<stable::Child<Element<E>, P>, P>().bytes();
    let release = stable::release_cost::<P>();
    let storage = if Q::INLINE { 0 } else { size_of::<T>() };
    let payload = if Q::INLINE {
        ConstructionCost::ZERO.fixed
    } else {
        plus(STEP_COST, release)
    };
    let build = plus(
        plus(
            plus(
                stable::acquire_cost(metadata::<E, P>()),
                sized::<Option<P>>().bound(),
            ),
            Q::HEADER.bound(),
        ),
        plus(payload, STEP_COST),
    );
    // The transition, the container's release and the metadata's.
    let cleanup = plus(plus(STEP_COST, Q::RELEASE.bound()), release);
    let each = plus(
        plus(
            plus(
                stable::install_cost::<stable::Child<Element<E>, P>, P>(),
                STEP_COST,
            ),
            release,
        ),
        plus(held(child), held(storage)),
    );
    ConstructionCost::fixed(plus(plus(build, cleanup), held(meta)))
        .plus(ConstructionCost::per_byte(each))
        .plus(element.children())
}

/// One admitted construction unit of sequence `Q` in `slot` from the array
/// at `index`. Without metadata the state is `INITIAL` (every cleanup that
/// releases the metadata restores it), so construction begins; any phase
/// past construction is refused.
fn build<T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    mut slot: Slot<'_, Q, State<T::State, A::Permit>>,
    a: &mut A,
) -> ConstructResult<Built, A> {
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
                &mut state.meta,
                &mut state.admitted,
                || Head {
                    children: Stack::new(),
                    committed: 0,
                },
                |meta| ptr::addr_of_mut!((*meta).head),
                a,
            )?
        };
        return Ok(Built::Progress);
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
        return Ok(Built::Progress);
    }
    if state.phase == Phase::Empty {
        Q::HEADER.admit(a)?;
        let Some(Kind::Array(count)) = node_at(document, index).map(|n| n.kind()) else {
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
        return Ok(Built::Progress);
    }
    let Some(Kind::Array(count)) = node_at(document, index).map(|n| n.kind()) else {
        return Err(wrong_type());
    };
    let count = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
    match state.phase {
        Phase::Initialized => {
            STEP.admit(a)?;
            state.phase = Phase::ReleasePayload;
        }
        Phase::ReleasePayload => {
            stable::admit_release(a)?;
            state.phase = Phase::AllocatePayload;
        }
        Phase::AllocatePayload => {
            // SAFETY: every phase after Initializing has written the slot.
            if unsafe { meta.payload.assume_init_ref() }.is_some() {
                // A permit is already held: a step after a failed
                // reservation, refused rather than leaking the permit.
                return Err(BoundedError::PlanMismatch.into());
            }
            let bytes = count
                .checked_mul(size_of::<T>())
                .ok_or(BoundedError::Overflow)?;
            let bytes = u64::try_from(bytes).map_err(|_| BoundedError::Overflow)?;
            meta.payload
                .write(Some(a.allocate(bytes).map_err(BoundedError::Refused)?));
            // SAFETY: the container is initialized and empty.
            if !unsafe { Q::reserve(place, state, count) } {
                return Err(BoundedError::Allocation { bytes }.into());
            }
            state.phase = Phase::Next;
        }
        Phase::Next => {
            if meta.head.committed == count {
                STEP.admit(a)?;
                state.phase = Phase::Complete;
                return Ok(Built::Done);
            }
            meta.head.children.push(
                Element {
                    state: T::INITIAL,
                    committed: false,
                },
                a,
            )?;
            state.phase = Phase::Child;
        }
        Phase::Child => {
            let (elements, capacity) = elements.ok_or(BoundedError::PlanMismatch)?;
            // The element's slot lies within the storage reserved: a count
            // read at a later step that would pass it is refused here, before
            // any place outside the storage exists.
            if meta.head.committed >= capacity {
                return Err(BoundedError::PlanMismatch.into());
            }
            let child = meta.head.children.top().ok_or(BoundedError::PlanMismatch)?;
            // SAFETY: `committed` is below the storage's capacity; reserved
            // storage cannot move during child construction, and the child's
            // record holds the state of exactly this slot.
            let destination =
                unsafe { Slot::new(elements.add(meta.head.committed), &mut child.state.state) };
            if T::build_step(document, state.position, destination, a)? == Built::Done {
                state.phase = Phase::Commit;
            }
        }
        Phase::Commit => {
            STEP.admit(a)?;
            let node = node_at(document, state.position).ok_or_else(wrong_type)?;
            state.position = super::super::next_index(node);
            let child = meta.head.children.top().ok_or(BoundedError::PlanMismatch)?;
            child.state.committed = true;
            meta.head.committed += 1;
            let committed = meta.head.committed;
            // SAFETY: the child returned Done at slot `committed - 1`.
            unsafe { Q::set_len(place, state, committed) };
            state.phase = Phase::Next;
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// One admitted cleanup unit of sequence `Q` in `slot`, following the
/// retained child records in reverse order. Partial children never enter the
/// committed prefix; committed elements leave it only after their own cleanup
/// returns Done, and the container is released empty. Every path that
/// releases the metadata leaves the state `INITIAL`, so a later step reports
/// `Done` and a later build begins anew.
fn reclaim<T: Reclaim<A>, Q: Sequence<T>, A: Allocator>(
    mut slot: Slot<'_, Q, State<T::State, A::Permit>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
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
            state.phase = Phase::Reclaim;
        }
        Phase::Reclaim => {
            let elements = elements.ok_or(BoundedError::PlanMismatch)?;
            let Some(child) = meta.head.children.top() else {
                if meta.head.committed != 0 {
                    return Err(BoundedError::PlanMismatch);
                }
                Q::RELEASE.admit(a)?;
                // SAFETY: entering Reclaim proves the container is initialized,
                // and no element remains.
                unsafe { Q::release(place, state) };
                state.phase = Phase::BufferFreed;
                return Ok(Reclaimed::Progress);
            };
            let committed = child.state.committed;
            let slot = if committed {
                meta.head
                    .committed
                    .checked_sub(1)
                    .ok_or(BoundedError::PlanMismatch)?
            } else {
                meta.head.committed
            };
            // SAFETY: a partial slot was reserved before its record was pushed;
            // committed slots lie inside the prefix; the record holds the
            // state of exactly this slot.
            let destination = unsafe { Slot::new(elements.add(slot), &mut child.state.state) };
            if T::reclaim_step(destination, a)? == Reclaimed::Done {
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

/// The calls [`reclaim`] still takes from `slot`'s state: no metadata or only
/// the block, one; nothing written, two; written, one to enter `Reclaim`,
/// then every element record's own calls, the container's release and the
/// metadata's; in `Reclaim`, the latter three; freed, one.
fn remaining<T: Reclaim<A>, Q: Sequence<T>, A: Allocator>(
    mut slot: PeekSlot<'_, Q, State<T::State, A::Permit>>,
) -> u64 {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        return 1;
    }
    // Without an initialized container no element record exists.
    match state.phase {
        Phase::Initializing | Phase::BufferFreed => return 1,
        Phase::Empty => return 2,
        _ => {}
    }
    // Element 0's place, observed under the sequence's custody before its
    // metadata is borrowed.
    // SAFETY: every remaining phase follows the container's initialization.
    let elements = unsafe { Q::peek_elements(place, &*state) };
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    let meta = installed.get();
    let mut drain = 0u64;
    // The records are pushed one per element in slot order, so the record
    // `records - 1 - n`, visited `n`th newest first, holds slot
    // `records - 1 - n`.
    let mut slot = meta.head.children.len();
    meta.head.children.for_each(|child| {
        slot -= 1;
        // SAFETY: every recorded slot was reserved, in an initialized
        // container, before its record was pushed; the record's state
        // describes that slot.
        let destination = unsafe { Slot::new(elements.add(slot), &mut child.state) };
        drain = drain.saturating_add(T::remaining(destination));
    });
    // Each record's own calls, then the container's release and the metadata's.
    let reclaiming = drain.saturating_add(2);
    if state.phase == Phase::Reclaim {
        reclaiming
    } else {
        reclaiming.saturating_add(1)
    }
}

// SAFETY: the shared engine initializes the header and each spare-capacity
// child in final storage; a child record is pushed before its element acquires
// anything and describes that element until reclamation, including partials.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for Vec<T> {
    const COST: ConstructionCost = sequence_cost::<T, Self, T::State, A::Permit>(T::COST);

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        build::<T, Self, A>(document, index, slot, a)
    }
}

// SAFETY: the shared engine reclaims every recorded child, then the buffer.
unsafe impl<T: Reclaim<A>, A: Allocator> Reclaim<A> for Vec<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = State<T::State, A::Permit>;
    const INITIAL: Self::State = State::INITIAL;

    fn reclaim_step(slot: Slot<'_, Self, Self::State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim::<T, Self, A>(slot, a)
    }

    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        remaining::<T, Self, A>(slot)
    }
}

// SAFETY: as for Vec, with each element built in the destination's own slot.
unsafe impl<T: InPlace<A>, A: Allocator, const N: usize> InPlace<A> for [T; N] {
    const COST: ConstructionCost = sequence_cost::<T, Self, T::State, A::Permit>(T::COST);

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        build::<T, Self, A>(document, index, slot, a)
    }
}

// SAFETY: as for Vec; the array owns no storage of its own to release.
unsafe impl<T: Reclaim<A>, A: Allocator, const N: usize> Reclaim<A> for [T; N] {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = State<T::State, A::Permit>;
    const INITIAL: Self::State = State::INITIAL;

    fn reclaim_step(slot: Slot<'_, Self, Self::State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim::<T, Self, A>(slot, a)
    }

    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        remaining::<T, Self, A>(slot)
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
    fn layouts<E, P>() {
        let _ = const { metadata::<E, P>() };
        let _ = const { sized::<Option<P>>() };
        let _ = const { stable::Metadata::whole::<stable::Child<Element<State<E, P>>, P>, P>() };
    }

    #[test]
    fn metadata_and_nested_child_writes_fit_at_the_permit_boundary() {
        layouts::<Written, Reservation>();
        layouts::<BufferState<Reservation>, Reservation>();
        layouts::<State<BufferState<Reservation>, Reservation>, Reservation>();
        layouts::<Written, [u8; 16]>();
        layouts::<Written, u128>();
        layouts::<State<Written, u128>, u128>();
        let cost = const { sequence_cost::<u8, Vec<u8>, Written, u128>(ConstructionCost::ZERO) };
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
        let vector = sequence_cost::<u64, Vec<u64>, Written, Reservation>(element);
        let array = sequence_cost::<u64, [u64; 3], Written, Reservation>(element);
        assert_eq!(vector, <Vec<u64> as InPlace<Limits>>::COST);
        assert_eq!(array, <[u64; 3] as InPlace<Limits>>::COST);
        assert_eq!(
            metadata::<Written, Reservation>().bytes(),
            const { metadata::<Written, Reservation>() }.bytes()
        );
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

    #[test]
    fn unwritten_payload_slot_is_observable_and_reclaimed_without_reading_it() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let mut value = MaybeUninit::<Vec<u8>>::uninit();
        let mut state = <Vec<u8> as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its initial
        // state; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
        assert_eq!(
            build::<u8, Vec<u8>, Limits>(&document, 0, slot.reborrow(), &mut policy).unwrap(),
            Built::Progress,
        );
        assert_eq!(
            slot.custody().observe(),
            SequenceObservation::Held(SequenceCustody {
                phase: Phase::Initializing,
                position: 0,
                committed: 0,
                records: 0,
                admitted: Admitted::Nothing,
                payload: false,
                newest: None,
            })
        );
        let attempts = policy.attempts();
        policy.exhaust();
        assert_eq!(
            reclaim::<u8, Vec<u8>, Limits>(slot.reborrow(), &mut policy).unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.attempts(), attempts, "release was prepaid");
        assert_eq!(policy.live_bytes(), 0);
        assert_eq!(
            slot.custody().observe(),
            SequenceObservation::Unallocated(Admitted::Nothing)
        );
    }

    /// A sequence reclaimed to `Done` is `INITIAL` again: a further cleanup
    /// step reports `Done` and touches nothing, and a further build begins
    /// anew instead of reading metadata slots it never wrote.
    #[test]
    fn a_reclaimed_sequence_is_initial_for_every_later_call() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::unlimited();
        let mut value = MaybeUninit::<Vec<u8>>::uninit();
        let mut state = <Vec<u8> as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its initial
        // state; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
        for _ in 0..2 {
            crate::bounded::within_steps("an empty vector's construction", 16, || {
                match build::<u8, Vec<u8>, Limits>(&document, 0, slot.reborrow(), &mut policy)
                    .unwrap()
                {
                    Built::Done => core::ops::ControlFlow::Break(()),
                    Built::Progress => core::ops::ControlFlow::Continue(()),
                }
            });
            crate::bounded::within_steps("an empty vector's cleanup", 16, || {
                match reclaim::<u8, Vec<u8>, Limits>(slot.reborrow(), &mut policy).unwrap() {
                    Reclaimed::Done => core::ops::ControlFlow::Break(()),
                    _ => core::ops::ControlFlow::Continue(()),
                }
            });
            assert_eq!(slot.custody().phase, Phase::Initializing);
            assert_eq!(
                slot.custody().observe(),
                SequenceObservation::Unallocated(Admitted::Nothing)
            );
            assert_eq!(
                reclaim::<u8, Vec<u8>, Limits>(slot.reborrow(), &mut policy).unwrap(),
                Reclaimed::Done,
                "a step after Done"
            );
            assert_eq!(policy.live_bytes(), 0);
        }
    }

    #[test]
    fn payload_slot_initialization_refusal_preserves_partial_custody() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let mut value = MaybeUninit::<Vec<u8>>::uninit();
        let mut state = <Vec<u8> as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its initial
        // state; every access to either is through this slot for the test.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
        assert_eq!(
            build::<u8, Vec<u8>, Limits>(&document, 0, slot.reborrow(), &mut policy).unwrap(),
            Built::Progress,
        );
        let before = slot.custody().observe();
        let live = policy.live_bytes();
        let used = policy.used();
        let attempt = policy.attempts();
        let refusals = policy.scheduled_refusals();
        policy.turn();
        policy.refuse_next();
        let result = build::<u8, Vec<u8>, Limits>(&document, 0, slot.reborrow(), &mut policy);
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
            build::<u8, Vec<u8>, Limits>(&document, 0, slot.reborrow(), &mut policy).unwrap(),
            Built::Progress,
        );
        assert_eq!(slot.custody().phase, Phase::Empty);
        assert_eq!(policy.attempts(), attempt + 2);
        assert_eq!(policy.scheduled_refusals(), refusals + 1);
        assert_eq!(
            policy.used(),
            used.then::<()>(WriteWork::new(1, size_of::<Option<Reservation>>() as u64))
                .unwrap()
        );
        assert_eq!(policy.live_bytes(), live);
        policy.turn();
        assert_eq!(
            reclaim::<u8, Vec<u8>, Limits>(slot.reborrow(), &mut policy).unwrap(),
            Reclaimed::Progress,
        );
        policy.exhaust();
        assert_eq!(
            reclaim::<u8, Vec<u8>, Limits>(slot.reborrow(), &mut policy).unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.live_bytes(), 0);
    }
}
