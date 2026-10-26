//! Stable sequence elements with retained per-element cleanup records.
//!
//! Vectors and fixed-size arrays both decode a CBOR array and share one element
//! engine: a vector's elements live in an admitted payload allocation, an
//! array's in the destination itself, which must declare exactly `N` elements,
//! as `[T; N]` encodes.
extern crate alloc;
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody};
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

struct Meta<E, P> {
    children: Stack<Element<E>, P>,
    // Written in its own admitted unit. An allowed 16-byte permit can make
    // Option<P> 32 bytes, so the complete metadata need not fit one quantum.
    payload: MaybeUninit<Option<P>>,
    /// Elements in the initialized prefix.
    committed: usize,
}

/// Acquisition writes the stack, committed count and allocation permit.
/// The payload slot has no initialized bytes until `Initializing` advances.
const fn metadata<E, P>() -> stable::Metadata {
    stable::Metadata::new::<Meta<E, P>, P>(
        size_of::<Stack<Element<E>, P>>()
            + size_of::<usize>()
            + crate::bounded::permit_bytes::<P>(),
    )
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
            committed: meta.committed,
            records: meta.children.len(),
            admitted: meta.children.admitted(),
            // SAFETY: every phase after Initializing has written the slot;
            // short-circuiting keeps observation from reading it before then.
            payload: self.phase != Phase::Initializing
                && unsafe { meta.payload.assume_init_ref() }.is_some(),
            newest: meta.children.top().map(|child| ElementObservation {
                committed: child.state.committed,
                element: child.state.state.observe(),
            }),
        })
    }
}

/// Where a sequence keeps its elements.
///
/// # Safety
/// After `initialize`, and `reserve` of `count` elements when not `INLINE`,
/// `slot(place, i)` is stable storage of element `i` for every `i` below
/// `count`, owned only by this sequence. `set_len` records the committed
/// prefix without running a destructor. `release` frees only the container's
/// own storage, and only once its committed prefix is empty.
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
    /// `place` is uninitialized and unique.
    unsafe fn initialize(place: NonNull<MaybeUninit<Self>>);
    /// Physically reserve `count` elements; false on allocation failure.
    ///
    /// # Safety
    /// The container is initialized and empty.
    unsafe fn reserve(place: NonNull<MaybeUninit<Self>>, count: usize) -> bool;
    /// # Safety
    /// As the trait contract, for `index` below the reserved count.
    unsafe fn slot(place: NonNull<MaybeUninit<Self>>, index: usize) -> NonNull<MaybeUninit<T>>;
    /// # Safety
    /// Exactly the first `len` elements are initialized.
    unsafe fn set_len(place: NonNull<MaybeUninit<Self>>, len: usize);
    /// # Safety
    /// The container is initialized and its committed prefix is empty.
    unsafe fn release(place: NonNull<MaybeUninit<Self>>);
}

// SAFETY: elements live in the reserved spare capacity, which cannot move while
// construction holds the only reference; release drops an empty Vec, freeing
// only its buffer.
unsafe impl<T> Sequence<T> for Vec<T> {
    const INLINE: bool = false;
    const HEADER: Unit<Caller> = sized::<Vec<T>>();
    const RELEASE: Unit<Caller> = sized::<Vec<T>>();

    fn accepts(_: usize) -> bool {
        true
    }

    unsafe fn initialize(place: NonNull<MaybeUninit<Self>>) {
        // SAFETY: forwarded from the caller.
        unsafe { place.as_ptr().write(MaybeUninit::new(Vec::new())) };
    }

    unsafe fn reserve(place: NonNull<MaybeUninit<Self>>, count: usize) -> bool {
        // SAFETY: forwarded from the caller.
        unsafe { (*place.as_ptr().cast::<Vec<T>>()).try_reserve_exact(count) }.is_ok()
    }

    unsafe fn slot(place: NonNull<MaybeUninit<Self>>, index: usize) -> NonNull<MaybeUninit<T>> {
        // SAFETY: `index` is within the reserved capacity.
        unsafe {
            NonNull::new_unchecked(
                (*place.as_ptr().cast::<Vec<T>>())
                    .as_mut_ptr()
                    .add(index)
                    .cast::<MaybeUninit<T>>(),
            )
        }
    }

    unsafe fn set_len(place: NonNull<MaybeUninit<Self>>, len: usize) {
        // SAFETY: forwarded from the caller.
        unsafe { (*place.as_ptr().cast::<Vec<T>>()).set_len(len) };
    }

    unsafe fn release(place: NonNull<MaybeUninit<Self>>) {
        // SAFETY: no live elements remain; only the backing buffer is freed.
        // Its payload reservation is released by the following phase.
        unsafe { ptr::drop_in_place(place.as_ptr().cast::<Vec<T>>()) };
    }
}

// SAFETY: element `i` is the destination's own `i`th slot; the array has no
// header or buffer, and its committed prefix is recorded in the metadata.
unsafe impl<T, const N: usize> Sequence<T> for [T; N] {
    const INLINE: bool = true;
    const HEADER: Unit<Caller> = STEP;
    const RELEASE: Unit<Caller> = STEP;

    fn accepts(count: usize) -> bool {
        count == N
    }

    unsafe fn initialize(_: NonNull<MaybeUninit<Self>>) {}

    unsafe fn reserve(_: NonNull<MaybeUninit<Self>>, _: usize) -> bool {
        // Inline storage is the destination itself.
        true
    }

    unsafe fn slot(place: NonNull<MaybeUninit<Self>>, index: usize) -> NonNull<MaybeUninit<T>> {
        // SAFETY: `index` is below N, within the destination.
        unsafe { NonNull::new_unchecked(place.as_ptr().cast::<MaybeUninit<T>>().add(index)) }
    }

    unsafe fn set_len(_: NonNull<MaybeUninit<Self>>, _: usize) {}

    unsafe fn release(_: NonNull<MaybeUninit<Self>>) {}
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

/// One admitted construction unit of sequence `Q` from the array at `index`.
///
/// # Safety
/// As [`InPlace::build_step`].
unsafe fn build<T: InPlace<A>, Q: Sequence<T>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<Q>>,
    state: &mut State<T::State, A::Permit>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: the stack and count are initialized; MaybeUninit permits
        // the payload slot to remain unwritten until the next phase.
        unsafe {
            stable::install::<Meta<T::State, A::Permit>, A>(
                &mut state.meta,
                &mut state.admitted,
                const { metadata::<T::State, A::Permit>() },
                |meta| {
                    ptr::addr_of_mut!((*meta).children).write(Stack::new());
                    ptr::addr_of_mut!((*meta).committed).write(0);
                },
                a,
            )?
        };
        return Ok(Built::Progress);
    };
    let meta = installed.get();
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
        unsafe { Q::initialize(place) };
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
            let bytes = count
                .checked_mul(size_of::<T>())
                .ok_or(BoundedError::Overflow)?;
            let bytes = u64::try_from(bytes).map_err(|_| BoundedError::Overflow)?;
            meta.payload
                .write(Some(a.allocate(bytes).map_err(BoundedError::Refused)?));
            // SAFETY: the container is initialized and empty.
            if !unsafe { Q::reserve(place, count) } {
                return Err(BoundedError::Allocation { bytes }.into());
            }
            state.phase = Phase::Next;
        }
        Phase::Next => {
            if meta.committed == count {
                STEP.admit(a)?;
                state.phase = Phase::Complete;
                return Ok(Built::Done);
            }
            meta.children.push(
                Element {
                    state: T::INITIAL,
                    committed: false,
                },
                a,
            )?;
            state.phase = Phase::Child;
        }
        Phase::Child => {
            let child = meta.children.top().ok_or(BoundedError::PlanMismatch)?;
            // SAFETY: `committed` is below `count`; reserved storage cannot
            // move during child construction.
            let destination = unsafe { Q::slot(place, meta.committed) };
            if unsafe {
                T::build_step(
                    document,
                    state.position,
                    destination,
                    &mut child.state.state,
                    a,
                )?
            } == Built::Done
            {
                state.phase = Phase::Commit;
            }
        }
        Phase::Commit => {
            STEP.admit(a)?;
            let node = node_at(document, state.position).ok_or_else(wrong_type)?;
            state.position = super::super::next_index(node);
            let child = meta.children.top().ok_or(BoundedError::PlanMismatch)?;
            meta.committed += 1;
            // SAFETY: the child returned Done at slot `committed - 1`.
            unsafe { Q::set_len(place, meta.committed) };
            child.state.committed = true;
            state.phase = Phase::Next;
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// One admitted cleanup unit of sequence `Q`, following the retained child
/// records in reverse order. Partial children never enter the committed
/// prefix; committed elements leave it only after their own cleanup returns
/// Done, and the container is released empty.
///
/// # Safety
/// As [`Reclaim::reclaim_step`].
unsafe fn reclaim<T: Reclaim<A>, Q: Sequence<T>, A: Allocator>(
    place: NonNull<MaybeUninit<Q>>,
    state: &mut State<T::State, A::Permit>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        state.position = 0;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
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
            let Some(child) = meta.children.top() else {
                if meta.committed != 0 {
                    return Err(BoundedError::PlanMismatch);
                }
                Q::RELEASE.admit(a)?;
                // SAFETY: entering Reclaim proves the container is initialized,
                // and no element remains.
                unsafe { Q::release(place) };
                state.phase = Phase::BufferFreed;
                return Ok(Reclaimed::Progress);
            };
            let committed = child.state.committed;
            let slot = if committed {
                meta.committed
                    .checked_sub(1)
                    .ok_or(BoundedError::PlanMismatch)?
            } else {
                meta.committed
            };
            // SAFETY: a partial slot was reserved before its record was pushed;
            // committed slots lie inside the prefix.
            let destination = unsafe { Q::slot(place, slot) };
            if unsafe { T::reclaim_step(destination, &mut child.state.state, a)? }
                == Reclaimed::Done
            {
                // The element is reclaimed completely: its record is freed in
                // the same step, a release its push paid for.
                meta.children.pop();
                if committed {
                    meta.committed = slot;
                    // SAFETY: the reclaimed element leaves the prefix without
                    // running a destructor.
                    unsafe { Q::set_len(place, meta.committed) };
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
            return Ok(Reclaimed::Done);
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from `state`: no metadata or only the
/// block, one; nothing written, two; written, one to enter `Reclaim`, then
/// every element record's own calls, the container's release and the
/// metadata's; in `Reclaim`, the latter three; freed, one.
///
/// # Safety
/// As [`Reclaim::remaining`].
unsafe fn remaining<T: Reclaim<A>, Q: Sequence<T>, A: Allocator>(
    place: NonNull<MaybeUninit<Q>>,
    state: &mut State<T::State, A::Permit>,
) -> u64 {
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    let meta = installed.get();
    let mut drain = 0u64;
    // The records are pushed one per element in slot order, so the record
    // `records - 1 - n`, visited `n`th newest first, holds slot
    // `records - 1 - n`.
    let mut slot = meta.children.len();
    meta.children.for_each(|child| {
        slot -= 1;
        // SAFETY: every recorded slot was reserved before its record was
        // pushed; the record's state describes that slot.
        let destination = unsafe { Q::slot(place, slot) };
        drain = drain.saturating_add(unsafe { T::remaining(destination, &mut child.state) });
    });
    // Each record's own calls, then the container's release and the metadata's.
    let reclaiming = drain.saturating_add(2);
    match state.phase {
        Phase::Initializing | Phase::BufferFreed => 1,
        Phase::Empty => 2,
        Phase::Initialized
        | Phase::ReleasePayload
        | Phase::AllocatePayload
        | Phase::Next
        | Phase::Child
        | Phase::Commit
        | Phase::Complete => reclaiming.saturating_add(1),
        Phase::Reclaim => reclaiming,
    }
}

// SAFETY: the shared engine initializes the header and each spare-capacity
// child in final storage; a child record is pushed before its element acquires
// anything and describes that element until reclamation, including partials.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for Vec<T> {
    const COST: ConstructionCost = sequence_cost::<T, Self, T::State, A::Permit>(T::COST);

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        // SAFETY: forwarded from the caller.
        unsafe { build::<T, Self, A>(document, index, place, state, a) }
    }
}

// SAFETY: the shared engine reclaims every recorded child, then the buffer.
unsafe impl<T: Reclaim<A>, A: Allocator> Reclaim<A> for Vec<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = State<T::State, A::Permit>;
    const INITIAL: Self::State = State::INITIAL;

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: forwarded from the caller.
        unsafe { reclaim::<T, Self, A>(place, state, a) }
    }

    unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        // SAFETY: forwarded from the caller.
        unsafe { remaining::<T, Self, A>(place, state) }
    }
}

// SAFETY: as for Vec, with each element built in the destination's own slot.
unsafe impl<T: InPlace<A>, A: Allocator, const N: usize> InPlace<A> for [T; N] {
    const COST: ConstructionCost = sequence_cost::<T, Self, T::State, A::Permit>(T::COST);

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        // SAFETY: forwarded from the caller.
        unsafe { build::<T, Self, A>(document, index, place, state, a) }
    }
}

// SAFETY: as for Vec; the array owns no storage of its own to release.
unsafe impl<T: Reclaim<A>, A: Allocator, const N: usize> Reclaim<A> for [T; N] {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(1);
    type State = State<T::State, A::Permit>;
    const INITIAL: Self::State = State::INITIAL;

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: forwarded from the caller.
        unsafe { reclaim::<T, Self, A>(place, state, a) }
    }

    unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        // SAFETY: forwarded from the caller.
        unsafe { remaining::<T, Self, A>(place, state) }
    }
}

#[cfg(all(test, feature = "std"))]
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

    #[test]
    fn unwritten_payload_slot_is_observable_and_reclaimed_without_reading_it() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let mut place = MaybeUninit::<Vec<u8>>::uninit();
        let place = NonNull::from(&mut place);
        let mut state = <Vec<u8> as Reclaim<Limits>>::INITIAL;
        assert_eq!(
            unsafe { build::<u8, Vec<u8>, Limits>(&document, 0, place, &mut state, &mut policy) }
                .unwrap(),
            Built::Progress,
        );
        assert_eq!(
            state.observe(),
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
            unsafe { reclaim::<u8, Vec<u8>, Limits>(place, &mut state, &mut policy) }.unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.attempts(), attempts, "release was prepaid");
        assert_eq!(policy.live_bytes(), 0);
        assert_eq!(
            state.observe(),
            SequenceObservation::Unallocated(Admitted::Nothing)
        );
    }

    #[test]
    fn payload_slot_initialization_refusal_preserves_partial_custody() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x80], 1, &mut parser).unwrap();
        let mut policy = Limits::turns();
        let mut place = MaybeUninit::<Vec<u8>>::uninit();
        let place = NonNull::from(&mut place);
        let mut state = <Vec<u8> as Reclaim<Limits>>::INITIAL;
        assert_eq!(
            unsafe { build::<u8, Vec<u8>, Limits>(&document, 0, place, &mut state, &mut policy) }
                .unwrap(),
            Built::Progress,
        );
        let before = state.observe();
        let live = policy.live_bytes();
        let used = policy.used();
        let attempt = policy.attempts();
        let refusals = policy.scheduled_refusals();
        policy.turn();
        policy.refuse_next();
        let result =
            unsafe { build::<u8, Vec<u8>, Limits>(&document, 0, place, &mut state, &mut policy) };
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
        assert_eq!(state.observe(), before);
        assert_eq!(policy.live_bytes(), live);
        policy.turn();
        assert_eq!(
            unsafe { build::<u8, Vec<u8>, Limits>(&document, 0, place, &mut state, &mut policy) }
                .unwrap(),
            Built::Progress,
        );
        assert_eq!(state.phase, Phase::Empty);
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
            unsafe { reclaim::<u8, Vec<u8>, Limits>(place, &mut state, &mut policy) }.unwrap(),
            Reclaimed::Progress,
        );
        policy.exhaust();
        assert_eq!(
            unsafe { reclaim::<u8, Vec<u8>, Limits>(place, &mut state, &mut policy) }.unwrap(),
            Reclaimed::Done,
        );
        assert_eq!(policy.live_bytes(), 0);
    }
}
