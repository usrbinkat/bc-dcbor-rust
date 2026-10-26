//! Stable allocations with intrusive, explicitly stepped reclamation.
//!
//! This owner never calls a value's `Drop`. Implementations explicitly reclaim
//! initialized subobjects, including partial construction, before returning Done.
//!
//! Retirement is a wait-free push onto an intrusive multi-producer queue: one
//! swap of the tail, then one store of the predecessor's link. Only the owner's
//! `step` removes records, and a stepping flag admits one caller at a time.
//! The borrowed [`Reclaimer`] erases its payload types, so it stays confined to
//! one thread; the owned scope re-exposes the same queue across threads only for
//! payloads its allocation path has proven `Send`.
use core::marker::{PhantomData, PhantomPinned};
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use super::operation::OperationPlace;
use super::stable::{self, Held};
use crate::bounded::{Allocator, BoundedError, BoundedResult, at};

mod owned;
/// Admissions held toward a block, as custody observations report them.
pub use super::stable::Admitted;
pub use owned::{
    Acquisition, DecodeOwner, OwnedInitialized, OwnedRecord, ScopePosition, scope_bound,
};
pub(crate) use owned::{EMPTIED, ScopeRef, slot_place};
#[cfg(all(test, feature = "std"))]
pub(crate) use owned::{ScopePlace, ScopeTerms};

/// What one cleanup step reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaimed {
    /// A cleanup unit was admitted and performed; more remain.
    Progress,
    /// Nothing can be advanced now: no record is queued while handles still
    /// hold records, a retiring thread has published its record but not yet
    /// linked it, or another caller is stepping the same queue. No unit was
    /// performed; an admission already granted for the next removal is
    /// retained for the following call.
    Waiting,
    /// Every record this step drains has been released.
    Done,
}

/// Maximum declared synchronous dispatch depth of an admitted stable record.
/// This is independent of input depth and checked before allocating the record.
pub const MAX_DISPATCH_DEPTH: usize = 64;

/// The custody a construction state holds, observed: a projection of the
/// one typed state that construction and cleanup themselves read and
/// write, never a second record kept beside it.
///
/// An observation distinguishes every state that differs in what is
/// initialized, which allocations, blocks and permits are held, staged,
/// published or awaiting release, how many cleanup units remain, and what
/// the active child holds: a parent's observation embeds its active child's
/// whole observation. It holds counts and phases, never an address.
///
/// Observing requires the state's custody, which is exclusive: `observe`
/// takes `&mut self`, so no shared access to a state ever reads it, and a
/// state's `Sync` rests on shared access reaching nothing. Observing admits
/// nothing, allocates nothing, and changes neither the state nor the trace.
///
/// An observation says what a state holds; it does not say which states
/// are interchangeable for verification. That is a separate claim
/// ([`Reduction`]).
pub trait Custody {
    /// What the state holds, by phase and count.
    type Observation: Copy + Eq + Ord + core::fmt::Debug;

    fn observe(&mut self) -> Self::Observation;
}

/// A declared reduction of a state's observations for the property a
/// stopped schedule verifies: cleanup from that state. `class` maps
/// observations to classes such that, from two states of one class, each
/// next cleanup unit, admitted or refused, reaches the same outcome (done,
/// progress or refusal), releases or keeps custody alike, and leaves states
/// again of one class. A class relation with that property is a simulation
/// of cleanup, and by induction over the cleanup that follows, a stop at
/// one state of a class stands for a stop at every other: a cancellation, a
/// terminal error or a physical failure there leaves cleanup that the kept
/// stop exercises. Construction steps are not part of the relation: two
/// states of one class may build differently, and no schedule that builds
/// from a state is omitted on its class's account.
///
/// Nothing provides this by default: a state without it is never reduced,
/// and every stop over it runs. A state whose observation does not carry
/// what its cleanup depends on cannot implement it soundly: a container
/// observes its newest child whole but counts its older ones, whose custody
/// may differ, so containers implement none, and a binding over a child
/// implements it only over a child that does. An implementation states the
/// argument for its relation at its definition; the verification suites
/// check the relation against the states and cleanup transitions they
/// reach, and reject planted relations that merge states of different
/// custody.
pub trait Reduction: Custody {
    type Class: Copy + Eq + Ord + core::fmt::Debug;

    fn class(observation: &Self::Observation) -> Self::Class;
}

/// Whether a resource-free value has been written to its destination: the
/// whole state of a binding that acquires nothing. It carries no authority,
/// so it may be copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Written {
    Empty,
    Initialized,
}

impl Custody for Written {
    type Observation = Self;

    fn observe(&mut self) -> Self {
        *self
    }
}

// Two written states hold exactly what their observation says, and their
// one cleanup unit depends on nothing else: the identity is a simulation.
impl Reduction for Written {
    type Class = Self;

    fn class(observation: &Self) -> Self {
        *observation
    }
}

/// The state of a record an operation initializes in a fixed number of
/// units: how many units of its resource-free prefix are initialized. A
/// count, not an authority, so it may be copied; only the crate advances it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Prefix {
    initialized: usize,
}

impl Prefix {
    /// No unit initialized.
    pub const EMPTY: Self = Self { initialized: 0 };

    /// The initialized units.
    pub const fn initialized(&self) -> usize {
        self.initialized
    }

    /// Record the next unit as initialized.
    pub(crate) fn advance(&mut self) {
        self.initialized += 1;
    }

    /// Record exactly `units` as initialized, for a prefix whose nested part
    /// counts its own units.
    pub(crate) fn set(&mut self, units: usize) {
        self.initialized = units;
    }
}

/// The initialized units: each is a distinct field written, and cleanup
/// releases what the first holds, so the count is the whole custody.
impl Custody for Prefix {
    type Observation = Self;

    fn observe(&mut self) -> Self {
        *self
    }
}

// The count is the custody and fixes the cleanup that follows: identity.
impl Reduction for Prefix {
    type Class = Self;

    fn class(observation: &Self) -> Self {
        *observation
    }
}

/// Mandatory cleanup for a stable, possibly partially initialized allocation.
///
/// Construction and cleanup progress is retained in [`Self::State`], a value
/// of the implementation's own type held beside the destination for its
/// whole life: it starts as [`Self::INITIAL`], is threaded through every
/// construction and cleanup step, and is never copied by the engine. A state
/// that holds an allocation holds it as a typed handle
/// ([`stable::Installed`]), never as an integer: the handle exists exactly
/// while its block is live and owned by this state, so a state that names a
/// block always names one it may access and must release.
///
/// # Safety
/// [`Self::INITIAL`] must mean "nothing initialized, nothing acquired". The
/// state must record exactly what construction initialized and acquired, on
/// every return. Every unit must be admitted before work; refusal must
/// preserve that unit's state. Cleanup must not allocate, unwind, recursively
/// destroy a value, or invoke an arbitrary user destructor. `Done` promises
/// that no initialized subobject or owned child allocation remains and that
/// releasing the outer allocation without `Drop` is sound.
pub unsafe trait Reclaim<A: Allocator>: Sized {
    /// Upper bound on nested construction/reclamation dispatch, including self.
    /// Implementations delegating to children must add their own fixed dispatch
    /// overhead to the maximum child's bound, using saturating arithmetic.
    /// The default is valid only for leaf bindings with no child dispatch.
    /// Understating this bound violates the unsafe implementation contract.
    const DISPATCH_DEPTH: usize = 1;

    /// The progress construction and cleanup retain across suspension, and
    /// the custody it holds ([`Custody`]).
    type State: Custody;

    /// The state of a destination nothing has been done to. A constant, so
    /// producing it can neither allocate nor unwind.
    const INITIAL: Self::State;

    /// # Safety
    /// `place` is the original stable allocation and `state` describes its
    /// initialized parts. No references into those parts may remain live.
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        allocator: &mut A,
    ) -> BoundedResult<Reclaimed, A>;

    /// The most successful [`Self::reclaim_step`] calls cleanup from `state`
    /// can take, the one that returns `Done` included: at least one. A refused
    /// call is not counted; it changes nothing and is repeated. Read under the
    /// state's exclusive custody, admitting nothing and changing nothing, like
    /// an observation ([`Custody`]); arithmetic saturates, a saturated count
    /// still bounding the cleanup. The scope holds every queued record to the
    /// count its state declares when its cleanup begins, so a drain, stepped
    /// or terminal, is finite: a record that would take more calls is a
    /// defect. Overstating is sound; understating violates this trait's
    /// contract and fails the drain.
    ///
    /// # Safety
    /// As [`Self::reclaim_step`]: `place` is the original stable allocation
    /// paired with `state`, and no references into its parts are live.
    unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64;
}

/// One cleanup unit of the record inside `slot`'s handle: `unwrap` takes the
/// record out of the handle, `reclaim` steps it, and `wrap` restores the
/// handle while the record survives. Every owning handle's operation-local
/// cleanup is this one routine over its own record type.
pub(crate) fn reclaim_within<W, R, A: Allocator>(
    slot: &mut Option<W>,
    a: &mut A,
    unwrap: impl FnOnce(W) -> R,
    wrap: impl FnOnce(R) -> W,
    reclaim: impl FnOnce(&mut Option<R>, &mut A) -> BoundedResult<Reclaimed, A>,
) -> BoundedResult<Reclaimed, A> {
    let mut record = slot.take().map(unwrap);
    let result = reclaim(&mut record, a);
    *slot = record.map(wrap);
    result
}

type Advance<A> = unsafe fn(NonNull<Header<A>>, &mut A) -> BoundedResult<Reclaimed, A>;
type Finish<A> = unsafe fn(NonNull<Header<A>>, Ending) -> u64;

/// What a record's [`Finish`] entry does: report the cleanup calls its state
/// declares ([`Reclaim::remaining`]), or free the block of a record whose
/// cleanup is done. One entry for both keeps the header within the bytes a
/// record's metadata may write in one unit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Count,
    Free,
}

/// Who holds a record's block: its handle, the queue, or the stepping
/// caller's active slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Holder {
    Handle,
    Queued,
    Active,
}

#[repr(C)]
struct Header<A: Allocator> {
    /// Written by the retiring thread before publication and by the next
    /// retiring thread when it links behind this record.
    next: AtomicPtr<Header<A>>,
    advance: Advance<A>,
    finish: Finish<A>,
    /// Owned by the handle until publication, then by the stepping caller.
    custody: Holder,
    /// Stepping caller only, once active: the cleanup calls the record may
    /// still take, its declared count when it became active
    /// ([`Reclaim::remaining`]), saturated, which only overstates. Held in
    /// the header's padding beside `custody`.
    budget: u32,
    _pin: PhantomPinned,
}

/// A record's metadata and payload. The header is first, and `Held` places its
/// value first, so a header pointer is a block pointer.
#[repr(C)]
struct Entry<T: Reclaim<A>, A: Allocator> {
    header: Header<A>,
    state: T::State,
    value: MaybeUninit<T>,
}

type Block<T, A> = Held<Entry<T, A>, <A as Allocator>::Permit>;

/// The record's admitted metadata: header, the payload's state and permit,
/// written in one unit. Evaluated in a constant by every caller, so a payload
/// whose state cannot fit fails to compile where its record type is used.
const fn metadata<T: Reclaim<A>, A: Allocator>() -> stable::Metadata {
    stable::Metadata::new::<Entry<T, A>, A::Permit>(
        size_of::<Header<A>>() + size_of::<T::State>() + size_of::<A::Permit>(),
    )
}

/// What allocating one record holding a `T` admits and requests: one unit
/// of its metadata, and its whole block.
pub(crate) const fn record_cost<T: Reclaim<A>, A: Allocator>() -> (stable::Metadata, usize) {
    (metadata::<T, A>(), size_of::<Block<T, A>>())
}

/// What the queue holds at its front, observed without removing anything.
enum Front {
    Empty,
    /// The tail was swapped by a retiring thread whose link is not yet stored.
    InFlight,
    Ready,
}

/// The queue and accounting of one decode scope. Handles reach it through the
/// scope; queued blocks are owned by the intrusive queue, not by a dropped
/// handle. The public authority is [`DecodeOwner`](owned::DecodeOwner).
pub(crate) struct Reclaimer<A: Allocator> {
    head: AtomicPtr<Header<A>>,
    tail: AtomicPtr<Header<A>>,
    /// Stepping caller only: the record whose cleanup is in progress.
    active: AtomicPtr<Header<A>>,
    /// Stepping caller only: the next removal's unit was admitted.
    removal_admitted: AtomicBool,
    outstanding: AtomicUsize,
    closed: AtomicBool,
    /// The explicit stepping authority was dropped; remaining references
    /// finish cleanup with the scope's terminal policy.
    abandoned: AtomicBool,
    stepping: AtomicBool,
    /// Payload types are erased in the queue. A borrowed owner may hold records
    /// of any type, so it is neither sent nor shared across threads.
    confined: PhantomData<*mut ()>,
}

impl<A: Allocator> Reclaimer<A> {
    pub(crate) const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            tail: AtomicPtr::new(ptr::null_mut()),
            active: AtomicPtr::new(ptr::null_mut()),
            removal_admitted: AtomicBool::new(false),
            outstanding: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            stepping: AtomicBool::new(false),
            confined: PhantomData,
        }
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Allocate uninitialized stable storage and its embedded custody record,
    /// its write and its release admitted first and kept in `admitted`. No
    /// `T` is created or moved. A failed physical allocation releases its
    /// reservation without registering a nonexistent block.
    ///
    /// # Safety
    /// Every borrow in T must remain valid until this owner's final cleanup,
    /// including after the last handle transfers custody to the queue.
    pub(crate) unsafe fn allocate<T: Reclaim<A>>(
        &self,
        a: &mut A,
        admitted: &mut stable::Admitted,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        // A record's dispatch depth is fixed by its type: one beyond the
        // limit fails to compile where the record type is used, before any
        // work could be admitted for it.
        const {
            assert!(
                T::DISPATCH_DEPTH <= MAX_DISPATCH_DEPTH,
                "a record's declared dispatch depth exceeds MAX_DISPATCH_DEPTH"
            )
        };
        // Budget/allocator implementations may hold another owner reference, so
        // closure is observed before admission and again after the permit.
        // SAFETY: header and state are written; no T is formed or moved.
        let block = unsafe {
            stable::acquire::<Entry<T, A>, A>(
                admitted,
                const { metadata::<T, A>() },
                || !self.is_closed(),
                |entry| {
                    ptr::addr_of_mut!((*entry).header).write(Header {
                        next: AtomicPtr::new(ptr::null_mut()),
                        advance: advance::<T, A>,
                        finish: finish::<T, A>,
                        custody: Holder::Handle,
                        budget: 0,
                        _pin: PhantomPinned,
                    });
                    ptr::addr_of_mut!((*entry).state).write(T::INITIAL);
                },
                a,
            )?
        };
        // Each outstanding block occupies a distinct live allocation, so the
        // count cannot exceed the number of addressable blocks.
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        Ok(Record {
            block,
            owner: self,
            marker: PhantomData,
        })
    }

    /// Wait-free retirement: the caller exclusively owns `header` until the
    /// tail swap publishes it. Any thread may call this concurrently.
    ///
    /// # Safety
    /// `header` heads a live block allocated by this owner, held by a handle.
    unsafe fn enqueue(&self, header: NonNull<Header<A>>) {
        // SAFETY: the handle has exclusive custody; both writes precede the
        // releasing publication below.
        unsafe {
            assert!((*header.as_ptr()).custody == Holder::Handle);
            (*header.as_ptr()).custody = Holder::Queued;
            (*header.as_ptr())
                .next
                .store(ptr::null_mut(), Ordering::Relaxed);
        }
        let previous = self.tail.swap(header.as_ptr(), Ordering::AcqRel);
        if previous.is_null() {
            self.head.store(header.as_ptr(), Ordering::Release);
        } else {
            // SAFETY: a queued predecessor is released only after the stepping
            // caller has removed it, which requires this link or the tail.
            unsafe { (*previous).next.store(header.as_ptr(), Ordering::Release) };
        }
    }

    /// Stepping caller only.
    fn front(&self) -> Front {
        let head = self.head.load(Ordering::Acquire);
        if head.is_null() {
            return Front::Empty;
        }
        // SAFETY: only the stepping caller removes and releases queued blocks.
        let next = unsafe { (*head).next.load(Ordering::Acquire) };
        if !next.is_null() || self.tail.load(Ordering::Acquire) == head {
            Front::Ready
        } else {
            Front::InFlight
        }
    }

    /// Stepping caller only. None when a retiring thread raced the last record.
    fn remove(&self) -> Option<NonNull<Header<A>>> {
        let head = NonNull::new(self.head.load(Ordering::Acquire))?;
        // SAFETY: only the stepping caller removes and releases queued blocks.
        let next = unsafe { (*head.as_ptr()).next.load(Ordering::Acquire) };
        if !next.is_null() {
            // A retiring thread writes head only after observing an empty
            // tail, which cannot happen while this record is still queued.
            self.head.store(next, Ordering::Release);
            return Some(head);
        }
        if self
            .tail
            .compare_exchange(
                head.as_ptr(),
                ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        // A failed exchange means a retiring thread that observed the empty
        // tail has already installed its record as the new head; that state is
        // already correct, so the result carries no further obligation.
        let _ = self.head.compare_exchange(
            head.as_ptr(),
            ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        Some(head)
    }

    /// Perform one cleanup unit; the unit that completes a record's cleanup
    /// also frees its block, a release its allocation paid for. On refusal
    /// or error the front record remains owned by this queue. Waiting: nothing
    /// can advance until a handle retires, a retiring thread links its record,
    /// or the caller already stepping, on another thread, returns. One caller
    /// steps at a time; a concurrent caller performs and admits nothing.
    pub(crate) fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        if self.stepping.swap(true, Ordering::Acquire) {
            return Ok(Reclaimed::Waiting);
        }
        struct Stepping<'a>(&'a AtomicBool);
        impl Drop for Stepping<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _stepping = Stepping(&self.stepping);
        let Some(head) = NonNull::new(self.active.load(Ordering::Relaxed)) else {
            match self.front() {
                Front::Empty => {
                    return Ok(if self.outstanding() == 0 {
                        Reclaimed::Done
                    } else {
                        Reclaimed::Waiting
                    });
                }
                Front::InFlight => return Ok(Reclaimed::Waiting),
                Front::Ready => {}
            }
            if !self.removal_admitted.load(Ordering::Relaxed) {
                super::operation::REMOVAL.admit(a)?;
                self.removal_admitted.store(true, Ordering::Relaxed);
            }
            let Some(head) = self.remove() else {
                return Ok(Reclaimed::Waiting);
            };
            self.removal_admitted.store(false, Ordering::Relaxed);
            // SAFETY: removal transferred exclusive custody to this caller,
            // and the declared count reads its state as an observation does.
            unsafe {
                assert!((*head.as_ptr()).custody == Holder::Queued);
                (*head.as_ptr()).custody = Holder::Active;
                let declared = ((*head.as_ptr()).finish)(head, Ending::Count);
                (*head.as_ptr()).budget = u32::try_from(declared).unwrap_or(u32::MAX);
            }
            self.active.store(head.as_ptr(), Ordering::Relaxed);
            return Ok(Reclaimed::Progress);
        };
        // SAFETY: the active slot exclusively owns this block, and callbacks
        // receive neither the owner nor its queue.
        unsafe {
            assert!((*head.as_ptr()).custody == Holder::Active);
            // A record whose cleanup would take more calls than it declared
            // when it became active breaks its `Reclaim` contract: a defect,
            // refused before the call, so no drain, stepped or terminal, runs
            // unbounded.
            let budget = (*head.as_ptr()).budget;
            if budget == 0 {
                return Err(BoundedError::PlanMismatch);
            }
            // The record's own cleanup is its operation's task's.
            let advance = (*head.as_ptr()).advance;
            let advanced = at(OperationPlace::Task, || advance(head, a))?;
            // A successful call spends one; a refused one changed nothing.
            (*head.as_ptr()).budget = budget - 1;
            if advanced != Reclaimed::Done {
                return Ok(Reclaimed::Progress);
            }
            let finish = (*head.as_ptr()).finish;
            self.active.store(ptr::null_mut(), Ordering::Relaxed);
            finish(head, Ending::Free);
        }
        Ok(if self.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }

    pub(crate) fn shutdown_step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.closed.store(true, Ordering::Release);
        self.step(a)
    }
}

/// Constant-size owning handle. Moving this handle never moves its allocation.
type InvariantOwned<T> = PhantomData<(T, fn(T) -> T)>;

/// The queue's view of one record held by a handle. Dropping it enqueues.
pub(crate) struct Record<'r, T: Reclaim<A>, A: Allocator> {
    block: NonNull<Block<T, A>>,
    owner: &'r Reclaimer<A>,
    // Invariance prevents shortening a payload borrow after allocation and then
    // initializing a shorter-lived value in storage queued for a longer scope.
    marker: InvariantOwned<T>,
}

impl<'r, T: Reclaim<A>, A: Allocator> Record<'r, T, A> {
    /// Reclaim a still-owned record, preserving it on every refusal. This is
    /// the terminal-error path: completion means this record's storage and
    /// reservation were released, independent of other records in the owner.
    pub(crate) fn reclaim_step(
        record: &mut Option<Self>,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let Some(current) = record.as_mut() else {
            return Ok(Reclaimed::Done);
        };
        let header = current.block.cast::<Header<A>>();
        // SAFETY: the unique handle has not been queued, and &mut Option<Self>
        // excludes publication and concurrent access to its destination.
        unsafe {
            assert!((*header.as_ptr()).custody == Holder::Handle);
            // The record's own cleanup is its operation's task's.
            let advance = (*header.as_ptr()).advance;
            if at(OperationPlace::Task, || advance(header, a))? != Reclaimed::Done {
                return Ok(Reclaimed::Progress);
            }
            // The cleanup is complete: the block is freed in this same unit, a
            // release its allocation paid for. Suppress Drop: this handle is
            // released here, never enqueued with a freed pointer.
            let current =
                core::mem::ManuallyDrop::new(record.take().ok_or(BoundedError::PlanMismatch)?);
            let owner = current.owner;
            ((*header.as_ptr()).finish)(header, Ending::Free);
            owner.outstanding.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(Reclaimed::Done)
    }
}

/// The payload destination and state of a block.
///
/// # Safety
/// The block is live and the caller holds its exclusive custody.
unsafe fn destination<'b, T: Reclaim<A>, A: Allocator>(
    block: NonNull<Block<T, A>>,
) -> (NonNull<MaybeUninit<T>>, &'b mut T::State) {
    // SAFETY: forwarded from the caller; field projections stay in bounds.
    unsafe {
        (
            NonNull::new_unchecked(ptr::addr_of_mut!((*block.as_ptr()).value.value)),
            &mut (*block.as_ptr()).value.state,
        )
    }
}

/// The published payload of a block.
///
/// # Safety
/// The block is live, its payload initialized, and no cleanup can run while
/// the returned borrow is live.
unsafe fn published<'b, T: Reclaim<A>, A: Allocator>(block: NonNull<Block<T, A>>) -> &'b T {
    // SAFETY: forwarded from the caller.
    unsafe { (&*ptr::addr_of!((*block.as_ptr()).value.value)).assume_init_ref() }
}

impl<A: Allocator> Drop for Reclaimer<A> {
    fn drop(&mut self) {
        // The scope block is never dropped as a value: it is released only by
        // shutdown after the queue is empty, or deliberately retained.
        debug_assert_eq!(*self.outstanding.get_mut(), 0);
    }
}

impl<T: Reclaim<A>, A: Allocator> Drop for Record<'_, T, A> {
    fn drop(&mut self) {
        // SAFETY: repr(C) places Header first; this unique handle transfers its
        // block exactly once. No allocation, traversal, or destructor is called.
        unsafe { self.owner.enqueue(self.block.cast::<Header<A>>()) };
    }
}

unsafe fn advance<T: Reclaim<A>, A: Allocator>(
    header: NonNull<Header<A>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    // SAFETY: the vtable was installed for exactly this Block<T, A>, and the
    // caller has exclusive custody after the public handle was dropped.
    unsafe {
        let (place, state) = destination::<T, A>(header.cast());
        T::reclaim_step(place, state, a)
    }
}

unsafe fn finish<T: Reclaim<A>, A: Allocator>(header: NonNull<Header<A>>, ending: Ending) -> u64 {
    match ending {
        // SAFETY: the vtable was installed for exactly this Block<T, A>, and
        // the caller has exclusive custody of the record.
        Ending::Count => unsafe {
            let (place, state) = destination::<T, A>(header.cast());
            T::remaining(place, state)
        },
        Ending::Free => {
            // SAFETY: cleanup returned Done, so the payload owns nothing; the
            // block's allocation admitted this release.
            unsafe { stable::free(header.cast::<Block<T, A>>()) };
            0
        }
    }
}
