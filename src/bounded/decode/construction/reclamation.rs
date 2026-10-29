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
pub(crate) use owned::{AbortOnUnwind, EMPTIED, ScopeRef, slot_place};
pub use owned::{
    Acquisition, DecodeOwner, OwnedInitialized, OwnedRecord, ScopePosition, scope_bound,
};
#[cfg(test)]
#[cfg(feature = "std")]
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

/// What a [`Place`] may do: build and clean up the value ([`Build`]), or
/// observe it ([`Observe`]). Sealed: the two modes are the only ones.
pub trait Mode: sealed::Sealed {}

/// A place's mode for construction and cleanup: it may write the value,
/// drop it in place and project raw pointers for a binding's own writes.
pub enum Build {}

/// A place's mode for observation, the only mode a cleanup count
/// ([`Reclaim::remaining`]) and an operation's detail receive: shared reads
/// and projection of the value, no write to it and no exclusive access to
/// any of its bytes. The one exclusive access it keeps is to a record's own
/// custody ([`Place::custody`]): a phase, a handle, a child's construction
/// state, which no reader of a published value borrows and no place lies
/// within.
pub enum Observe {}

impl Mode for Build {}
impl Mode for Observe {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Build {}
    impl Sealed for super::Observe {}
}

/// A stable destination of a `T`, with the provenance of the allocation it
/// lies in for that allocation's whole life.
///
/// A place is issued only where provenance is rooted ([`Place::root`]): a
/// record's block, a metadata block's value, a container's buffer, a tree's
/// node. Every place within it is a raw projection from it ([`Self::project`],
/// [`Self::cast`]), so every place derived from one root, in any step of
/// construction or cleanup, or in any observation, stays valid as long as
/// the allocation does. No operation of a place reborrows the value
/// exclusively and lets the borrow outlive it: under the aliasing model such a
/// reborrow, even one that writes nothing, invalidates every place derived
/// before it from the bytes it covers, which is how a binding that keeps a
/// child's place across steps (`Option<T>`'s payload) would lose it, and how
/// a count read while the value is borrowed elsewhere (a published value a
/// preparation traverses) would invalidate the borrow. A place cannot be
/// made to reborrow its value without a new unsafe cast of its own.
///
/// A place is `Copy`, so a place alone cannot exclude a second access
/// through a copy of it. Every operation that reads, writes or borrows the
/// value therefore takes a borrow of the custody paired with the place: the
/// state construction and cleanup thread beside it (a binding's
/// [`Reclaim::State`], a record's progress, a block's handle), which its
/// holder has exclusively. A shared read ([`Self::get`]) holds that custody
/// shared for as long as the read is live, and every write, exclusive borrow
/// or custody access holds it exclusively, so the borrow checker refuses a
/// write, a second exclusive borrow or a second custody access while either
/// is live: two aliasing `&mut`, or a write under a live `&`, cannot be
/// written through a place. Pairing a place with its own custody remains
/// the caller's obligation, as every place's provenance is.
///
/// A write under a live read does not compile, even through a copy of the
/// place:
/// ```compile_fail,E0502
/// use core::{mem::MaybeUninit, ptr::NonNull};
/// use dcbor::bounded::decode::construction::reclamation::{Place, Written};
/// let mut slot = MaybeUninit::<u64>::uninit();
/// let mut state = Written::Empty;
/// let place = unsafe { Place::root(NonNull::from(&mut slot)) };
/// let copy = place;
/// unsafe { place.write(&mut state, 1) };
/// let read = unsafe { place.get(&state) };
/// unsafe { copy.write(&mut state, 2) };
/// assert_eq!(*read, 1);
/// ```
///
/// `M` is what the place may do: [`Build`] or [`Observe`] ([`Peek`]).
pub struct Place<T, M: Mode = Build> {
    place: NonNull<MaybeUninit<T>>,
    mode: PhantomData<M>,
}

/// A place in its observing mode ([`Observe`]).
pub type Peek<T> = Place<T, Observe>;

impl<T, M: Mode> Clone for Place<T, M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, M: Mode> Copy for Place<T, M> {}

impl<T, M: Mode> Place<T, M> {
    /// The place of a destination whose provenance is rooted at `place`: a
    /// record's block, a metadata block's value, a container's buffer, a
    /// tree's node, or a destination a driver owns outright.
    ///
    /// # Safety
    /// `place` is stable and suitably aligned for a `T`, and every access
    /// to the destination for the rest of its life is through `place` or a
    /// place derived from it: nothing reborrows the destination otherwise.
    pub const unsafe fn root(place: NonNull<MaybeUninit<T>>) -> Self {
        Self {
            place,
            mode: PhantomData,
        }
    }

    /// The place `project` computes within this one: a field, a variant's
    /// payload or an element, in this place's mode. Construction, cleanup
    /// and counting of one value project its parts through one expression,
    /// so a part's count is read at exactly the place its cleanup steps.
    ///
    /// # Safety
    /// `project` computes a place within the value from the value's
    /// pointer by raw projection alone (`addr_of_mut!`, pointer arithmetic
    /// or a cast), forming no reference to any part of the value.
    pub unsafe fn project<F>(self, project: impl FnOnce(*mut T) -> *mut F) -> Place<F, M> {
        Place {
            // SAFETY: forwarded from the caller: a projection within a
            // nonnull, stable destination.
            place: unsafe {
                NonNull::new_unchecked(project(self.place.as_ptr().cast::<T>()).cast())
            },
            mode: PhantomData,
        }
    }

    /// This place as a place of a `U` laid out at its start.
    ///
    /// # Safety
    /// A `U` is laid out at the start of the value: a transparent wrapper's
    /// field, a representation's first member.
    pub const unsafe fn cast<U>(self) -> Place<U, M> {
        Place {
            place: self.place.cast(),
            mode: PhantomData,
        }
    }

    /// The place `count` values of `T` past this one: an element of the
    /// array or buffer this place lies in.
    ///
    /// # Safety
    /// The result lies within the same allocation.
    pub const unsafe fn add(self, count: usize) -> Self {
        Place {
            // SAFETY: forwarded from the caller.
            place: unsafe { self.place.add(count) },
            mode: PhantomData,
        }
    }

    /// The value, read through a shared borrow, which coexists with every
    /// other shared borrow and with every place derived before it, for as
    /// long as `custody`, the custody paired with this place, is borrowed
    /// shared: no write through a place can be made meanwhile.
    ///
    /// # Safety
    /// The value is initialized, and `custody` is this place's own.
    pub unsafe fn get<C: ?Sized>(self, custody: &C) -> &T {
        let _ = custody;
        // SAFETY: forwarded from the caller; the custody borrow bounds the
        // read.
        unsafe { self.place.as_ref().assume_init_ref() }
    }

    /// A record's own custody, exclusively, for as long as `custody`, the
    /// progress paired with the record's place, is borrowed exclusively: a
    /// second custody access, or any write through a place, cannot be made
    /// meanwhile. The custody is one field of the record grouping
    /// everything the record holds besides its published value (its
    /// handles, its phase, its children's construction states), so one call
    /// yields all of it and its fields borrow disjointly. Available in both
    /// modes: a cleanup count reads a record's phase and steps its
    /// children's counts through their states, which take `&mut`; the
    /// value's own bytes stay unborrowed.
    ///
    /// # Safety
    /// `custody` is this place's own; `project` computes the custody
    /// field's place by raw projection alone; the field is initialized, no
    /// place lies within it, and no reader of a published value borrows it.
    pub(crate) unsafe fn custody<C: ?Sized, F>(
        self,
        custody: &mut C,
        project: impl FnOnce(*mut T) -> *mut F,
    ) -> &mut F {
        let _ = custody;
        // SAFETY: forwarded from the caller; the projection forms no
        // reference beyond the field itself, and the custody borrow bounds
        // the result.
        unsafe { &mut *project(self.place.as_ptr().cast::<T>()) }
    }
}

impl<T> Place<T, Build> {
    /// Write the whole value, without reading or dropping what was there,
    /// `custody`, this place's own, borrowed exclusively for the write.
    ///
    /// # Safety
    /// The destination holds nothing that needs dropping, the write is
    /// admitted, and `custody` is this place's own.
    pub unsafe fn write<C: ?Sized>(self, custody: &mut C, value: T) {
        let _ = custody;
        // SAFETY: forwarded from the caller; the place is stable and aligned.
        unsafe { self.place.as_ptr().cast::<T>().write(value) }
    }

    /// Drop the value in place, `custody`, this place's own, borrowed
    /// exclusively for the drop.
    ///
    /// # Safety
    /// The value is initialized, owns nothing a cleanup step has not
    /// released or accounted, and is not used again; `custody` is this
    /// place's own.
    pub unsafe fn drop_in_place<C: ?Sized>(self, custody: &mut C) {
        let _ = custody;
        // SAFETY: forwarded from the caller.
        unsafe { core::ptr::drop_in_place(self.place.as_ptr().cast::<T>()) }
    }

    /// The value's raw pointer, for a binding's own writes of its parts by
    /// raw projection, `custody`, this place's own, borrowed exclusively to
    /// obtain it: never to reborrow the value, which [`Place`]'s contract
    /// forbids.
    pub fn as_ptr<C: ?Sized>(self, custody: &mut C) -> *mut T {
        let _ = custody;
        self.place.as_ptr().cast()
    }

    /// The value, borrowed exclusively for `use_value` alone, `custody`,
    /// this place's own, borrowed exclusively for as long: how a binding
    /// calls the methods of a value that needs `&mut` (a vector's header
    /// reserving its buffer or recording its length). The borrow ends with
    /// the call.
    ///
    /// # Safety
    /// The value is initialized, `custody` is this place's own, and no place
    /// derived from this one lies within the value's own bytes: an exclusive
    /// reborrow would invalidate it. Places within a separate allocation the
    /// value owns (a buffer it points to) are unaffected.
    pub unsafe fn with_mut<C: ?Sized, R>(
        self,
        custody: &mut C,
        use_value: impl FnOnce(&mut T) -> R,
    ) -> R {
        let _ = custody;
        // SAFETY: forwarded from the caller; the borrow ends with the call.
        use_value(unsafe { self.place.as_ptr().cast::<T>().as_mut_unchecked() })
    }

    /// The place of a part of the value reached through the value itself,
    /// for a part whose position only the value's own methods know (an
    /// option's payload): `reach` finds it through an exclusive borrow that
    /// ends with the call, and the part's place keeps the provenance of
    /// that borrow, a child of this place's.
    ///
    /// # Safety
    /// As [`Self::with_mut`], and the part `reach` returns lies within the
    /// value. While the part's place is in use, a place now lies within the
    /// value's bytes, so this place is not borrowed exclusively again
    /// ([`Self::with_mut`], [`Self::reach`]) and does not write the value;
    /// shared reads ([`Self::get`]) leave the part's place valid.
    pub unsafe fn reach<C: ?Sized, F>(
        self,
        custody: &mut C,
        reach: impl FnOnce(&mut T) -> Option<&mut F>,
    ) -> Option<Place<F>> {
        // SAFETY: forwarded from the caller.
        unsafe {
            self.with_mut(custody, |value| {
                reach(value).map(|part| Place::root(NonNull::from(part).cast()))
            })
        }
    }

    /// This place in its observing mode.
    pub const fn observe(self) -> Peek<T> {
        Place {
            place: self.place,
            mode: PhantomData,
        }
    }
}

/// A value's [`Place`] together with the custody paired with it, borrowed
/// exclusively for `'c`: the one form in which construction, cleanup and
/// counting receive a destination.
///
/// The pairing is carried by the type. A slot is minted only where a place's
/// provenance is rooted and its custody lives beside it (a scope record's
/// block, an installed block's value, a container's element under its
/// record, a driver's own destination), through [`Slot::new`], whose
/// obligation is that pairing; every other slot is a child projected from
/// one ([`Slot::child`]). So a caller holding a slot has no obligation left:
/// [`Reclaim`], [`InPlace`](super::in_place::InPlace) and their callbacks
/// take slots through safe signatures, and their implementations, under
/// their `unsafe trait` contracts, must be sound for every call a slot's
/// holder can make, in any order: a step after `Done`, a build after
/// cleanup began, a count at any point.
///
/// A slot is not `Copy`: while one is live its custody is borrowed, so a
/// second slot of the same destination cannot be formed from it, only a
/// reborrow for the length of a call ([`Self::reborrow`], [`Self::observe`]).
///
/// Two reborrows of one slot are not live at once:
/// ```compile_fail,E0499
/// use core::{mem::MaybeUninit, ptr::NonNull};
/// use dcbor::bounded::decode::construction::reclamation::{Build, Place, Slot, Written};
/// let mut value = MaybeUninit::<u64>::uninit();
/// let mut state = Written::Empty;
/// let place = unsafe { Place::<u64, Build>::root(NonNull::from(&mut value)) };
/// let mut slot = unsafe { Slot::new(place, &mut state) };
/// let first = slot.reborrow();
/// let second = slot.reborrow();
/// drop((first, second));
/// ```
///
/// A slot is minted only under the pairing obligation:
/// ```compile_fail,E0133
/// use core::{mem::MaybeUninit, ptr::NonNull};
/// use dcbor::bounded::decode::construction::reclamation::{Build, Place, Slot, Written};
/// let mut value = MaybeUninit::<u64>::uninit();
/// let mut state = Written::Empty;
/// let place = unsafe { Place::<u64, Build>::root(NonNull::from(&mut value)) };
/// let slot = Slot::new(place, &mut state);
/// drop(slot);
/// ```
pub struct Slot<'c, T, S: ?Sized, M: Mode = Build> {
    place: Place<T, M>,
    custody: &'c mut S,
}

/// A slot in its observing mode ([`Observe`]): what a cleanup count and an
/// operation's detail receive.
pub type PeekSlot<'c, T, S> = Slot<'c, T, S, Observe>;

impl<'c, T, S: ?Sized, M: Mode> Slot<'c, T, S, M> {
    /// The slot of `place` and `custody`.
    ///
    /// # Safety
    /// `custody` is `place`'s own: it records exactly what is initialized
    /// and acquired at `place`, and every access to the destination for the
    /// rest of its life is through this slot, a slot derived from it, or a
    /// slot minted again from the same place and the same custody.
    pub const unsafe fn new(place: Place<T, M>, custody: &'c mut S) -> Self {
        Self { place, custody }
    }

    /// This slot for the length of a borrow of it.
    pub fn reborrow(&mut self) -> Slot<'_, T, S, M> {
        Slot {
            place: self.place,
            custody: self.custody,
        }
    }

    /// This slot, observing, for the length of a borrow of it.
    pub fn observe(&mut self) -> PeekSlot<'_, T, S> {
        Slot {
            place: Place {
                place: self.place.place,
                mode: PhantomData,
            },
            custody: self.custody,
        }
    }

    /// This slot, observing, for the rest of its borrow.
    pub fn into_observe(self) -> PeekSlot<'c, T, S> {
        Slot {
            place: Place {
                place: self.place.place,
                mode: PhantomData,
            },
            custody: self.custody,
        }
    }

    /// The custody: plain state, which its own type keeps consistent.
    pub fn custody(&mut self) -> &mut S {
        self.custody
    }

    /// The place and the custody, for an implementation's own access to the
    /// value: every [`Place`] operation that reads, writes or borrows the
    /// value takes the custody, and is itself unsafe.
    pub fn parts(&mut self) -> (Place<T, M>, &mut S) {
        (self.place, self.custody)
    }

    /// The place and the custody for the rest of this slot's borrow.
    pub fn into_parts(self) -> (Place<T, M>, &'c mut S) {
        (self.place, self.custody)
    }

    /// The slot of a part of the value: `project` computes the part's place
    /// within this one, and `custody` selects the part's own custody within
    /// this slot's.
    ///
    /// # Safety
    /// `project` computes a place within the value by raw projection alone
    /// (as [`Place::project`]), and the custody `custody` selects is that
    /// part's own (as [`Slot::new`]).
    pub unsafe fn child<F, SF: ?Sized>(
        self,
        project: impl FnOnce(*mut T) -> *mut F,
        custody: impl FnOnce(&'c mut S) -> &'c mut SF,
    ) -> Slot<'c, F, SF, M> {
        Slot {
            // SAFETY: forwarded from the caller.
            place: unsafe { self.place.project(project) },
            custody: custody(self.custody),
        }
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
/// Construction and cleanup receive the value as a [`Slot`], its place and
/// this state together, so a caller holding one has nothing to promise.
///
/// # Safety
/// [`Self::INITIAL`] must mean "nothing initialized, nothing acquired". The
/// state must record exactly what construction initialized and acquired, on
/// every return. Every unit must be admitted before work; refusal must
/// preserve that unit's state. Cleanup must not allocate, unwind, recursively
/// destroy a value, or invoke an arbitrary user destructor. `Done` promises
/// that no initialized subobject or owned child allocation remains and that
/// releasing the outer allocation without `Drop` is sound. Every method is
/// sound for every call a slot's holder can make, in any order: a cleanup
/// step after `Done` reports `Done` and touches nothing, and a count at any
/// point reads only the state and what it records as initialized.
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

    /// One unit of cleanup of the value in `slot`: its place and the state
    /// that describes its initialized parts. No references into those parts
    /// remain live while the slot is held.
    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
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
    /// The value may still be borrowed when its count is read, as a
    /// published value is by a preparation traversing it, so the count
    /// reads it only through its slot observed ([`PeekSlot`]), whose place
    /// cannot write the value or reborrow any of its bytes exclusively; it
    /// reaches exclusively only a record's own custody ([`Place::custody`]),
    /// which no reader borrows, through the slot's custody.
    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> u64;
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

/// What a record's acquisition writes, whole: its header and the payload's
/// state. The header is first.
#[repr(C)]
struct Head<T: Reclaim<A>, A: Allocator> {
    header: Header<A>,
    state: T::State,
}

/// A record's metadata and payload. The head is first, its header first in
/// it, and `Held` places its value first, so a header pointer is a block
/// pointer.
#[repr(C)]
struct Entry<T: Reclaim<A>, A: Allocator> {
    head: Head<T, A>,
    value: MaybeUninit<T>,
}

type Block<T, A> = Held<Entry<T, A>, <A as Allocator>::Permit>;

/// The record's admitted metadata: its head, whole, and the permit, written
/// in one unit. Evaluated in a constant by every caller, so a payload whose
/// state cannot fit fails to compile where its record type is used.
const fn metadata<T: Reclaim<A>, A: Allocator>() -> stable::Metadata {
    stable::Metadata::header::<Head<T, A>, Entry<T, A>, A::Permit>()
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
    /// Written by the stepping caller only: the next removal's unit was
    /// admitted. A step that admits it and then finds the front record raced
    /// by a retiring thread returns `Waiting` and keeps it; the step that
    /// removes the record spends it without admitting again. Custody the
    /// scope holds, so observation reads it ([`Self::removal_admitted`]).
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

    /// Whether the next removal's unit is admitted and retained: exact for
    /// the caller that steps, whose own stores it reads in program order; a
    /// snapshot for any other thread while a step is in progress there.
    pub(crate) fn removal_admitted(&self) -> bool {
        self.removal_admitted.load(Ordering::Relaxed)
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
        // SAFETY: the head, header and state, is written whole at its field;
        // no T is formed or moved.
        let block = unsafe {
            stable::acquire::<Entry<T, A>, Head<T, A>, A>(
                admitted,
                || !self.is_closed(),
                || Head {
                    header: Header {
                        next: AtomicPtr::new(ptr::null_mut()),
                        advance: advance::<T, A>,
                        finish: finish::<T, A>,
                        custody: Holder::Handle,
                        budget: 0,
                        _pin: PhantomPinned,
                    },
                    state: T::INITIAL,
                },
                |entry| ptr::addr_of_mut!((*entry).head),
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

/// The payload's slot in a block: its place, the root of the payload's
/// provenance ([`Place::root`]), projected from the block's own pointer, so
/// every place derived from it, in any step, stays valid while the block is
/// live, with the state the block keeps beside it, its custody.
///
/// # Safety
/// The block is live and the caller holds its exclusive custody.
unsafe fn destination<'b, T: Reclaim<A>, A: Allocator>(
    block: NonNull<Block<T, A>>,
) -> Slot<'b, T, T::State> {
    // SAFETY: forwarded from the caller; field projections stay in bounds,
    // every access to the payload is through this place, and the state in
    // the block's head is the one the record's acquisition paired with it.
    unsafe {
        Slot::new(
            Place::root(NonNull::new_unchecked(ptr::addr_of_mut!(
                (*block.as_ptr()).value.value
            ))),
            &mut (*block.as_ptr()).value.head.state,
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
    let slot = unsafe { destination::<T, A>(header.cast()) };
    T::reclaim_step(slot, a)
}

unsafe fn finish<T: Reclaim<A>, A: Allocator>(header: NonNull<Header<A>>, ending: Ending) -> u64 {
    match ending {
        // SAFETY: the vtable was installed for exactly this Block<T, A>, and
        // the caller has exclusive custody of the record.
        Ending::Count => T::remaining(unsafe { destination::<T, A>(header.cast()) }.into_observe()),
        Ending::Free => {
            // SAFETY: cleanup returned Done, so the payload owns nothing; the
            // block's allocation admitted this release.
            unsafe { stable::free(header.cast::<Block<T, A>>()) };
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;

    /// A prefix's class is its count: two prefixes of one count are one
    /// class, of different counts two.
    #[test]
    fn a_prefixs_class_is_its_count() {
        let mut one = Prefix::EMPTY;
        one.advance();
        let mut two = one;
        two.advance();
        assert_eq!(<Prefix as Reduction>::class(&one), one);
        assert_eq!(<Prefix as Reduction>::class(&two).initialized(), 2);
        assert_ne!(
            <Prefix as Reduction>::class(&one),
            <Prefix as Reduction>::class(&two)
        );
    }

    /// A place's copy is the same place: its pointer, and so its
    /// provenance, unchanged.
    #[test]
    #[expect(
        clippy::clone_on_copy,
        reason = "the test runs the place's `Clone` impl itself, which a copy bypasses"
    )]
    fn a_copied_place_is_the_same_place() {
        let mut slot = MaybeUninit::<u64>::uninit();
        let mut custody = ();
        // SAFETY: the test owns the destination; nothing else reaches it.
        let place = unsafe { Place::<u64, Build>::root(NonNull::from(&mut slot)) };
        let copied = <Place<u64, Build> as Clone>::clone(&place);
        assert_eq!(place.as_ptr(&mut custody), copied.as_ptr(&mut custody));
    }

    /// A record's cost evaluated at run time is the constant the scope
    /// admits: its metadata, header and state written whole with the
    /// permit, and the whole block.
    #[test]
    fn a_records_cost_at_run_time_is_its_metadata_and_its_block() {
        let (metadata, block) = record_cost::<u64, Limits>();
        let (constant, bytes) = const { record_cost::<u64, Limits>() };
        assert_eq!(metadata.bytes(), constant.bytes());
        assert_eq!(block, bytes);
    }

    /// A queue dropped as a value holds nothing: the check its drop makes
    /// holds of an empty one.
    #[test]
    fn an_empty_queue_drops_cleanly() {
        let queue = Reclaimer::<Limits>::new();
        assert_eq!(queue.outstanding(), 0);
        drop(queue);
    }
}
