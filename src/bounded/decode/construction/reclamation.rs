//! Stable allocations with intrusive, explicitly stepped reclamation.
//!
//! This owner never calls a value's `Drop`. Implementations explicitly reclaim
//! initialized subobjects, including partial construction, before returning Done.
//!
//! Retirement is a wait-free push onto an intrusive multi-producer queue: one
//! swap of the tail, then one store of the predecessor's link. Only the owner's
//! `step` removes records, and a stepping flag admits one caller at a time.
//! The borrowed `Reclaimer` erases its payload types, so it stays confined to
//! one thread; the owned scope re-exposes the same queue across threads only for
//! payloads its allocation path has proven `Send`.
use core::marker::{PhantomData, PhantomPinned};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

use super::operation::OperationPlace;
use super::stable::{self, Held};
use crate::bounded::ResourceBound;
use crate::bounded::boundary::{Predicate, boundary};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Caller, CustodySink, Identity, PermitsObserved,
    RecordStage, Releasing, Unit, at, observed_all,
};
use crate::sync::{
    AtomicBool, AtomicPtr, AtomicUsize, Atomics, Ordered, Ordering, Plain, Representation, Shipped,
};

mod owned;
/// Admissions held toward a block, as custody observations report them.
pub use super::stable::Admitted;
#[cfg(test)]
pub(crate) use owned::admits_its_production_representation;
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

/// The capability every cleanup step receives ([`Reclaim::reclaim_step`]):
/// the policy the cleanup runs under, as a [`Releasing`] budget only. Through
/// it a cleanup step admits work, observes, settles and names permits; no
/// new allocation can be requested through it, because it implements no
/// [`Allocator`], exposes no field, and has no method, `Deref` or `AsMut`
/// returning the policy it wraps.
///
/// The enforcement is this wrapper, not a generic bound: a concrete policy
/// that is [`Releasing`] may also be an [`Allocator`], so a step generic over
/// `A: Releasing` alone could still be handed one; a step given a `Cleanup`
/// cannot reach it. What a step allocates by other means (the global
/// allocator, an allocator it owns) is outside this capability: the
/// physical-allocation checks of the verification layer and the trusted
/// domain's contract govern it.
///
/// Minted by the engine alone (its constructor is crate-private), where it
/// dispatches cleanup: a record's advance, an operation's or a standalone
/// driver's cleanup step. Callers outside the crate never hold one; every
/// public stepping entry takes the policy and mints it.
///
/// Each property is a compile-fail fixture of its own, with its planted
/// control (`dcbor-derive/tests/ui/fail`): no allocation requested through
/// it (`cleanup_allocate.rs`, E0599), no dereference to the policy
/// (`cleanup_deref.rs`, E0614), and no access to its field
/// (`cleanup_field.rs`, E0616).
pub struct Cleanup<'a, A: Allocator> {
    policy: &'a mut A,
    /// The scope references this step released inside cleanup, deferred
    /// rather than released in place ([`owned::Worklist`]): the minting
    /// frame's combinator processes them once the step returns
    /// ([`with_cleanup`]), or the queue's step hands them to its caller.
    worklist: owned::Worklist<A>,
    /// The dispatch level this step is at against its root's declaration
    /// ([`Depth`]): fresh at every mint, so each root, and each record a
    /// drain steps, starts at level zero.
    depth: Depth,
}

// The build's threads' own locals ([`crate::sync::thread_locals`]), as the
// nesting hooks' (`owned`): a model thread's dispatch level is its own.
#[cfg(all(test, feature = "std"))]
crate::sync::thread_locals! {
    /// The deepest dispatch level entered on this thread since the last
    /// [`deepest_reached`]: the measurement the declaration census reads.
    /// Test builds only; no shipped code keeps it.
    static DEEPEST: core::cell::Cell<usize> = core::cell::Cell::new(0);
}

/// The deepest dispatch level `run` enters on this thread, construction and
/// cleanup alike ([`Depth::descend`]): the census's measurement of a
/// binding's dispatch against its declaration.
#[cfg(all(test, feature = "std"))]
pub(crate) fn deepest_reached(run: impl FnOnce()) -> usize {
    DEEPEST.with(|deepest| deepest.set(0));
    run();
    DEEPEST.with(core::cell::Cell::get)
}

/// The run-time check of dispatch depth, one definition for construction
/// ([`super::Context`]) and cleanup ([`Cleanup`]): the level a dispatch is
/// at, against the dispatch depth its root declared ([`Reclaim::DISPATCH_DEPTH`],
/// at most [`MAX_DISPATCH_DEPTH`] by [`admitted_depth`]). Every engine
/// dispatch into a binding or a record (a root's session entry, a part's
/// entry, a record's advance) descends one level first and is refused
/// [`BoundedError::PlanMismatch`], nothing changed, past the declaration: a
/// binding understating its depth is refused at the dispatch that exceeds
/// it, never recursing unbounded. The root session's own frame is a
/// constant one per root and is not a level. In cleanup the level lives in
/// the one capability every dispatch of a step shares, so each dispatch
/// restores it on return ([`Cleanup::descend`]); in construction each part's
/// context carries a copy ([`super::Context::part`]), so a sibling never
/// sees another's level and there is nothing to restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Depth {
    at: usize,
    /// The root's declaration, taken at its first dispatch; `None` before.
    declared: Option<usize>,
}

impl Depth {
    /// No level entered and no root declared.
    pub(crate) const fn fresh() -> Self {
        Self {
            at: 0,
            declared: None,
        }
    }

    /// Take `declared`, the root's dispatch depth, unless a root already
    /// declared one: a nested record reached through its parent continues
    /// the parent's declaration, which contains its own.
    pub(crate) fn declare(&mut self, declared: usize) {
        if self.declared.is_none() {
            self.declared = Some(declared);
        }
    }

    /// Enter one dispatch level, refused past the declaration (or with
    /// none taken), the level unchanged.
    pub(crate) fn descend<R>(&mut self) -> Result<(), BoundedError<R>> {
        let at = self.at.checked_add(1).ok_or(BoundedError::Overflow)?;
        match self.declared {
            Some(declared) if at <= declared => {
                self.at = at;
                #[cfg(all(test, feature = "std"))]
                DEEPEST.with(|deepest| deepest.set(deepest.get().max(at)));
                Ok(())
            }
            _ => Err(BoundedError::PlanMismatch),
        }
    }

    /// Leave the level [`Self::descend`] entered.
    fn ascend(&mut self) {
        self.at -= 1;
    }
}

impl<'a, A: Allocator> Cleanup<'a, A> {
    /// Run `dispatch` one dispatch level deeper ([`Depth::descend`]),
    /// refused before it runs past the root's declaration; the level is
    /// restored on its return.
    pub(crate) fn descend<R>(
        &mut self,
        dispatch: impl FnOnce(&mut Self) -> BoundedResult<R, A>,
    ) -> BoundedResult<R, A> {
        self.depth.descend()?;
        let result = dispatch(self);
        self.depth.ascend();
        result
    }

    /// Take the root's declared dispatch depth ([`Depth::declare`]).
    pub(crate) fn declare(&mut self, declared: usize) {
        self.depth.declare(declared);
    }
    /// The capability over `policy`, minted where the engine dispatches
    /// cleanup, with an empty worklist. Every minting site hands the
    /// worklist on: the outermost frames through [`with_cleanup`], the
    /// queue's step into its caller's list ([`Reclaimer::step`]).
    pub(crate) fn new(policy: &'a mut A) -> Self {
        Self {
            policy,
            worklist: owned::Worklist::new(),
            depth: Depth::fresh(),
        }
    }

    /// The worklist the step's deferred scope references go to: every
    /// release of a scope reference inside cleanup defers into it
    /// ([`owned::ScopeRef`]).
    pub(crate) fn worklist(&mut self) -> &mut owned::Worklist<A> {
        &mut self.worklist
    }
}

/// Run `step` under a cleanup capability minted over `policy`, then perform
/// every scope release the step deferred ([`owned::with_worklist`]): the one
/// wrapper every outermost cleanup dispatch mints through: a handle's public
/// step, a standalone driver's, an operation's, the scope authority's.
pub(crate) fn with_cleanup<A: Allocator, R>(
    policy: &mut A,
    step: impl FnOnce(&mut Cleanup<'_, A>) -> R,
) -> R {
    owned::with_worklist(|worklist| {
        let mut cleanup = Cleanup::new(policy);
        let result = step(&mut cleanup);
        worklist.append(&mut cleanup.worklist);
        result
    })
}

impl<A: Allocator> crate::bounded::Budget for Cleanup<'_, A> {
    type Refusal = A::Refusal;

    #[expect(
        clippy::disallowed_methods,
        reason = "forwards an admission already made through the route"
    )]
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
        self.policy.traverse(values, bytes)
    }

    fn boundary(&mut self, boundary: crate::bounded::boundary::Boundary) {
        self.policy.boundary(boundary)
    }

    type Origin = A::Origin;

    fn origin(&self) -> Self::Origin {
        self.policy.origin()
    }

    fn admitted(&mut self, work: crate::bounded::WriteWork) {
        self.policy.admitted(work)
    }

    fn identify(&mut self) -> Result<Identity, Self::Refusal> {
        self.policy.identify()
    }

    fn held(&mut self, work: crate::bounded::WriteWork, hold: crate::bounded::Hold) {
        self.policy.held(work, hold)
    }

    fn effect(&mut self, effect: crate::bounded::Effect) {
        self.policy.effect(effect)
    }

    fn owner(&mut self) -> Result<crate::bounded::Owner, Self::Refusal> {
        self.policy.owner()
    }

    fn acquisition(
        &mut self,
        owner: &crate::bounded::Owner,
    ) -> Result<crate::bounded::Acquisition<Self::Origin>, Self::Refusal> {
        self.policy.acquisition(owner)
    }

    fn validate_owner(&mut self, owner: &crate::bounded::Owner) -> Result<(), Self::Refusal> {
        self.policy.validate_owner(owner)
    }

    fn performer(&self) -> crate::bounded::Performer {
        self.policy.performer()
    }
}

impl<A: Allocator> Releasing for Cleanup<'_, A> {
    type Permit = A::Permit;

    fn permit_identity(permit: &Self::Permit) -> Identity {
        A::permit_identity(permit)
    }

    fn custody(permit: &Self::Permit, owner: Identity, stage: RecordStage) {
        A::custody(permit, owner, stage)
    }
}

/// Maximum declared synchronous dispatch depth of an admitted stable record.
/// This is independent of input depth and checked before allocating the record.
pub const MAX_DISPATCH_DEPTH: usize = 64;

/// The one static check of a root's declared dispatch depth: evaluated in a
/// `const` block at every place a root is admitted, a scope record's
/// allocation ([`Reclaimer::allocate`]) and the standalone driver's
/// creation (`Standalone::new`), so a root declaring more than
/// [`MAX_DISPATCH_DEPTH`] fails to compile (E0080) where it is used, before
/// any work could be admitted for it. The run-time check of each dispatch
/// against the declaration is beside it (`Depth`).
pub(crate) const fn admitted_depth<T: Reclaim<A>, A: Allocator>() {
    assert!(
        T::DISPATCH_DEPTH <= MAX_DISPATCH_DEPTH,
        "a record's declared dispatch depth exceeds MAX_DISPATCH_DEPTH"
    );
}

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
/// may differ, so a container implements it only over children whose every
/// complete state is of one class ([`Uniform`]), and a binding over a child
/// implements it only over a child that does. An implementation states the
/// argument for its relation at its definition; the verification suites
/// check the relation against the states and cleanup transitions they
/// reach, and reject planted relations that merge states of different
/// custody.
///
/// A class carries exactly what its state's cleanup reads, so a class
/// gains a field or a variant whenever that cleanup comes to read more: the
/// crate's class types are `#[non_exhaustive]`, read and compared by their
/// users, built only by the crate's own `class` functions (an enum's
/// variants excepted). Their `Ord` is a total order for keying classes in
/// sorted collections within one build of the crate; it means nothing
/// beyond equality and carries no stability across versions. A state's
/// observation, unlike its class, is the exact alphabet its successor
/// relations are written over, and stays exhaustive.
pub trait Reduction: Custody {
    type Class: Copy + Eq + Ord + core::fmt::Debug;

    fn class(observation: &Self::Observation) -> Self::Class;
}

/// A reduction whose every complete state, the state any construction
/// reaches when a build step reports `Built::Done`, is of one class,
/// [`Self::COMPLETE`]. What a container's reduction rests on: it observes
/// its newest child whole and counts its older ones, which are complete, so
/// their cleanups are alike, and its class a simulation of cleanup, exactly
/// when every complete child is of one class. A state whose complete states
/// differ in what their cleanup reads (an option complete as absent or as
/// present) declares none, and a container over it is never reduced. Each
/// declaration states why it holds; the verification suites require every
/// complete state they reach to be of the declared class, and reject a
/// planted declaration that is not.
pub trait Uniform: Reduction {
    /// The class of every complete state.
    const COMPLETE: Self::Class;
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

// Every binding whose state is `Written` records the value written before
// its build step reports `Done` (the integers' and scalars' bindings, and the
// derive's unit payloads): a complete state is `Initialized`.
impl Uniform for Written {
    const COMPLETE: Self = Written::Initialized;
}

/// The state of a record an operation initializes in a fixed number of
/// units: how many units of its resource-free prefix are initialized, or
/// released, the terminal state its incomplete prefix's cleanup leaves. A
/// value, not an authority, so it may be copied; only the crate advances or
/// releases it.
///
/// Released is not the initial state, though neither holds an initialized
/// unit: from it cleanup reports `Done` admitting nothing, the count is the
/// one call that reports it, and initialization is refused, as a session's
/// `Released` refuses every later build (`in_place::Session`). Without it a
/// released prefix would read as an unstarted one, whose first cleanup unit
/// admits the record's release again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Prefix {
    state: PrefixState,
}

/// What a [`Prefix`] records: its initialized units, held as their count
/// plus one so the count's zero is the niche `Released` occupies, or its
/// release. The state is then one word, as the bare count it replaced: every
/// record's block, and so every bound and recorded figure over it, is
/// unchanged by the released state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PrefixState {
    Initialized(core::num::NonZeroUsize),
    Released,
}

const _: () = assert!(
    core::mem::size_of::<Prefix>() == core::mem::size_of::<usize>(),
    "a prefix's released state widens every prefix record"
);

impl Prefix {
    /// No unit initialized.
    pub const EMPTY: Self = Self {
        state: PrefixState::Initialized(core::num::NonZeroUsize::MIN),
    };

    /// The initialized units: none once released.
    pub const fn initialized(&self) -> usize {
        match self.state {
            PrefixState::Initialized(units) => units.get() - 1,
            PrefixState::Released => 0,
        }
    }

    /// Whether the record's cleanup released it: terminal.
    pub const fn released(&self) -> bool {
        matches!(self.state, PrefixState::Released)
    }

    /// Record the next unit as initialized. Initialization refuses a
    /// released prefix before it writes, so this is never reached on one.
    pub(crate) fn advance(&mut self) {
        self.set(self.initialized() + 1);
    }

    /// Record exactly `units` as initialized, for a prefix whose nested part
    /// counts its own units: at most its task's `INIT_STEPS`, which every
    /// initialization checks before it writes, so the count plus one fits.
    pub(crate) fn set(&mut self, units: usize) {
        match core::num::NonZeroUsize::MIN.checked_add(units) {
            Some(stored) => self.state = PrefixState::Initialized(stored),
            None => unreachable!("a prefix's units are bounded by its INIT_STEPS"),
        }
    }

    /// Record the record released: its incomplete prefix's cleanup released
    /// every unit it wrote.
    pub(crate) fn release(&mut self) {
        self.state = PrefixState::Released;
    }
}

/// The initialized units, or the release: each unit is a distinct field
/// written, and cleanup releases what the first holds, so the count, or the
/// release that ended it, is the whole custody.
impl Custody for Prefix {
    type Observation = Self;

    fn observe(&mut self) -> Self {
        *self
    }
}

// The count, or the release, is the custody and fixes the cleanup that
// follows: identity.
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
/// custody (`Place::custody`): a phase, a handle, a child's construction
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

    /// The address of the slot's place: what a construction's record of the
    /// value there names ([`super::in_place::Assembly`]). An address, never
    /// a pointer to dereference.
    pub(crate) fn address(&self) -> usize {
        self.place.place.as_ptr().addr()
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
/// (`stable::Installed`), never as an integer: the handle exists exactly
/// while its block is live and owned by this state, so a state that names a
/// block always names one it may access and must release.
///
/// Construction and cleanup receive the value as a [`Slot`], its place and
/// this state together, so a caller holding one has nothing to promise.
///
/// # Safety
/// An implementation keeps eight obligations, and the `// SAFETY:` comment
/// on it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *initial*: [`Self::INITIAL`] means nothing initialized, nothing
///   acquired.
/// - *state*: the state records exactly what construction initialized and
///   acquired, on every return.
/// - *admission*: every unit is admitted before its work; a refusal
///   preserves that unit's state.
/// - *cleanup*: cleanup does not allocate, unwind, recursively destroy a
///   value, or invoke an arbitrary user destructor.
/// - *done*: `Done` means no initialized subobject or owned child allocation
///   remains, so releasing the outer allocation without `Drop` is sound.
/// - *order*: every method is sound for every call a slot's holder can make,
///   in any order: a cleanup step after `Done` reports `Done` and touches
///   nothing, and a count at any point reads only the state and what it
///   records as initialized.
/// - *depth*: [`Self::DISPATCH_DEPTH`] is not understated.
/// - *count*: [`Self::remaining`] is not understated.
pub unsafe trait Reclaim<A: Allocator>: Sized {
    /// Upper bound on nested construction/reclamation dispatch, including self.
    /// Implementations delegating to children must add their own fixed dispatch
    /// overhead to the maximum child's bound, using saturating arithmetic.
    /// The default is valid only for leaf bindings with no child dispatch.
    /// Understating this bound violates the unsafe implementation contract.
    /// A root past [`MAX_DISPATCH_DEPTH`] fails to compile ([`admitted_depth`]);
    /// an understated declaration is refused at run time at the dispatch
    /// that exceeds it (`Depth`): construction is refused
    /// [`BoundedError::PlanMismatch`], nothing changed; a stepped cleanup is
    /// refused the same on every call, the record retained and still
    /// reported by its custody observation, never reclaimed; a terminal
    /// drain meeting it aborts, as it does on every error. Neither is
    /// reclamation: the declaration bounds dispatch only for a binding that
    /// keeps this contract.
    const DISPATCH_DEPTH: usize = 1;

    /// The progress construction and cleanup retain across suspension, and
    /// the custody it holds ([`Custody`]).
    type State: Custody;

    /// The state of a destination nothing has been done to. A constant, so
    /// producing it can neither allocate nor unwind.
    const INITIAL: Self::State;

    /// One unit of cleanup of the value in `slot`: its place and the state
    /// that describes its initialized parts. No references into those parts
    /// remain live while the slot is held. It runs under `cleanup`, the
    /// engine's cleanup capability ([`Cleanup`]), through which no new
    /// allocation can be requested.
    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A>;

    /// The most successful [`Self::reclaim_step`] calls cleanup from `state`
    /// can take, the one that returns `Done` included: at least one. A refused
    /// call is not counted; it changes nothing and is repeated. Read under the
    /// state's exclusive custody, admitting nothing and changing nothing, like
    /// an observation ([`Custody`]); arithmetic is checked: `None` when the
    /// count does not fit in `u64`, never a saturated count, which a reader
    /// refuses as [`BoundedError::Overflow`]. The scope holds every queued record to the
    /// count its state declares when its cleanup begins, so a drain, stepped
    /// or terminal, is finite: a record that would take more calls is a
    /// defect. Overstating is sound; understating violates this trait's
    /// contract and fails the drain.
    ///
    /// The value may still be borrowed when its count is read, as a
    /// published value is by a preparation traversing it, so the count
    /// reads it only through its slot observed ([`PeekSlot`]), whose place
    /// cannot write the value or reborrow any of its bytes exclusively; it
    /// reaches exclusively only a record's own custody (`Place::custody`),
    /// which no reader borrows, through the slot's custody.
    fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> Option<u64>;

    /// Each permit the value's state owns, reported once to `sink`
    /// ([`CustodySink::permit`]): its installed metadata blocks, its payload
    /// allocations, its child records' blocks, and every live child's own.
    /// A binding opens no group of its own: the root holding it brackets
    /// these permits in its owner's group, since every acquisition a binding
    /// makes is bound under that root's pending ([`stable::Pending`]). A
    /// binding holds no obligation (its credit is the root pending's) and
    /// reports none; a state that holds an independently owning custody of
    /// its own (an arena with its own pending) reports that custody as a
    /// nested group of its own owner. Read as [`Self::remaining`] is,
    /// through the slot observed, admitting, allocating, publishing and
    /// releasing nothing; a permit is named, never moved. A permit the
    /// operation's own record or a parent holds is that holder's to report.
    /// A value that owns no permit reports nothing. Returns the completeness
    /// of every nested custody reported (an arena's, a queue's), combined
    /// ([`crate::bounded::observed_all`]); a value reporting none is
    /// `Complete`.
    fn observe_permits(
        slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved;
}

/// One cleanup unit of the record inside `slot`'s handle: `unwrap` takes the
/// record out of the handle, `reclaim` steps it, and `wrap` restores the
/// handle while the record survives. Every owning handle's operation-local
/// cleanup is this one routine over its own record type.
pub(crate) fn reclaim_within<W, R, A: Allocator>(
    slot: &mut Option<W>,
    cleanup: &mut Cleanup<'_, A>,
    unwrap: impl FnOnce(W) -> R,
    wrap: impl FnOnce(R) -> W,
    reclaim: impl FnOnce(&mut Option<R>, &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A>,
) -> BoundedResult<Reclaimed, A> {
    let mut record = slot.take().map(unwrap);
    let result = reclaim(&mut record, cleanup);
    *slot = record.map(wrap);
    result
}

type Advance<A> = unsafe fn(NonNull<Header<A>>, &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A>;
type Finish<A> =
    for<'v> unsafe fn(NonNull<Header<A>>, Ending<'v, <A as Releasing>::Permit>) -> Option<u64>;

/// What a record's [`Finish`] entry does: report the cleanup calls its state
/// declares ([`Reclaim::remaining`]); publish its cleanup's completion
/// ([`RecordStage::Reclaimed`]) and free the block of a record whose cleanup
/// is done; report the permits the record owns, its block's and its
/// payload's ([`Reclaim::observe_permits`]), to the sink, inside the group
/// its caller opened, and store the report's completeness in the second
/// field; or publish the record's entry into a holder's stage through its
/// block's permit ([`Releasing::custody`]), which a type-erased holder (the
/// queue) cannot name. One entry for all four keeps the header within the
/// bytes a record's metadata may write in one unit.
enum Ending<'v, P> {
    Count,
    Free,
    Permits(&'v mut dyn CustodySink<P>, &'v mut PermitsObserved),
    Custody(RecordStage),
}

/// The record stage of a record held by `holder` ([`Holder`]): the one
/// mapping every report and publication of a record's holder reads.
const fn stage_of(holder: Holder) -> RecordStage {
    match holder {
        Holder::Handle => RecordStage::Handle,
        Holder::Queued => RecordStage::Queued,
        Holder::Active => RecordStage::Active,
    }
}

/// Who holds a record's block: its handle, the queue, or the stepping
/// caller's active slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Holder {
    Handle,
    Queued,
    Active,
}

/// A record's header, one definition for every atomics family `S`
/// ([`crate::sync`]): the build stores `Shipped`'s, and every contract
/// quantity reads `Core`'s ([`Representation`], [`contract`]).
#[repr(C)]
struct Header<A: Allocator, S: Atomics = Shipped> {
    /// Written by the retiring thread before publication and by the next
    /// retiring thread when it links behind this record.
    next: S::Link<Header<A, S>>,
    advance: Advance<A>,
    finish: Finish<A>,
    /// Owned by the handle until publication, then by the stepping caller:
    /// written before the tail swap that publishes the record and read after
    /// the removal that acquires it, so its accesses are ordered by that
    /// publication alone.
    custody: S::Cell<Holder>,
    /// Stepping caller only, once active: the cleanup calls the record may
    /// still take, its declared count when it became active
    /// ([`Reclaim::remaining`]), saturated, which only overstates. Held in
    /// the header's padding beside `custody`.
    budget: S::Cell<u32>,
    _pin: PhantomPinned,
}

/// What a record's acquisition writes, whole: its header and the payload's
/// state. The header is first.
#[repr(C)]
struct Head<T: Reclaim<A>, A: Allocator, S: Atomics = Shipped> {
    header: Header<A, S>,
    state: T::State,
}

/// A record's metadata and payload. The head is first, its header first in
/// it, and `Held` places its value first, so a header pointer is a block
/// pointer. Between the head and the payload, the identity of the owner of
/// the acquisition that allocated the record: observational identity, the
/// key its custody is reported under through every holder (the operation,
/// the published handle, the queue), never an owner capability and never
/// settlement authority. Written once, by an admitted unit of its own
/// ([`OWNER`]) that is the acquisition's second stage, before any handle to
/// the record exists ([`owned::Acquisition`]); never written again.
#[repr(C)]
pub(crate) struct Entry<T: Reclaim<A>, A: Allocator, S: Atomics = Shipped> {
    head: Head<T, A, S>,
    owner: MaybeUninit<Identity>,
    value: MaybeUninit<T>,
}

/// A record's owner stage: its owner's identity written in one admitted unit
/// of its own bytes, after the head's unit and within the same acquisition.
/// The head's unit cannot carry it: a record's head is its header (32 bytes
/// in the production representation) and its payload's state beside a
/// 16-byte permit, already a quantum for a two-word state.
const OWNER: Unit<Caller> = Unit::written::<Identity>(Caller);

type Block<T, A, S = Shipped> = Held<Entry<T, A, S>, <A as Releasing>::Permit>;

impl<T: Reclaim<A>, A: Allocator, S: Atomics> Representation for Head<T, A, S> {
    type In<F: Atomics> = Head<T, A, F>;
}

impl<T: Reclaim<A>, A: Allocator, S: Atomics> Representation for Entry<T, A, S> {
    type In<F: Atomics> = Entry<T, A, F>;
}

/// What acquiring a record holding a `T` admits ([`stable::Contract`]): its
/// head, whole, and the permit, written in one unit, and its whole block;
/// read from the production representation, so the same in every build,
/// whatever atomics the build stores. Evaluated in a constant by every
/// caller, so a payload whose state cannot fit fails to compile where its
/// record type is used.
const fn contract<T: Reclaim<A>, A: Allocator>()
-> stable::Contract<Head<T, A>, Entry<T, A>, A::Permit> {
    stable::Contract::of()
}

/// What allocating one record holding a `T` admits and requests: its two
/// units, the head's write ([`contract`]) and the owner stage's
/// ([`OWNER`]), and its whole block.
pub(crate) const fn record_cost<T: Reclaim<A>, A: Allocator>() -> (ResourceBound, usize) {
    let contract = contract::<T, A>();
    let written = match contract.write().checked_add(OWNER.bound()) {
        Some(written) => written,
        None => panic!("a record's two acquisition units overflow u64"),
    };
    (written, contract.block())
}

/// The production representation's record head write, owner write and
/// block, read directly from `Core`'s types and not through [`contract`] or
/// [`OWNER`]: the oracle the I3 witness (`crate::sync::models`) holds what a
/// record admits to in every build.
#[cfg(test)]
pub(crate) fn production_record<T: Reclaim<A>, A: Allocator>() -> (usize, usize, usize) {
    use crate::sync::Core;
    (
        core::mem::size_of::<Head<T, A, Core>>() + core::mem::size_of::<A::Permit>(),
        core::mem::size_of::<Identity>(),
        core::mem::size_of::<Block<T, A, Core>>(),
    )
}

/// What the queue holds at its front, observed without removing anything.
enum Front {
    Empty,
    /// The tail was swapped by a retiring thread whose link is not yet stored.
    InFlight,
    Ready,
}

/// The scope queue's drain state, what its next steps read
/// ([`Reclaimer::step`]): the remaining declared calls of the record whose
/// cleanup is active, if one is; the records queued behind it; and whether
/// the next removal's unit is admitted and retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QueuePosition {
    pub active: Option<u32>,
    pub queued: usize,
    pub removal_admitted: bool,
}

/// An observation of a scope queue ([`Reclaimer::queue_position`]): none
/// when the operation holds no scope reference, contended when another
/// caller was stepping the queue, else its drain state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueueObservation {
    Unscoped,
    Contended,
    Observed(QueuePosition),
}

/// The queue and accounting of one decode scope. Handles reach it through the
/// scope; queued blocks are owned by the intrusive queue, not by a dropped
/// handle. The public authority is [`DecodeOwner`](owned::DecodeOwner).
pub(crate) struct Reclaimer<A: Allocator, S: Atomics = Shipped> {
    head: S::Link<Header<A, S>>,
    tail: S::Link<Header<A, S>>,
    /// Stepping caller only: the record whose cleanup is in progress.
    active: S::Link<Header<A, S>>,
    /// Written by the stepping caller only: the next removal's unit was
    /// admitted. A step that admits it and then finds the front record raced
    /// by a retiring thread returns `Waiting` and keeps it; the step that
    /// removes the record spends it without admitting again. Custody the
    /// scope holds, so observation reads it ([`Self::removal_admitted`]).
    removal_admitted: S::Flag,
    outstanding: S::Counter,
    closed: S::Flag,
    /// The explicit stepping authority was dropped; remaining references
    /// finish cleanup with the scope's terminal policy.
    abandoned: S::Flag,
    stepping: S::Flag,
    /// Payload types are erased in the queue. A borrowed owner may hold records
    /// of any type, so it is neither sent nor shared across threads.
    confined: PhantomData<*mut ()>,
}

impl<A: Allocator> Reclaimer<A> {
    /// An empty queue. Built at run time, inside the scope's acquisition:
    /// its atomics come from [`crate::sync`], and a model checker's atomics
    /// are not constructible in a constant.
    pub(crate) fn new() -> Self {
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

    /// The head stage of a record's acquisition: uninitialized stable
    /// storage and its embedded custody record, its write and its release
    /// admitted first and held, with their origins, in `pending` for the
    /// acquisition `holder` names, outside the record being acquired
    /// ([`stable::acquire`]): the acquiring token's own custody, validated
    /// against on every entry. No `T` is created or moved. A failed physical
    /// allocation releases its reservation without registering a nonexistent
    /// block. The granted block is the acquiring token's until its owner
    /// stage ([`Self::own`]) makes it a record; no handle exists before.
    ///
    /// # Safety
    /// Every borrow in T must remain valid until this owner's final cleanup,
    /// including after the last handle transfers custody to the queue.
    pub(crate) unsafe fn allocate<T: Reclaim<A>>(
        &self,
        a: &mut A,
        pending: &mut stable::Pending<A::Origin>,
        holder: &mut Option<stable::Ticket>,
    ) -> BoundedResult<NonNull<Block<T, A>>, A> {
        // A record's dispatch depth is fixed by its type: one beyond the
        // limit fails to compile where the record type is used, before any
        // work could be admitted for it.
        const { admitted_depth::<T, A>() };
        // Below or at the limit, the valuation the record reaches; past it is
        // the compile-time refusal above (`dispatch_depth_beyond_limit`).
        boundary!(
            a,
            Predicate::DispatchDepth,
            T::DISPATCH_DEPTH,
            MAX_DISPATCH_DEPTH
        );
        // Budget/allocator implementations may hold another owner reference, so
        // closure is observed before admission and again after the permit.
        // SAFETY: the head, header and state, is written whole at its field;
        // no T is formed or moved.
        let block = unsafe {
            stable::acquire::<Entry<T, A>, Head<T, A>, A>(
                const { contract::<T, A>() },
                pending,
                holder,
                || !self.is_closed(),
                || Head {
                    header: Header {
                        next: AtomicPtr::new(ptr::null_mut()),
                        advance: advance::<T, A>,
                        finish: finish::<T, A>,
                        custody: Plain::new(Holder::Handle),
                        budget: Plain::new(0),
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
        // The block classified a record block, granted to the acquiring
        // token's owner, once its initialization is complete: no ordinary
        // permit is ever taken for it, so its release is checked as a
        // record's ([`RecordStage::Granted`]). An acquisition is bound only
        // under a made owner, so the pending names it.
        // SAFETY: the block was just granted and initialized, and the caller
        // holds it exclusively; its permit is only read.
        A::custody(
            unsafe { block.as_ref() }.permit(),
            pending.owner_id().unwrap_or(Identity::UNOBSERVED),
            RecordStage::Granted,
        );
        Ok(block)
    }

    /// The owner stage of a record's acquisition: `owner`, the identity the
    /// acquiring token's pending stores, written into the granted `block` in
    /// one admitted unit ([`OWNER`]), after which the block is a record and
    /// its handle is returned. A refused unit writes nothing and leaves the
    /// block the token's, for a retry of this stage alone.
    ///
    /// # Safety
    /// `block` came from [`Self::allocate`] on this owner, its owner stage
    /// not yet made, and the caller holds it exclusively.
    pub(crate) unsafe fn own<T: Reclaim<A>>(
        &self,
        block: NonNull<Block<T, A>>,
        owner: Identity,
        a: &mut A,
    ) -> BoundedResult<Record<'_, T, A>, A> {
        OWNER.admit(a)?;
        // SAFETY: forwarded from the caller: a live block of this entry type,
        // its owner field unwritten, reached by field syntax; once written
        // the block is a record, its handle's from here.
        unsafe {
            (*block.as_ptr()).value.owner.write(owner);
            publish::<T, A>(block, RecordStage::Handle);
        }
        Ok(Record {
            block,
            owner: self,
            marker: PhantomData,
        })
    }

    /// Release a block granted to an acquisition stopped before its owner
    /// stage: freed without its owner, never written, being read, a release
    /// its acquisition paid for, and no longer counted outstanding.
    ///
    /// # Safety
    /// `block` came from [`Self::allocate`] on this owner, its owner stage
    /// not made, the caller holds it exclusively and does not use it again.
    /// Its payload state is the initial one: nothing initialized.
    pub(crate) unsafe fn release_unowned<T: Reclaim<A>>(&self, block: NonNull<Block<T, A>>) {
        // SAFETY: forwarded from the caller; an initial payload owns nothing.
        unsafe { stable::free(block) };
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
    }

    /// Wait-free retirement: the caller exclusively owns `header` until the
    /// tail swap publishes it. Any thread may call this concurrently.
    ///
    /// # Safety
    /// `header` heads a live block allocated by this owner, held by a handle.
    unsafe fn enqueue(&self, header: NonNull<Header<A>>) {
        // SAFETY: the handle has exclusive custody; both writes precede the
        // releasing publication below.
        // The queue's custody is published before the tail swap makes the
        // record reachable by the stepping caller, through the block's own
        // permit: retirement has no budget.
        unsafe {
            assert!((*header.as_ptr()).custody.get() == Holder::Handle);
            (*header.as_ptr()).custody.set(Holder::Queued);
            ((*header.as_ptr()).finish)(header, Ending::Custody(RecordStage::Queued));
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
    /// Every scope reference the record's cleanup releases is deferred into
    /// `worklist`, the caller's, never released here: an inner frame, so a
    /// drain of another scope never runs inside this one's step.
    pub(crate) fn step(
        &self,
        a: &mut A,
        worklist: &mut owned::Worklist<A>,
    ) -> BoundedResult<Reclaimed, A> {
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
            // A count that does not fit in `u64` is a defect of the record's
            // `Reclaim::remaining`, refused as an overflow; one beyond the
            // header's `u32` budget is held at `u32::MAX`, an understatement
            // only past four billion calls (register 29.63).
            unsafe {
                assert!((*head.as_ptr()).custody.get() == Holder::Queued);
                (*head.as_ptr()).custody.set(Holder::Active);
                // The removal's exclusive custody, published before the step
                // returns its progress.
                ((*head.as_ptr()).finish)(head, Ending::Custody(RecordStage::Active));
                self.active.store(head.as_ptr(), Ordering::Relaxed);
                let declared =
                    ((*head.as_ptr()).finish)(head, Ending::Count).ok_or(BoundedError::Overflow)?;
                (*head.as_ptr())
                    .budget
                    .set(u32::try_from(declared).unwrap_or(u32::MAX));
            }
            return Ok(Reclaimed::Progress);
        };
        // SAFETY: the active slot exclusively owns this block, and callbacks
        // receive neither the owner nor its queue.
        unsafe {
            assert!((*head.as_ptr()).custody.get() == Holder::Active);
            // A record whose cleanup would take more calls than it declared
            // when it became active breaks its `Reclaim` contract: a defect,
            // refused before the call, so no drain, stepped or terminal, runs
            // unbounded.
            let budget = (*head.as_ptr()).budget.get();
            if budget == 0 {
                return Err(BoundedError::PlanMismatch);
            }
            // The record's own cleanup is its operation's task's, under the
            // cleanup capability the queue's dispatch mints over `a`.
            let advance = (*head.as_ptr()).advance;
            let mut cleanup = Cleanup::new(a);
            let advanced = at(OperationPlace::Task, || advance(head, &mut cleanup));
            // Whatever the step deferred, refused or not, is the caller's
            // to perform.
            worklist.append(cleanup.worklist());
            let advanced = advanced?;
            // A successful call spends one; a refused one changed nothing.
            (*head.as_ptr()).budget.set(budget - 1);
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

    pub(crate) fn shutdown_step(
        &self,
        a: &mut A,
        worklist: &mut owned::Worklist<A>,
    ) -> BoundedResult<Reclaimed, A> {
        self.closed.store(true, Ordering::Release);
        self.step(a, worklist)
    }

    /// What the queue's next steps read ([`Self::step`]): the active
    /// record's remaining declared calls, the records queued behind it, and
    /// whether the next removal's unit is admitted. Walked under the
    /// stepping flag, as [`Self::observe_custody`] walks it;
    /// [`QueueObservation::Contended`] when another caller is stepping.
    /// Admits, allocates and releases nothing.
    pub(crate) fn queue_position(&self) -> QueueObservation {
        if self.stepping.swap(true, Ordering::Acquire) {
            return QueueObservation::Contended;
        }
        struct Stepping<'a>(&'a AtomicBool);
        impl Drop for Stepping<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _stepping = Stepping(&self.stepping);
        // SAFETY: the active slot owns its block exclusively and the stepping
        // flag held here excludes its cleanup; its budget is only read.
        let active = NonNull::new(self.active.load(Ordering::Relaxed))
            .map(|active| unsafe { (*active.as_ptr()).budget.get() });
        let mut queued = 0;
        let mut next = self.head.load(Ordering::Acquire);
        while let Some(record) = NonNull::new(next) {
            queued += 1;
            // SAFETY: only the stepping caller removes and frees queued
            // blocks, and this caller holds the stepping flag.
            next = unsafe { (*record.as_ptr()).next.load(Ordering::Acquire) };
        }
        QueueObservation::Observed(QueuePosition {
            active,
            queued,
            removal_admitted: self.removal_admitted.load(Ordering::Relaxed),
        })
    }

    /// Report every record the queue owns, once each: the active record and
    /// every queued record, each as a group of its own under the owner its
    /// entry stores ([`Record::observe_custody`], through the record's own
    /// dispatch), the owner of the acquisition that allocated it, never the
    /// scope that queues it. Records still held by their handles are their
    /// handles' to report. The queue is walked as a stepper walks it, under the stepping
    /// flag, so no record is removed or freed meanwhile; `Contended`,
    /// nothing reported, when another caller is stepping. A record a
    /// retiring thread has published but not yet linked is not reached: the
    /// observer reads at a point where no handle is retiring. Admits,
    /// allocates and releases nothing.
    pub(crate) fn observe_custody(&self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        if self.stepping.swap(true, Ordering::Acquire) {
            return PermitsObserved::Contended;
        }
        struct Stepping<'a>(&'a AtomicBool);
        impl Drop for Stepping<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _stepping = Stepping(&self.stepping);
        let mut whole = PermitsObserved::Complete;
        if let Some(active) = NonNull::new(self.active.load(Ordering::Relaxed)) {
            let mut observed = PermitsObserved::Complete;
            // SAFETY: the active slot owns this block exclusively, and the
            // stepping flag held here excludes its cleanup meanwhile.
            unsafe {
                ((*active.as_ptr()).finish)(active, Ending::Permits(&mut *sink, &mut observed))
            };
            whole = observed_all([whole, observed]);
        }
        let mut next = self.head.load(Ordering::Acquire);
        while let Some(queued) = NonNull::new(next) {
            let mut observed = PermitsObserved::Complete;
            // SAFETY: only the stepping caller removes and frees queued
            // blocks, and this caller holds the stepping flag; the record's
            // dispatch was installed for its own block.
            unsafe {
                ((*queued.as_ptr()).finish)(queued, Ending::Permits(&mut *sink, &mut observed));
                next = (*queued.as_ptr()).next.load(Ordering::Acquire);
            }
            whole = observed_all([whole, observed]);
        }
        whole
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
    /// The record `block` holds, as a group of its own under the owner its
    /// entry stores ([`Entry`]): its block's permit and its payload's
    /// custody ([`Reclaim::observe_permits`], whose independently owning
    /// parts nest their own groups). The one record observation every
    /// holder makes, its handle and the queue alike, so a record keeps one
    /// owner association from its acquisition to its release. Returns the
    /// payload's completeness.
    ///
    /// # Safety
    /// The block is a record (its owner stage made, [`Reclaimer::own`]),
    /// live, and the caller holds its custody (its handle, or the queue
    /// under the stepping flag).
    pub(crate) unsafe fn observe_custody(
        block: NonNull<Block<T, A>>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        // SAFETY: forwarded from the caller: the owner is written before any
        // holder of the record exists and never again; the permit is only
        // read, and the payload is read through its slot observed.
        unsafe {
            sink.begin(Some((*block.as_ptr()).value.owner.assume_init()));
            // Its block's permit under its actual holder's stage, read from
            // the header the holder transitions write.
            let holder = (*block.cast::<Header<A>>().as_ptr()).custody.get();
            sink.permit(block.as_ref().permit(), Some(stage_of(holder)));
            let observed = T::observe_permits(destination::<T, A>(block).into_observe(), sink);
            sink.end();
            observed
        }
    }

    /// Reclaim a still-owned record, preserving it on every refusal. This is
    /// the terminal-error path: completion means this record's storage and
    /// reservation were released, independent of other records in the owner.
    /// Runs under `cleanup`, the capability of the cleanup that reaches the
    /// record: a handle's public step mints it, a parent's cleanup passes its
    /// own.
    pub(crate) fn reclaim_step(
        record: &mut Option<Self>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        let Some(current) = record.as_mut() else {
            return Ok(Reclaimed::Done);
        };
        let header = current.block.cast::<Header<A>>();
        // SAFETY: the unique handle has not been queued, and &mut Option<Self>
        // excludes publication and concurrent access to its destination.
        unsafe {
            assert!((*header.as_ptr()).custody.get() == Holder::Handle);
            // The record's own cleanup is its operation's task's.
            let advance = (*header.as_ptr()).advance;
            if at(OperationPlace::Task, || advance(header, cleanup))? != Reclaimed::Done {
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

impl<A: Allocator, S: Atomics> Drop for Reclaimer<A, S> {
    fn drop(&mut self) {
        // The scope block is never dropped as a value: it is released only by
        // shutdown after the queue is empty, or deliberately retained.
        debug_assert_eq!(S::exclusive(&mut self.outstanding), 0);
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
    cleanup: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    // SAFETY: the vtable was installed for exactly this Block<T, A>, and the
    // caller has exclusive custody after the public handle was dropped.
    let slot = unsafe { destination::<T, A>(header.cast()) };
    // A record dispatched by a fresh capability (a queue step, a handle's
    // public step) is its root and declares; one reached through a parent
    // continues the parent's declaration.
    cleanup.declare(T::DISPATCH_DEPTH);
    cleanup.descend(|cleanup| T::reclaim_step(slot, cleanup))
}

/// Publish that the record `block` entered `stage` under the owner its
/// entry stores, through its block's permit's own family
/// ([`Releasing::custody`]), whatever budget, or none, performs the step.
///
/// # Safety
/// `block` is a live record (its owner stage made) in the caller's custody.
unsafe fn publish<T: Reclaim<A>, A: Allocator>(block: NonNull<Block<T, A>>, stage: RecordStage) {
    // SAFETY: forwarded from the caller: the owner is written before any
    // holder exists and never again; the permit is only read.
    unsafe {
        A::custody(
            block.as_ref().permit(),
            (*block.as_ptr()).value.owner.assume_init(),
            stage,
        );
    }
}

unsafe fn finish<T: Reclaim<A>, A: Allocator>(
    header: NonNull<Header<A>>,
    ending: Ending<'_, A::Permit>,
) -> Option<u64> {
    match ending {
        // SAFETY: the vtable was installed for exactly this Block<T, A>, and
        // the caller has exclusive custody of the record.
        Ending::Count => T::remaining(unsafe { destination::<T, A>(header.cast()) }.into_observe()),
        Ending::Free => {
            // SAFETY: cleanup returned Done, so the payload owns nothing; the
            // block's allocation admitted this release. Its completion is
            // published before the block is freed, so its permit's release
            // follows it.
            unsafe {
                publish::<T, A>(header.cast::<Block<T, A>>(), RecordStage::Reclaimed);
                stable::free(header.cast::<Block<T, A>>());
            }
            Some(0)
        }
        Ending::Custody(stage) => {
            // SAFETY: the vtable was installed for exactly this Block<T, A>,
            // a record, live and in the caller's exclusive custody.
            unsafe { publish::<T, A>(header.cast::<Block<T, A>>(), stage) };
            Some(0)
        }
        Ending::Permits(sink, observed) => {
            // SAFETY: the vtable was installed for exactly this Block<T, A>,
            // a record (only records are queued), live and in the caller's
            // exclusive custody.
            *observed =
                unsafe { Record::<T, A>::observe_custody(header.cast::<Block<T, A>>(), sink) };
            Some(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;

    /// Successive siblings under one cleanup capability each enter the
    /// level after their parent's, the parent's level restored after each
    /// ([`Cleanup::descend`]): under a declaration of two, a parent level
    /// then two sibling dispatches, both admitted, the level back at zero at
    /// the end. Resource-free: no record, no scope, nothing to reclaim,
    /// whatever the outcome. Planted control
    /// `tests/data/controls/depth-not-restored.patch` (the level not
    /// restored) refuses the second sibling, the assertion "the second
    /// sibling was refused at its parent's level".
    #[test]
    fn successive_siblings_each_enter_the_level_after_their_parents() {
        let mut policy = Limits::unlimited();
        let mut cleanup = Cleanup::new(&mut policy);
        cleanup.declare(2);
        let (first, second) = cleanup
            .descend(|cleanup| {
                let first = cleanup.descend(|_| Ok(()));
                let second = cleanup.descend(|_| Ok(()));
                Ok((first, second))
            })
            .expect("the parent's level is within the declaration");
        assert_eq!(first, Ok(()), "the first sibling was refused");
        assert_eq!(
            second,
            Ok(()),
            "the second sibling was refused at its parent's level"
        );
        assert_eq!(
            cleanup.depth,
            Depth {
                at: 0,
                declared: Some(2)
            }
        );
    }

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
        // Released: no unit initialized, yet its own class, never the
        // unstarted prefix's.
        let mut released = two;
        released.release();
        assert!(released.released());
        assert_eq!(released.initialized(), 0);
        assert!(!Prefix::EMPTY.released());
        assert_ne!(
            <Prefix as Reduction>::class(&released),
            <Prefix as Reduction>::class(&Prefix::EMPTY)
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
    /// admits: its header and state written whole with the permit, then its
    /// owner's identity in a unit of its own, and the whole block, each the
    /// production representation's.
    #[test]
    fn a_records_cost_at_run_time_is_its_two_writes_and_its_block() {
        let (write, block) = record_cost::<u64, Limits>();
        assert_eq!((write, block), const { record_cost::<u64, Limits>() });
        let (head, owner, production) = production_record::<u64, Limits>();
        assert_eq!(write.values, 2, "the head's unit and the owner's");
        assert_eq!(write.bytes, (head + owner) as u64);
        assert_eq!(OWNER.bound().bytes, owner as u64);
        assert_eq!(block, production);
    }

    /// I3: a scope and a record admit their production representation
    /// ([`admits_its_production_representation`]), natively; the models run
    /// the same witness under each checker.
    #[test]
    fn a_scope_and_a_record_admit_their_production_representation() {
        admits_its_production_representation();
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
