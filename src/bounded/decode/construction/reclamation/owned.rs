//! The decode scope: one custody owner for every record of every operation.
//!
//! The scope owns queued records. Each live record handle owns one scope
//! reference. Only a record handle accesses its payload; after retirement only
//! the scope's active cleanup slot does. Shutdown releases the scope block only
//! when no other reference exists and the intrusive owner is empty.
//!
//! `'s` is the scope's data lifetime: every payload outlives it, and no handle,
//! operation or the owner itself can outlive it. Owned inputs use `'static`;
//! borrowed inputs bind the scope to the borrow.
//!
//! Every handle may move to, and retire on, any thread. Retirement pushes the
//! record onto the queue before the handle's scope reference is released, so a
//! stepping thread that observes the last reference also observes every push.
use super::*;
use crate::bounded::{Caller, Places, ResourceBound, Unit, widen};
use core::cell::Cell;

/// What the scope block's acquisition writes, whole: its queue and its
/// reference count, every field an atomic.
struct ScopeHead<A: Allocator> {
    owner: Reclaimer<A>,
    references: AtomicUsize,
}

/// The scope block's value: its header, then its terminal dispatch, written
/// in an admitted unit of its own before any reference is exposed.
struct Scope<A: Allocator> {
    head: ScopeHead<A>,
    terminal: MaybeUninit<unsafe fn(NonNull<ScopeBlock<A>>)>,
}

type ScopeBlock<A> = Held<Scope<A>, <A as Allocator>::Permit>;

places! {
    /// The places a decode scope's own lifecycle charges ([`DecodeOwner`]),
    /// one term of [`scope_bound`] each. Its records are each accounted by
    /// the operation that allocated them, their removal and release
    /// included. Shutdown's release of the scope block was paid for by its
    /// initialization, so shutdown charges nothing of its own.
    pub(crate) enum ScopePlace {
        Initialization,
    }
}

/// Completing a handle's cleanup whose record was released or moved out
/// earlier. The operation stepping it supplies the place.
pub(crate) const EMPTIED: Unit<Caller> = Unit::new(Caller, 1, 0);

/// The accounting place of one cleanup step of a handle slot: `held`, whose
/// term accounts the handle's own cleanup, while the slot holds a handle;
/// `emptied` once it is empty, where the step admits [`EMPTIED`]. The bound
/// is named by path: in this module `Place` is a record's destination
/// ([`super::Place`]).
pub(crate) fn slot_place<T, P: crate::bounded::Place>(slot: &Option<T>, held: P, emptied: P) -> P {
    if slot.is_some() { held } else { emptied }
}

/// The [`ResourceBound`] of a decode scope's own lifecycle with permits of
/// `A`: its block written and allocated by [`DecodeOwner::initialize_step`],
/// which admits the block's release with it; the block is held until
/// [`DecodeOwner::shutdown_step`] releases it once every record has been
/// released. Nothing remains held.
pub fn scope_bound<A: Allocator, R>() -> Result<ResourceBound, BoundedError<R>> {
    ScopeTerms::of::<A, R>()?.bound()
}

/// The terms [`scope_bound`] sums, one per [`ScopePlace`].
pub(crate) struct ScopeTerms {
    initialization: ResourceBound,
}

impl ScopeTerms {
    pub(crate) fn of<A: Allocator, R>() -> Result<Self, BoundedError<R>> {
        let block = widen(size_of::<ScopeBlock<A>>())?;
        // The whole block written, as `initialize_step` acquires it, and its
        // release, admitted with it.
        let work = stable::acquire_cost(const { scope_metadata::<A>() })
            .work()
            .then(stable::release_cost::<A::Permit>().work())?
            .then(
                Unit::written::<unsafe fn(NonNull<ScopeBlock<A>>)>(Caller)
                    .bound()
                    .work(),
            )?;
        Ok(Self {
            initialization: ResourceBound {
                values: work.values,
                bytes: work.bytes,
                allocated: block,
                peak: block,
                retained: 0,
            },
        })
    }
}

impl Places for ScopeTerms {
    type Place = ScopePlace;

    fn term(&self, place: ScopePlace) -> ResourceBound {
        match place {
            ScopePlace::Initialization => self.initialization,
        }
    }
}

/// Invariant in `'s`: a scope can be neither shortened nor extended.
type Lifetime<'s> = PhantomData<Cell<&'s ()>>;

/// What the scope block's acquisition writes: its header, whole, and the
/// permit.
const fn scope_metadata<A: Allocator>() -> stable::Metadata {
    stable::Metadata::header::<ScopeHead<A>, Scope<A>, A::Permit>()
}

/// The scope's terminal dispatch, written into its block so a reference that
/// does not know the allocator's terminal policy can run it: the block's
/// queue drained with that policy ([`drain_terminally`]).
///
/// # Safety
/// The caller holds a counted reference to the initialized block, kept until
/// this returns, including through child retirement, so no recursive
/// reference release can free this scope beneath it.
unsafe fn terminal<A: crate::bounded::TerminalAllocator>(block: NonNull<ScopeBlock<A>>) {
    // SAFETY: forwarded from the caller: the calling reference keeps the
    // initialized block, its header and its permit live.
    let permit = unsafe { block.as_ref().permit() };
    drain_terminally::<A>(scope(&block), permit);
}

/// Run the queue's state machine with an allocation-free terminal policy
/// over the scope's own permit, until the queue reports `Done` or `Waiting`.
/// A drain that fails, or unwinds, aborts: a terminal drain cannot report.
fn drain_terminally<A: crate::bounded::TerminalAllocator>(head: &ScopeHead<A>, permit: &A::Permit) {
    let guard = AbortOnUnwind;
    let mut policy = A::terminal(permit);
    loop {
        match head.owner.shutdown_step(&mut policy) {
            Ok(Reclaimed::Progress) => {}
            Ok(Reclaimed::Done | Reclaimed::Waiting) => break,
            Err(_) => abort(),
        }
    }
    drop(policy);
    core::mem::forget(guard);
}

/// Armed around work that must not unwind, and forgotten once that work
/// returns: dropped by an unwind instead, it aborts the process ([`abort`]).
/// A terminal drain is such work, and so is a callback a release runs
/// inside a cleanup step (`policy::Reservation`): a step half done by an
/// unwind leaves a state that no longer records what it holds.
pub(crate) struct AbortOnUnwind;

impl Drop for AbortOnUnwind {
    fn drop(&mut self) {
        abort();
    }
}

/// The scope's last reference, released: no other holder of its block
/// exists. Minted only where the reference count reached zero
/// ([`release_reference`]), and consumed by [`release_last`], so the block's
/// final release can happen once.
struct LastReference<A: Allocator> {
    block: NonNull<ScopeBlock<A>>,
}

impl<A: Allocator> LastReference<A> {
    /// # Safety
    /// The caller released the scope's last reference to `block`: no other
    /// holder exists.
    unsafe fn new(block: NonNull<ScopeBlock<A>>) -> Self {
        Self { block }
    }
}

fn release_reference<A: Allocator>(block: NonNull<ScopeBlock<A>>) {
    let state = scope(&block);
    if state.owner.abandoned.load(Ordering::Acquire)
        && !state.owner.stepping.load(Ordering::Acquire)
    {
        // SAFETY: references are exposed only after terminal initialization,
        // so the dispatch is written; this counted reference keeps the block
        // allocated and remains counted throughout the drain.
        unsafe { (*block.as_ptr()).value.terminal.assume_init()(block) };
    }
    if scope(&block).references.fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: this was the last reference.
        release_last(unsafe { LastReference::new(block) });
    }
}

/// The last reference's release: the remaining records drained, then the
/// scope block freed.
///
/// A drain that met a record still being linked by a retiring thread
/// (`Front::InFlight`) reports `Waiting` and stops, and the retiring thread,
/// finding the queue stepped, leaves the drain to the stepper: the scope's
/// count can then reach zero with that record queued. Every other holder
/// enqueued its records before releasing its reference, which the caller's
/// count acquired, so here the queue holds every remaining record, linked,
/// and none of them holds a reference (it would be counted): nothing is left
/// to race, and the drain completes. Only a record whose own cleanup cannot
/// finish is left after it, a defect, and an invalid binding cannot turn
/// that into a leak or an unwind.
fn release_last<A: Allocator>(last: LastReference<A>) {
    let block = last.block;
    if scope(&block).owner.outstanding() != 0 {
        // The drain holds a counted reference while it runs, as every
        // terminal drain does; no other holder can observe it.
        scope(&block).references.store(1, Ordering::Relaxed);
        // SAFETY: references are exposed only after terminal initialization,
        // so the dispatch is written; this function, holding the last
        // reference, keeps the block allocated until it frees it.
        unsafe { (*block.as_ptr()).value.terminal.assume_init()(block) };
    }
    if scope(&block).owner.outstanding() != 0 {
        abort();
    }
    // SAFETY: the token proves no other reference exists, and every record
    // is reclaimed.
    unsafe { stable::free(block) };
}

/// References beyond this bound can only come from leaked handles; counting
/// further would risk wrapping the count, so the process is aborted instead,
/// as for reference-counted pointers.
const MAX_REFERENCES: usize = isize::MAX as usize;

/// End the process where continuing cannot be reported: a scope reference
/// count past [`MAX_REFERENCES`], a terminal drain that fails, or an unwind
/// through work that must not unwind ([`AbortOnUnwind`]).
#[cold]
fn abort() -> ! {
    #[cfg(feature = "std")]
    {
        std::process::abort()
    }
    #[cfg(not(feature = "std"))]
    {
        // A panic while panicking aborts.
        struct Abort;
        impl Drop for Abort {
            fn drop(&mut self) {
                panic!("dcbor aborted: a scope or cleanup step could not continue");
            }
        }
        let _abort = Abort;
        panic!("dcbor aborted: a scope or cleanup step could not continue");
    }
}

/// The scope's queue and reference count behind a counted reference,
/// borrowed no longer than the holder.
fn scope<A: Allocator>(block: &NonNull<ScopeBlock<A>>) -> &ScopeHead<A> {
    // SAFETY: every holder of the pointer holds a counted reference, which
    // keeps the block allocated, and its acquisition wrote the header; the
    // header is only accessed through atomics.
    unsafe { &(*block.as_ptr()).value.head }
}

fn add_reference<A: Allocator>(block: &NonNull<ScopeBlock<A>>) {
    if scope(block).references.fetch_add(1, Ordering::Relaxed) >= MAX_REFERENCES {
        abort();
    }
}

/// A live reference, never a shutdown authority. The block remains valid
/// through explicit shutdown or until the last abandoned-scope reference
/// finishes terminal cleanup.
/// Public only as an unnameable type of the sealed operation interface.
pub struct ScopeRef<'s, A: Allocator> {
    scope: NonNull<ScopeBlock<A>>,
    lifetime: Lifetime<'s>,
}

// SAFETY: a `ScopeRef` reaches the scope block only through `scope`, which
// yields `&Scope`, and every field of `Scope` is an atomic (the reference
// count, and the `Reclaimer`'s queue pointers, counters and flags). The
// queue's stepping fields `active` and `removal_admitted` are written only
// by the caller holding the `stepping` flag, whose acquiring swap and
// releasing store order them between steppers; observation reads
// `removal_admitted` atomically, writing nothing. The queue holds only records
// allocated by `allocate_step`, which requires each payload and its state to
// be `Send`, so a record retired on one thread may be stepped and released on
// another; their permits are dropped by that stepping thread.
unsafe impl<A: Allocator> Send for ScopeRef<'_, A> where A::Permit: Send {}
// SAFETY: as above; shared access mutates only atomics, and the stepping
// fields under the `stepping` flag.
unsafe impl<A: Allocator> Sync for ScopeRef<'_, A> where A::Permit: Send {}

impl<'s, A: Allocator> ScopeRef<'s, A> {
    fn new(block: NonNull<ScopeBlock<A>>) -> Self {
        add_reference(&block);
        Self {
            scope: block,
            lifetime: PhantomData,
        }
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::new(self.scope)
    }

    fn owner(&self) -> &Reclaimer<A> {
        &scope(&self.scope).owner
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.owner().outstanding()
    }

    /// Allocate one record in this scope, admission retained in `acquisition`.
    pub(crate) fn allocate_step<T: Reclaim<A> + Send + 's>(
        &self,
        a: &mut A,
        acquisition: &mut Acquisition<'s, T, A>,
    ) -> BoundedResult<OwnedRecord<'s, T, A>, A>
    where
        T::State: Send,
    {
        if let Some(bound) = &acquisition.scope {
            if bound.scope != self.scope {
                return Err(BoundedError::PlanMismatch);
            }
        } else {
            acquisition.scope = Some(self.duplicate());
        }
        // SAFETY: T outlives 's, and neither the owner nor any handle of this
        // scope can outlive 's, so every borrow in T outlives final cleanup.
        let record = core::mem::ManuallyDrop::new(unsafe {
            self.owner().allocate::<T>(a, &mut acquisition.admitted)?
        });
        acquisition.scope = None;
        Ok(OwnedRecord {
            block: record.block,
            scope: self.duplicate(),
            marker: PhantomData,
        })
    }
}

impl<A: Allocator> Drop for ScopeRef<'_, A> {
    fn drop(&mut self) {
        release_reference(self.scope);
    }
}

/// Opaque retained admission for one record allocation, bound to its payload
/// type and owning scope. Dropping an unfinished token cancels acquisition
/// without allocating or destroying a payload. Success resets it for reuse.
pub struct Acquisition<'s, T: Reclaim<A>, A: Allocator> {
    scope: Option<ScopeRef<'s, A>>,
    admitted: stable::Admitted,
    marker: InvariantOwned<T>,
}

impl<T: Reclaim<A>, A: Allocator> Acquisition<'_, T, A> {
    pub const fn new() -> Self {
        Self {
            scope: None,
            admitted: stable::Admitted::Nothing,
            marker: PhantomData,
        }
    }
}

impl<T: Reclaim<A>, A: Allocator> Default for Acquisition<'_, T, A> {
    fn default() -> Self {
        Self::new()
    }
}

/// The cleanup authority of one decode scope. `new` allocates nothing.
/// Initialize with `initialize_step`, retain this authority while handles are
/// live, then call `shutdown_step` until Done. Records may retire on any
/// thread, and the authority may be shared: any thread holding `&DecodeOwner`
/// may allocate records and step cleanup, one stepper at a time (a concurrent
/// one is answered `Waiting`). Initialization and shutdown take `&mut self`.
///
/// Dropping the authority closes the scope and drains queued records through
/// their reclamation state machines without refusal. Live handles retain the
/// scope; their later retirement continues terminal draining. The last reference
/// releases the scope allocation and then its permit.
pub struct DecodeOwner<'s, A: Allocator> {
    scope: Option<NonNull<ScopeBlock<A>>>,
    admitted: stable::Admitted,
    /// Terminal: shutdown completed. A closed authority never acquires a new
    /// scope, so shutdown cannot be undone by a later initialization.
    closed: bool,
    ready: bool,
    lifetime: Lifetime<'s>,
}

// SAFETY: the authority's own fields (`scope`, `admitted`, `closed`) are
// plain values it exclusively owns; the scope block it points to is shared
// state reached only as for `ScopeRef`, so moving the authority to another
// thread moves only those values.
unsafe impl<A: Allocator> Send for DecodeOwner<'_, A> where A::Permit: Send {}
// SAFETY: through `&DecodeOwner` the methods are `position`, `outstanding`,
// `reference`, `allocate_step` and `step`. They read the authority's own
// fields without writing them (only `initialize_step` and `shutdown_step`
// write them, and those take `&mut self`), and reach the scope block only
// through `scope`, whose shared access is the atomics and the
// `stepping`-guarded fields `ScopeRef`'s `Sync` argument covers. Concurrent
// `step` calls are serialized by the `stepping` flag: the loser performs and
// admits nothing and returns `Waiting`.
unsafe impl<A: Allocator> Sync for DecodeOwner<'_, A> where A::Permit: Send {}

impl<A: Allocator> Default for DecodeOwner<'_, A> {
    fn default() -> Self {
        Self::new()
    }
}

/// Observation of a decode scope, allocation-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopePosition {
    pub initialized: bool,
    pub closed: bool,
    pub outstanding: usize,
    pub references: usize,
    /// The next removal's unit is admitted and retained: a step admitted it,
    /// found the front record still being linked by a retiring thread and
    /// returned `Waiting`. The step that removes the record spends it and
    /// reports `Progress` without admitting. Exact for the thread that
    /// steps; a snapshot for any other while a step is in progress there.
    pub removal_admitted: bool,
}

impl<'s, A: Allocator> DecodeOwner<'s, A> {
    pub const fn new() -> Self {
        Self {
            scope: None,
            admitted: stable::Admitted::Nothing,
            closed: false,
            ready: false,
            lifetime: PhantomData,
        }
    }

    /// Admit and allocate the scope's queue and reference count, then admit
    /// its terminal dispatch write. A refusal retains what was admitted for the
    /// next call; once `Ok`, later calls do nothing and return `Ok`. A closed
    /// authority refuses with `PlanMismatch`.
    pub fn initialize_step(&mut self, a: &mut A) -> BoundedResult<(), A>
    where
        A: crate::bounded::TerminalAllocator,
    {
        if self.closed {
            return Err(BoundedError::PlanMismatch);
        }
        if self.ready {
            return Ok(());
        }
        if self.scope.is_none() {
            let admitted = &mut self.admitted;
            // SAFETY: the header, the queue and reference count, is written
            // whole at its field; the terminal dispatch is MaybeUninit until
            // the final admitted write.
            let block = at(ScopePlace::Initialization, || unsafe {
                stable::acquire::<Scope<A>, ScopeHead<A>, A>(
                    admitted,
                    || true,
                    || ScopeHead {
                        owner: Reclaimer::new(),
                        references: AtomicUsize::new(1),
                    },
                    |scope| ptr::addr_of_mut!((*scope).head),
                    a,
                )
            })?;
            self.scope = Some(block);
        }
        let block = self.scope.ok_or(BoundedError::PlanMismatch)?;
        // SAFETY: no reference is exposed until this final field is initialized.
        // Refusal leaves the empty scope retained for initialization or Drop.
        at(ScopePlace::Initialization, || unsafe {
            crate::bounded::decode::initialization::field(
                ptr::addr_of_mut!((*block.as_ptr()).value.terminal),
                || MaybeUninit::new(terminal::<A> as unsafe fn(NonNull<ScopeBlock<A>>)),
                a,
            )
        })?;
        self.ready = true;
        Ok(())
    }

    pub fn position(&self) -> ScopePosition {
        ScopePosition {
            initialized: self.ready,
            closed: self.closed
                || self
                    .scope
                    .as_ref()
                    .is_some_and(|block| scope(block).owner.is_closed()),
            outstanding: self
                .scope
                .as_ref()
                .map_or(0, |block| scope(block).owner.outstanding()),
            references: self
                .scope
                .as_ref()
                .map_or(0, |block| scope(block).references.load(Ordering::Acquire)),
            removal_admitted: self
                .scope
                .as_ref()
                .is_some_and(|block| scope(block).owner.removal_admitted()),
        }
    }

    pub fn outstanding(&self) -> usize {
        self.position().outstanding
    }

    pub(crate) fn reference(&self) -> Option<ScopeRef<'s, A>> {
        if self.ready {
            self.scope.map(ScopeRef::new)
        } else {
            None
        }
    }

    /// Allocate one record for a custom resource binding. Initialize it through
    /// [`OwnedRecord::destination`] and publish it; retain `acquisition` across
    /// refusals.
    pub fn allocate_step<T: Reclaim<A> + Send + 's>(
        &self,
        a: &mut A,
        acquisition: &mut Acquisition<'s, T, A>,
    ) -> BoundedResult<OwnedRecord<'s, T, A>, A>
    where
        T::State: Send,
    {
        self.reference()
            .ok_or(BoundedError::PlanMismatch)?
            .allocate_step(a, acquisition)
    }

    /// One unit of queued cleanup. Waiting: nothing can advance until a
    /// handle retires, a retiring thread links its record, or another
    /// stepper returns. A removal admitted before a `Waiting` is retained
    /// ([`ScopePosition::removal_admitted`]); the call that removes the
    /// record spends it and reports `Progress` without admitting.
    pub fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        match &self.scope {
            Some(block) => scope(block).owner.step(a),
            None => Ok(Reclaimed::Done),
        }
    }

    /// Close allocation and perform one unit of shutdown. Done only after
    /// every record and the scope block itself have been released.
    pub fn shutdown_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let Some(block) = self.scope else {
            self.closed = true;
            return Ok(Reclaimed::Done);
        };
        match scope(&block).owner.shutdown_step(a)? {
            Reclaimed::Done => {}
            pending => return Ok(pending),
        }
        // Every record is released, but another handle still references the
        // scope block: nothing here can advance until it retires.
        if scope(&block).references.load(Ordering::Acquire) != 1 {
            return Ok(Reclaimed::Waiting);
        }
        // SAFETY: the only reference is this authority's; the queue is empty
        // and closed, so the scope owns nothing. Its release was paid for by
        // its initialization.
        unsafe { stable::free(block) };
        self.scope = None;
        self.ready = false;
        self.closed = true;
        Ok(Reclaimed::Done)
    }
}

impl<A: Allocator> Drop for DecodeOwner<'_, A> {
    fn drop(&mut self) {
        if let Some(block) = self.scope.take() {
            if self.ready {
                scope(&block).owner.closed.store(true, Ordering::Release);
                scope(&block).owner.abandoned.store(true, Ordering::Release);
                release_reference(block);
            } else {
                // SAFETY: partial initialization exposed no references and
                // acquired no records. The scope's release was prepaid.
                unsafe { stable::free(block) };
            }
        }
    }
}

/// An owning stable destination; retirement transfers to the scope's queue.
pub struct OwnedRecord<'s, T: Reclaim<A>, A: Allocator> {
    block: NonNull<Block<T, A>>,
    scope: ScopeRef<'s, A>,
    marker: InvariantOwned<T>,
}

// SAFETY: the handle exclusively owns its block, payload and state together
// (moving it moves both, which are `Send`); the scope reference is `Send`.
unsafe impl<T: Reclaim<A> + Send, A: Allocator> Send for OwnedRecord<'_, T, A>
where
    T::State: Send,
    A::Permit: Send,
{
}
// SAFETY: shared access exposes only `&T` (through `OwnedInitialized::value`)
// and atomic scope operations; the state is reached only through `&mut self`.
unsafe impl<T: Reclaim<A> + Sync, A: Allocator> Sync for OwnedRecord<'_, T, A> where A::Permit: Send {}

impl<'s, T: Reclaim<A>, A: Allocator> OwnedRecord<'s, T, A> {
    /// The record's slot: its place, the root of its payload's provenance
    /// for the record's whole life ([`Place`]), and its state, for as long as
    /// this handle is borrowed. Its holder builds the payload through `T`'s
    /// own methods, whose contracts keep the state describing every
    /// initialized part and acquired resource; every other access to the
    /// payload is through the slot's place, whose operations are each
    /// `unsafe` under their own contracts.
    pub fn destination(&mut self) -> Slot<'_, T, T::State> {
        // SAFETY: the handle has exclusive custody of its block for the
        // borrow.
        unsafe { destination(self.block) }
    }

    /// # Safety
    /// T must be fully initialized and its state must describe all resources.
    pub unsafe fn publish(self) -> OwnedInitialized<'s, T, A> {
        OwnedInitialized { record: self }
    }

    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        &self.scope
    }

    /// One unit of this record's own cleanup, performed in place rather than
    /// through the scope queue: completion is independent of every other
    /// record in the scope. Refusal and errors leave the slot holding the
    /// record with its progress retained. Done releases the block and
    /// reservation, returns the handle's scope reference, and empties the slot.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        // An empty slot was released or moved out earlier; a caller stepping
        // its phase through it still admits the completion reported here.
        let Some(current) = slot.as_ref() else {
            EMPTIED.admit(a)?;
            return Ok(Reclaimed::Done);
        };
        let mut held = Some(Record {
            block: current.block,
            owner: current.scope.owner(),
            marker: PhantomData::<(T, fn(T) -> T)>,
        });
        let result = Record::reclaim_step(&mut held, a);
        let released = held.is_none();
        // While the block is not released the slot still owns it, so this
        // temporary view must not transfer it to the queue. Forgetting the
        // emptied view after release is a no-op.
        core::mem::forget(held);
        if released {
            let handle =
                core::mem::ManuallyDrop::new(slot.take().ok_or(BoundedError::PlanMismatch)?);
            // SAFETY: `handle` is never dropped, so its scope reference is read
            // out exactly once and released here.
            drop(unsafe { ptr::read(&handle.scope) });
        }
        result
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`: an empty
    /// slot, one; otherwise the record's own ([`Reclaim::remaining`]), the
    /// last of which also releases the block.
    pub(crate) fn remaining(slot: &mut Option<Self>) -> u64 {
        let Some(current) = slot.as_mut() else {
            return 1;
        };
        T::remaining(current.destination().into_observe())
    }
}

impl<T: Reclaim<A>, A: Allocator> Drop for OwnedRecord<'_, T, A> {
    fn drop(&mut self) {
        // The push happens here, before the scope field's releasing decrement.
        // A short-lived borrow of the stable scope; no lifetime erasure.
        drop(Record {
            block: self.block,
            owner: self.scope.owner(),
            marker: PhantomData::<(T, fn(T) -> T)>,
        });
    }
}

/// A published record: shared access to its fully initialized payload.
pub struct OwnedInitialized<'s, T: Reclaim<A>, A: Allocator> {
    record: OwnedRecord<'s, T, A>,
}

impl<'s, T: Reclaim<A>, A: Allocator> OwnedInitialized<'s, T, A> {
    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        self.record.scope()
    }

    pub fn value(&self) -> &T {
        // SAFETY: published records are fully initialized; this handle keeps
        // the record out of the queue while the borrow is live.
        unsafe { published(self.record.block) }
    }

    /// The published record's slot, its place and its progress, the custody
    /// every access through the place borrows ([`Place`]): how its holder
    /// changes a part of the record it owns (a handle it gives up) without
    /// reborrowing the value. The same slot [`OwnedRecord::destination`]
    /// gives an unpublished record; `&mut self` excludes every reader of the
    /// value while it is held.
    pub(crate) fn destination(&mut self) -> Slot<'_, T, T::State> {
        self.record.destination()
    }

    /// Operation-local cleanup of a published value ([`OwnedRecord::reclaim_step`]).
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            a,
            |Self { record }| record,
            |record| Self { record },
            OwnedRecord::reclaim_step,
        )
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedRecord::remaining`]).
    pub(crate) fn remaining(slot: &mut Option<Self>) -> u64 {
        let mut record = slot.take().map(|Self { record }| record);
        let remaining = OwnedRecord::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;

    /// An abandoned scope whose count reaches zero with a record still
    /// queued, linked: the state a terminal drain leaves when it meets a
    /// record still being linked by a retiring thread, reports `Waiting` and
    /// stops, while that thread, finding the queue stepped, leaves the drain
    /// to the stepper and releases its reference first. The interleaving
    /// lies inside the queue's wait-free enqueue, between its tail swap and
    /// its link, so the state is built directly: a record queued, the
    /// authority given up without draining it, its reference released. The
    /// last reference drains the record and frees the scope; it neither
    /// aborts nor leaks.
    #[test]
    fn the_last_reference_drains_what_a_stopped_drain_left() {
        let mut m = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut m).unwrap();
        let record = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .unwrap();
        // Queued and linked; its handle's reference released.
        drop(record);
        let block = owner.scope.take().expect("an initialized scope");
        // The authority given up as its drop gives it up, without the drain
        // a concurrent stepper would have held off.
        owner.ready = false;
        drop(owner);
        let state = scope(&block);
        state.owner.closed.store(true, Ordering::Release);
        state.owner.abandoned.store(true, Ordering::Release);
        assert_eq!(state.owner.outstanding(), 1, "the record was not queued");
        assert_eq!(
            state.references.fetch_sub(1, Ordering::AcqRel),
            1,
            "the authority's was not the last reference"
        );
        // SAFETY: the last reference was just released.
        release_last(unsafe { LastReference::new(block) });
        assert_eq!(
            m.live_bytes(),
            0,
            "the record or the scope outlived the last reference"
        );
    }

    /// A removal admitted by a step that then returned `Waiting` is custody
    /// the scope holds: the position reports it, and the step that removes
    /// the record spends it, reporting `Progress` with no admission of its
    /// own, after which the position no longer reports it. The race that
    /// leaves it (a retiring thread swapping the tail between the step's
    /// front check and its removal) lies inside the queue's wait-free
    /// enqueue, so the state is built directly: a record queued, its removal
    /// admitted as the step admits it, the admission retained.
    #[test]
    fn a_retained_removal_admission_is_observed_and_spent_without_admitting() {
        let mut m = Limits::unlimited().logged();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut m).unwrap();
        let record = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .unwrap();
        drop(record);
        assert!(
            !owner.position().removal_admitted,
            "a queued record reported its removal admitted before any step"
        );
        let block = owner.scope.expect("an initialized scope");
        crate::bounded::decode::construction::operation::REMOVAL
            .admit(&mut m)
            .unwrap();
        scope(&block)
            .owner
            .removal_admitted
            .store(true, Ordering::Relaxed);
        assert!(
            owner.position().removal_admitted,
            "the retained removal admission is not observed"
        );
        let attempts = m.attempts();
        assert_eq!(owner.step(&mut m), Ok(Reclaimed::Progress));
        assert_eq!(
            m.attempts(),
            attempts,
            "the removal was admitted again where its admission was retained"
        );
        assert!(
            !owner.position().removal_admitted,
            "the spent removal admission is still reported"
        );
        let mut done = false;
        for _ in 0..4 {
            if owner.shutdown_step(&mut m).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "the scope did not shut down");
        assert_eq!(m.live_bytes(), 0, "the record or the scope was kept");
    }

    /// The defaults are the empty forms: an authority that holds no scope,
    /// and an acquisition that holds no admission, with which a record is
    /// acquired as with a new one; the scope's metadata evaluated at run
    /// time is the constant its initialization admits.
    #[test]
    fn the_defaults_hold_nothing() {
        let mut owner = DecodeOwner::<'static, Limits>::default();
        assert_eq!(
            owner.position(),
            ScopePosition {
                initialized: false,
                closed: false,
                outstanding: 0,
                references: 0,
                removal_admitted: false,
            }
        );
        let mut m = Limits::unlimited();
        owner.initialize_step(&mut m).unwrap();
        let record = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::default())
            .unwrap();
        assert_eq!(owner.outstanding(), 1);
        drop(record);
        let mut done = false;
        for _ in 0..4 {
            if owner.shutdown_step(&mut m).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "the scope did not shut down");
        assert_eq!(m.live_bytes(), 0);
        assert_eq!(
            scope_metadata::<Limits>().bytes(),
            const { scope_metadata::<Limits>() }.bytes()
        );
    }
}
