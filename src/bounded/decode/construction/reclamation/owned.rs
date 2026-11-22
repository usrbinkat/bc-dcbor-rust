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
use crate::bounded::decode::construction::stable::{Pending, Ticket};
use crate::bounded::{
    Budget, Caller, Custodial, Performer, Places, ResourceBound, TerminalAllocator, Unit,
    WriteWork, widen,
};
use core::cell::Cell;

/// What the scope block's acquisition writes, whole: its queue and its
/// reference count, every field an atomic of the family `S`
/// ([`crate::sync`]): the build stores `Shipped`'s, and every contract
/// quantity reads `Core`'s ([`scope_contract`]).
struct ScopeHead<A: Allocator, S: Atomics = Shipped> {
    owner: Reclaimer<A, S>,
    references: S::Counter,
}

/// The scope block's value: its header, then its terminal dispatch and its
/// deferral, each written in an admitted unit of its own before any
/// reference is exposed. The header's unit is a whole quantum (a
/// `Reclaimer` of 40 bytes, the reference count, and the 16-byte permit), so
/// neither fits in it.
struct Scope<A: Allocator, S: Atomics = Shipped> {
    head: ScopeHead<A, S>,
    dispatch: MaybeUninit<Dispatch<A>>,
    deferral: MaybeUninit<Deferral<A, S>>,
}

type ScopeBlock<A, S = Shipped> = Held<Scope<A, S>, <A as crate::bounded::Releasing>::Permit>;

/// The scope's terminal dispatch ([`terminal`]): the one definition that
/// types it.
type Terminal<A> = unsafe fn(NonNull<ScopeBlock<A>>, &mut Worklist<A>);

/// What a reference that outlives the scope's authority reads of it,
/// written in one admitted unit before any reference is exposed: the
/// terminal dispatch that drains the scope once it is abandoned
/// ([`release_reference`]), and the identity of the owner the authority's
/// pending stores, under which the abandoned scope's custody is reported
/// ([`ScopeRef::observe_abandoned`]). Its size is the unit's write.
struct Dispatch<A: Allocator> {
    terminal: Terminal<A>,
    owner: Option<crate::bounded::Identity>,
}

// The dispatch is plain data, read by value; derived impls would bound `A`.
impl<A: Allocator> Clone for Dispatch<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Allocator> Copy for Dispatch<A> {}

/// The scope block's custody, its one enumeration, reported inside the open
/// group of the scope's owner: its permit, the scope block no record block;
/// then every record its queue holds, active and queued, each a group of
/// its own, nested, under the owner of the acquisition that allocated it
/// ([`Reclaimer::observe_custody`]). The queue is written whole with the
/// block's header, so it is observed whenever the block exists. Read by the
/// authority inside its own group ([`DecodeOwner`]'s traversal) and, once
/// the authority is dropped, by the references that keep the scope alive,
/// inside a group under the owner the dispatch unit stores
/// ([`ScopeRef::observe_abandoned`]).
fn scope_custody<A: Allocator>(
    block: &NonNull<ScopeBlock<A>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    // SAFETY: every holder of the pointer holds a counted reference, which
    // keeps the block live; its permit is written for the block's whole life
    // and only read.
    sink.permit(unsafe { block.as_ref() }.permit(), None);
    scope(block).owner.observe_custody(sink)
}

/// The scope's deferred releases: counted references released inside some
/// cleanup and not yet performed, and the link of the one worklist that
/// lists the scope while any are. The phases, as they run:
///
/// 1. Listed, before a batch: every deferred release is backed by a counted
///    reference it has not released, so `deferred <= references`, and a
///    listed scope holds at least the listing's own release (`deferred >= 1`).
/// 2. During a batch of `n - 1` ([`process`]): the count still includes the
///    releases the processor has already performed, at most `n - 1` of them,
///    so `deferred` may exceed `references`; the listing's retained release
///    is unperformed throughout the batch and the subtraction, so
///    `references >= 1` and the block stays allocated.
/// 3. After the compare-exchange from 1 to 0, the processor holds that one
///    reference until its final release, and touches nothing of the block
///    after it.
///
/// The count never wraps: at a batch's load `n <= references <=`
/// [`MAX_REFERENCES`], and until its subtraction the only additions are new
/// deferrals, each backed by a live counted reference, so at most
/// `MAX_REFERENCES` more: `deferred <=` [`MAX_DEFERRED`], below `usize::MAX`
/// on every target, which [`defer`] enforces as [`add_reference`] enforces
/// its own ceiling.
struct Deferral<A: Allocator, S: Atomics = Shipped> {
    /// The next listed scope. Accessed only between an increment of
    /// `deferred` from 0 to 1, whose thread pushes the scope, and the pop
    /// that follows it in that thread's frame (an append moves the node
    /// within the frame); no other thread pushes a scope whose count is not
    /// 0, and a processor never reads it after its pop.
    next: S::Cell<Option<NonNull<ScopeBlock<A>>>>,
    deferred: S::Counter,
}

impl<A: Allocator, S: Atomics> Representation for Deferral<A, S> {
    type In<F: Atomics> = Deferral<A, F>;
}

/// The scopes whose deferred releases one outermost frame performs once the
/// step it ran returns: an intrusive stack through each scope's own
/// [`Deferral`], on the frame, allocating nothing. Every inner frame (the
/// queue's step, a terminal drain, a reference's release) appends to the
/// list it is given and never processes it ([`with_worklist`]), so a chain
/// of scope drains is iterated at one stack depth. Typed by the allocator:
/// nested cleanup steps handles of its own allocator type only
/// ([`OwnedRecord::reclaim_under`]).
pub(crate) struct Worklist<A: Allocator> {
    head: Option<NonNull<ScopeBlock<A>>>,
}

impl<A: Allocator> Worklist<A> {
    pub(crate) const fn new() -> Self {
        Self { head: None }
    }

    /// List `block`, whose `next` this frame has exclusive access to
    /// ([`Deferral::next`]).
    fn push(&mut self, block: NonNull<ScopeBlock<A>>) {
        // SAFETY: the block is live (a deferred reference holds it) and its
        // link this frame's alone.
        unsafe { deferral(&block).next.set(self.head) };
        self.head = Some(block);
    }

    /// The most recently listed scope, unlinked: its link is not read again
    /// by this frame.
    fn pop(&mut self) -> Option<NonNull<ScopeBlock<A>>> {
        let block = self.head?;
        // SAFETY: as [`Self::push`].
        self.head = unsafe { deferral(&block).next.get() };
        Some(block)
    }

    /// Move every scope `other` lists into this list: a frame's step hands
    /// its deferrals outward.
    pub(crate) fn append(&mut self, other: &mut Self) {
        while let Some(block) = other.pop() {
            self.push(block);
        }
    }

    /// Perform every deferred release, iteratively, each listed scope by
    /// [`process`]; scopes its releases list are appended here and
    /// performed by this same loop.
    fn process(&mut self) {
        while let Some(block) = self.pop() {
            process(block, self);
        }
    }
}

/// Run `body` with an empty worklist, then perform every scope release it
/// deferred ([`Worklist::process`]) and return `body`'s result: the one
/// processing form every outermost frame uses, directly where a scope
/// reference ends outside any cleanup, and through
/// [`super::with_cleanup`] where a cleanup capability is minted. An unwind
/// out of `body` skips the processing: the listed references stay counted,
/// leaked, never released early.
pub(crate) fn with_worklist<A: Allocator, R>(body: impl FnOnce(&mut Worklist<A>) -> R) -> R {
    let mut worklist = Worklist::new();
    let result = body(&mut worklist);
    worklist.process();
    result
}

/// The scope's deferral, behind a counted reference.
fn deferral<A: Allocator>(block: &NonNull<ScopeBlock<A>>) -> &Deferral<A> {
    // SAFETY: every holder of the pointer holds a counted reference, which
    // keeps the block allocated, and references exist only once the
    // deferral's own unit has written it (`DecodeOwner::initialize_step`);
    // it is accessed only through atomics and its link's cell.
    unsafe { (*block.as_ptr()).value.deferral.assume_init_ref() }
}

/// Release one counted reference of `block` inside cleanup: moved into the
/// scope's deferral rather than decremented, and the drain trigger not run
/// ([`release_reference`]); the release whose increment takes the count
/// from 0 to 1 lists the scope in `worklist`. The reference stays counted
/// until the listing frame performs it ([`process`]).
fn defer<A: Allocator>(block: NonNull<ScopeBlock<A>>, worklist: &mut Worklist<A>) {
    let previous = deferral(&block).deferred.fetch_add(1, Ordering::AcqRel);
    // Past the ceiling the phases bound ([`Deferral`]), only leaked handles
    // can have released references: abort before the count could wrap.
    if previous >= MAX_DEFERRED {
        abort();
    }
    if previous == 0 {
        worklist.push(block);
    }
}

/// The most a scope's deferred count can reach ([`Deferral`]): every counted
/// reference deferred, plus as many new deferrals during one processor's
/// batch.
const MAX_DEFERRED: usize = 2 * MAX_REFERENCES;

/// Perform a popped scope's deferred releases, through the phases
/// [`Deferral`] states. The listing holds one of them
/// until the end: `n - 1` are performed and subtracted exactly, so a
/// concurrent deferral is neither lost nor repeated; once one remains, the
/// count is cleared by a compare-exchange from 1, and the retained release
/// is performed last, after which nothing of the block is touched (it may
/// have been the last reference). A deferral that takes the count from 0 to
/// 1 after the clear lists the scope in its own frame's worklist: the block
/// was popped before processing began, so its link is no longer this
/// frame's. Each release runs at this outer loop: a drain it triggers
/// claims the queue by its stepping swap and defers into this same list.
fn process<A: Allocator>(block: NonNull<ScopeBlock<A>>, worklist: &mut Worklist<A>) {
    loop {
        let deferred = deferral(&block).deferred.load(Ordering::Acquire);
        match deferred {
            // Phase 1: a listed scope holds at least the listing's release.
            0 => abort(),
            1 => {
                if deferral(&block)
                    .deferred
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }
            n => {
                for _ in 1..n {
                    release_reference(block, worklist);
                }
                deferral(&block).deferred.fetch_sub(n - 1, Ordering::AcqRel);
            }
        }
    }
    release_reference(block, worklist);
}

impl<A: Allocator, S: Atomics> Representation for ScopeHead<A, S> {
    type In<F: Atomics> = ScopeHead<A, F>;
}

impl<A: Allocator, S: Atomics> Representation for Scope<A, S> {
    type In<F: Atomics> = Scope<A, F>;
}

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
        let contract = const { scope_contract::<A>() };
        let block = widen(contract.block())?;
        // The header written, as `initialize_step` acquires it, and its
        // release, admitted with it; then the terminal dispatch and the
        // deferral, each its own admitted unit, read from the production
        // representation.
        let work = contract
            .write()
            .work()
            .checked_then(stable::release_cost::<A::Permit>().work())
            .and_then(|work| work.checked_then(Unit::written::<Dispatch<A>>(Caller).bound().work()))
            .and_then(|work| {
                work.checked_then(
                    Unit::written::<Deferral<A, crate::sync::Core>>(Caller)
                        .bound()
                        .work(),
                )
            })
            .ok_or(BoundedError::Overflow)?;
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

/// What the scope block's acquisition admits ([`stable::Contract`]): its
/// header, whole, and the permit, written in one unit, and its whole block;
/// read from the production representation, so the same in every build,
/// whatever atomics the build stores.
const fn scope_contract<A: Allocator>() -> stable::Contract<ScopeHead<A>, Scope<A>, A::Permit> {
    stable::Contract::of()
}

/// The production representation's scope write and block, read directly
/// from `Core`'s types and not through [`scope_contract`]: the oracle the
/// I3 witness (`crate::sync::models`) holds what a scope admits to in every
/// build.
#[cfg(test)]
pub(crate) fn production_scope<A: Allocator>() -> (usize, usize) {
    use crate::sync::Core;
    (
        core::mem::size_of::<ScopeHead<A, Core>>() + core::mem::size_of::<A::Permit>(),
        core::mem::size_of::<ScopeBlock<A, Core>>(),
    )
}

/// The I3 witness: a scope's initialization and a record's acquisition
/// admit exactly what their production representation holds, whatever
/// atomics the build stores. Their allocation requests are the production
/// blocks, in order, and their header writes the production headers with
/// their permits, against `size_of` read directly from `Core`'s types
/// ([`production_scope`], `production_record`), never through the contract
/// functions the admissions use. Run natively by this module's tests and,
/// inside a model, under each checker (`crate::sync::models`), where a
/// contract read from the build's own atomics fails it. Every check after
/// the run is a finding, and the run's session is concluded complete and
/// refined ([`Findings`]), inside the model when a model runs it, as
/// `crate::sync::models`' `drained` concludes its own.
#[cfg(test)]
pub(crate) fn admits_its_production_representation() {
    extern crate alloc;
    use crate::bounded::decode::construction::findings::{Expected, ExpectedHistory, Findings};
    use crate::bounded::{Call, Capacity, Limits, Session};
    use alloc::format;
    let session = Session::new(Capacity::DEFAULT);
    let mut m = Limits::recorded_unlimited(&session);
    let mut owner = DecodeOwner::<'static, Limits>::new();
    owner
        .initialize_step(&mut m)
        .expect("an unlimited policy admits the scope");
    let record = owner
        .allocate_step::<u64>(&mut m, &mut Acquisition::new())
        .expect("an unlimited policy admits a record");
    let (scope_write, scope_block) = production_scope::<Limits>();
    let (record_write, record_owner, record_block) = super::production_record::<u64, Limits>();
    let admitted = m.admitted_calls();
    let mut allocations = admitted.iter().filter_map(|call| match call {
        Call::Allocate(bytes) => Some(*bytes),
        Call::Work { .. } => None,
    });
    let mut findings = Findings::new();
    findings.equal(
        "the scope's allocation request is not its production block",
        allocations.next(),
        Some(scope_block as u64),
    );
    findings.equal(
        "the record's allocation request is not its production block",
        allocations.next(),
        Some(record_block as u64),
    );
    findings.equal("an allocation beyond the two", allocations.next(), None);
    // The scope's deferral, its own admitted unit, read directly from
    // `Core`'s representation.
    let deferral_write = core::mem::size_of::<Deferral<Limits, crate::sync::Core>>();
    for (what, write) in [
        ("scope", scope_write),
        ("scope deferral", deferral_write),
        ("record", record_write),
        ("record owner", record_owner),
    ] {
        findings.check(
            admitted.contains(&Call::Work {
                values: 1,
                bytes: write as u64,
            }),
            || {
                format!(
                    "the {what}'s header write of {write} production bytes was not admitted: \
                     {admitted:?}"
                )
            },
        );
    }
    drop(record);
    // The dropped record is the one queued.
    tests::shut_down_into(&mut findings, &mut owner, &mut m, 1);
    drop(owner);
    findings.policies([("m", m, ExpectedHistory::Readable)]);
    findings.conclude(&[("the I3 session", &session.finish(), Expected::Complete)]);
}

/// The scope's terminal dispatch, written into its block so a reference that
/// does not know the allocator's terminal policy can run it: the block's
/// queue drained with that policy ([`drain_terminally`]).
///
/// # Safety
/// The caller holds a counted reference to the initialized block, kept until
/// this returns, including through child retirement, so no recursive
/// reference release can free this scope beneath it.
unsafe fn terminal<A: crate::bounded::TerminalAllocator>(
    block: NonNull<ScopeBlock<A>>,
    worklist: &mut Worklist<A>,
) {
    // SAFETY: forwarded from the caller: the calling reference keeps the
    // initialized block, its header and its permit live.
    let permit = unsafe { block.as_ref().permit() };
    drain_terminally::<A>(scope(&block), permit, worklist);
}

/// Run the queue's state machine with an allocation-free terminal policy
/// over the scope's own permit, until the queue reports `Done` or `Waiting`.
/// A drain that fails, or unwinds, aborts: a terminal drain cannot report.
/// Every scope reference its records release is deferred into `worklist`,
/// the outermost frame's: a chain of drains is iterated there, never nested
/// here.
fn drain_terminally<A: crate::bounded::TerminalAllocator>(
    head: &ScopeHead<A>,
    permit: &A::Permit,
    worklist: &mut Worklist<A>,
) {
    let guard = AbortOnUnwind;
    #[cfg(all(test, feature = "std"))]
    DRAINS.with(|drains| {
        let (active, most) = drains.get();
        // The nesting oracle, in every test that reaches a drain: a drain
        // begun inside another is the recursion the worklist excludes, which
        // an implicit drop of a scope reference inside a step (no syntactic
        // site the census can list) would cause. Named, then aborted, unless
        // a witness measuring the nesting disarmed it ([`drains_nested`]).
        if active > 0 && !NESTING_DISARMED.with(core::cell::Cell::get) {
            std::eprintln!("a terminal drain began inside another");
            abort();
        }
        drains.set((active + 1, most.max(active + 1)));
    });
    let mut policy = A::terminal(permit);
    loop {
        match head.owner.shutdown_step(&mut policy, worklist) {
            Ok(Reclaimed::Progress) => {}
            Ok(Reclaimed::Done | Reclaimed::Waiting) => break,
            Err(_) => abort(),
        }
    }
    drop(policy);
    #[cfg(all(test, feature = "std"))]
    DRAINS.with(|drains| {
        let (active, most) = drains.get();
        drains.set((active - 1, most));
    });
    core::mem::forget(guard);
}

// The build's threads' own locals ([`crate::sync::thread_locals`]): under a
// checker its model threads share one OS thread, so a std local would count
// another model thread's drain as nested in this one's.
#[cfg(all(test, feature = "std"))]
crate::sync::thread_locals! {
    /// The terminal drains active on this thread and the most ever nested
    /// since the last [`drains_nested`]: the measurement of the worklist's
    /// claim that a drain never runs inside another. Test builds only; no
    /// shipped code keeps it.
    static DRAINS: core::cell::Cell<(usize, usize)> = core::cell::Cell::new((0, 0));
    /// The nesting oracle disarmed, while a witness measures the nesting
    /// itself and reports it as its own finding ([`drains_nested`]).
    static NESTING_DISARMED: core::cell::Cell<bool> = core::cell::Cell::new(false);
}

/// The most terminal drains `run` nests on this thread at once, the nesting
/// oracle in `drain_terminally` disarmed meanwhile, so the caller's finding
/// names an excess instead of the oracle's abort.
#[cfg(all(test, feature = "std"))]
fn drains_nested(run: impl FnOnce()) -> usize {
    DRAINS.with(|drains| drains.set((0, 0)));
    let armed = NESTING_DISARMED.with(|disarmed| disarmed.replace(true));
    run();
    NESTING_DISARMED.with(|disarmed| disarmed.set(armed));
    DRAINS.with(|drains| drains.get().1)
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

/// Release one counted reference of `block` at an outer frame, outside any
/// cleanup step: the drain trigger, then the decrement. A release inside a
/// cleanup step is deferred instead ([`defer`]). Every reference a drain run
/// here releases is deferred into `worklist`, performed by the caller's
/// loop.
fn release_reference<A: Allocator>(block: NonNull<ScopeBlock<A>>, worklist: &mut Worklist<A>) {
    let state = scope(&block);
    if state.owner.abandoned.load(Ordering::Acquire)
        && !state.owner.stepping.load(Ordering::Acquire)
    {
        // SAFETY: references are exposed only after terminal initialization,
        // so the dispatch is written; this counted reference keeps the block
        // allocated and remains counted throughout the drain.
        unsafe { ((*block.as_ptr()).value.dispatch.assume_init().terminal)(block, worklist) };
    }
    if scope(&block).references.fetch_sub(1, Ordering::AcqRel) == 1 {
        // SAFETY: this was the last reference.
        release_last(unsafe { LastReference::new(block) }, worklist);
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
fn release_last<A: Allocator>(last: LastReference<A>, worklist: &mut Worklist<A>) {
    let block = last.block;
    if scope(&block).owner.outstanding() != 0 {
        // The drain holds a counted reference while it runs, as every
        // terminal drain does; no other holder can observe it.
        scope(&block).references.store(1, Ordering::Relaxed);
        // SAFETY: references are exposed only after terminal initialization,
        // so the dispatch is written; this function, holding the last
        // reference, keeps the block allocated until it frees it.
        unsafe { ((*block.as_ptr()).value.dispatch.assume_init().terminal)(block, worklist) };
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

    /// The custody of the scope this reference keeps alive once its
    /// authority was dropped: the scope's one enumeration ([`scope_custody`])
    /// under the owner its dispatch unit stores, held jointly by every live
    /// reference and so reported as shared custody, once per observation,
    /// by whichever holder the sink lets report it ([`CustodySink::shared`]).
    /// While the authority lives its own traversal reports the scope, and
    /// this reports nothing.
    pub(crate) fn observe_abandoned(
        &self,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        if !self.owner().abandoned.load(Ordering::Acquire) {
            return PermitsObserved::Complete;
        }
        // SAFETY: this counted reference keeps the block live, and references
        // exist only once the dispatch unit was written; the permit is
        // written for the block's whole life, and both are only read.
        let (permit, dispatch) = unsafe {
            let block = self.scope.as_ref();
            (
                A::permit_identity(block.permit()),
                block.value.dispatch.assume_init(),
            )
        };
        if !sink.shared(permit) {
            return PermitsObserved::Complete;
        }
        sink.begin(dispatch.owner);
        let custody = scope_custody(&self.scope, sink);
        sink.end();
        custody
    }

    /// One step of allocating one record in this scope, in two stages of one
    /// acquisition, each retried alone after a refusal: the head, its
    /// admissions held, with their origins, in `acquisition`'s own pending
    /// credit, outside the record being acquired, every entry validated
    /// against the token's owner ([`Pending::bind`]), its granted block then
    /// held by the token; and the owner stage, the identity of the owner the
    /// token's pending stores written into the block in an admitted unit of
    /// its own ([`Reclaimer::own`]). Only then is the record handle made, so
    /// no handle, published value or queued record exists without its owner
    /// association.
    pub(crate) fn allocate_step<T: Reclaim<A> + Send + 's>(
        &self,
        a: &mut A,
        acquisition: &mut Acquisition<'s, T, A>,
    ) -> BoundedResult<OwnedRecord<'s, T, A>, A>
    where
        A: TerminalAllocator,
        T::State: Send,
    {
        if let Some(bound) = &acquisition.scope {
            if bound.scope != self.scope {
                return Err(BoundedError::PlanMismatch);
            }
        } else {
            acquisition.scope = Some(self.duplicate());
        }
        let block = match acquisition.granted {
            Some(block) => block,
            None => {
                // SAFETY: T outlives 's, and neither the owner nor any handle
                // of this scope can outlive 's, so every borrow in T outlives
                // final cleanup.
                let block = unsafe {
                    self.owner().allocate::<T>(
                        a,
                        &mut acquisition.pending,
                        &mut acquisition.holder,
                    )?
                };
                acquisition.granted = Some(block);
                block
            }
        };
        // The pending's owner was made by the head stage's first entry and
        // is never replaced.
        let owner = acquisition
            .pending
            .owner_id()
            .ok_or(BoundedError::PlanMismatch)?;
        // SAFETY: the block came from this scope's `allocate`, its owner
        // stage not yet made (the token clears `granted` only here), and the
        // token holds it exclusively.
        let record = core::mem::ManuallyDrop::new(unsafe { self.owner().own(block, owner, a)? });
        // Owned: the acquisition ended, nothing held.
        acquisition.granted = None;
        acquisition.scope = None;
        Ok(OwnedRecord {
            block: record.block,
            scope: self.duplicate(),
            marker: PhantomData,
        })
    }
}

impl<'s, A: Allocator> ScopeRef<'s, A> {
    /// End this reference inside a cleanup step: deferred into the step's
    /// worklist ([`defer`]), performed by the frame that minted the step's
    /// capability. Every site ending a scope reference inside cleanup ends it
    /// here, never through `Drop`, which would release it in place.
    pub(crate) fn defer(self, worklist: &mut Worklist<A>) {
        let block = core::mem::ManuallyDrop::new(self).scope;
        defer(block, worklist);
    }
}

/// A reference ended outside any cleanup step: released at this outermost
/// frame, a drain it triggers and every release that drain defers performed
/// here ([`with_worklist`]).
impl<A: Allocator> Drop for ScopeRef<'_, A> {
    fn drop(&mut self) {
        with_worklist(|worklist| release_reference(self.scope, worklist));
    }
}

/// Opaque retained admission for one record allocation, bound to its payload
/// type and owning scope. Dropping an unfinished token cancels acquisition
/// without allocating or destroying a payload. Success resets it for reuse.
///
/// The token is the custody of the credit used to obtain its record, which
/// therefore stays outside the record it acquires: its admissions toward a
/// record not yet granted are held in its own pending credit
/// ([`Pending`]), each obligation keeping the origin and identity its
/// admission gave it, so a write admitted under one family and a release,
/// after a refused request, under another each settle into their own
/// family, under one acquisition identity. Its owner is made by its first
/// acquisition entry ([`Pending::deferred`]), every later entry validated
/// against it. Cancelled ([`Self::cancel`]) or dropped holding credit, the
/// token settles it explicitly by origin, [`crate::bounded::Forfeit::Cancelled`];
/// its grant and its cancel leave nothing held and the token unbound, ready
/// for reuse.
///
/// Between a record's two acquisition stages ([`ScopeRef::allocate_step`])
/// the token also holds the granted block, its head written and its owner
/// not yet: the block is the acquisition's, reported in the token's group,
/// and a cancel or drop then frees it without reading its owner
/// ([`Reclaimer::release_unowned`]), a release its acquisition paid for.
pub struct Acquisition<'s, T: Reclaim<A>, A: TerminalAllocator> {
    scope: Option<ScopeRef<'s, A>>,
    pending: Pending<A::Origin>,
    holder: Option<Ticket>,
    /// The block granted by the head stage, until its owner stage makes it
    /// a record; `Some` only while `scope` is bound to the block's scope.
    granted: Option<NonNull<Block<T, A>>>,
    marker: InvariantOwned<T>,
}

// SAFETY: the token exclusively owns its granted block, a payload state
// (`T::State`, initial) and a permit, as a record handle owns its block
// (`OwnedRecord`'s `Send`); its pending credit and scope reference are `Send`
// as the operation's own fields are.
unsafe impl<T: Reclaim<A> + Send, A: TerminalAllocator> Send for Acquisition<'_, T, A>
where
    T::State: Send,
    A::Permit: Send,
    Pending<A::Origin>: Send,
{
}
// SAFETY: the `&self` methods (`held_credit`) read the pending credit alone;
// the granted block is reached only through `&mut self` (`observe_custody`,
// `cancel`, the allocation step) or by drop.
unsafe impl<T: Reclaim<A>, A: TerminalAllocator> Sync for Acquisition<'_, T, A>
where
    A::Permit: Send,
    Pending<A::Origin>: Sync,
{
}

impl<T: Reclaim<A>, A: TerminalAllocator> Acquisition<'_, T, A> {
    pub const fn new() -> Self {
        Self {
            scope: None,
            pending: Pending::deferred(),
            holder: None,
            granted: None,
            marker: PhantomData,
        }
    }

    /// The credit this token holds toward a record not yet granted: its
    /// pending's ([`Pending::held_credit`]), the token's one holder of
    /// obligations. Allocation-free. `None` when the sum does not fit.
    pub fn held_credit(&self) -> Option<WriteWork> {
        self.pending.held_credit()
    }

    /// The owner this token's acquisitions are bound under, the owner every
    /// record it acquires stores, once its first acquisition entry made it
    /// ([`Pending::deferred`]); `None` before. A custom binding acquires its
    /// payload's storage under it ([`crate::bounded::Owned::reserve`]), so
    /// the record's group, which reports the payload's permits under the
    /// record's owner ([`Reclaim::observe_permits`]), reports them under the
    /// owner that acquired them: the association the crate's own bindings
    /// make through the operation's acquisition custody ([`Self::pending`]).
    /// Read-only, minting nothing.
    pub fn owner(&self) -> Option<&crate::bounded::Owner> {
        self.pending.owner_ref()
    }

    /// The token's pending custody, for the operation's task once its record
    /// is owned ([`super::super::operation::Task::advance`]): the one
    /// acquisition custody of the operation, its owner the record's, so the
    /// acquisitions a task binds on it share the record's owner association
    /// and are settled with the token's ([`Self::cancel`]).
    pub(crate) fn pending(&mut self) -> &mut Pending<A::Origin> {
        &mut self.pending
    }

    /// Free a block granted and never owned, if the token holds one: the
    /// cleanup of an acquisition stopped between its two stages.
    fn release_granted(&mut self) {
        if let Some(block) = self.granted.take() {
            // A granted block is held only while the token is bound to its
            // scope (`granted`'s invariant): an unbound one is a defect that
            // cannot be reported from a drop.
            let Some(scope) = self.scope.as_ref() else {
                abort()
            };
            // SAFETY: the block came from this scope's `allocate`, its owner
            // stage never made, held exclusively by the token and dropped
            // from it above; its payload state is the initial one.
            unsafe { scope.owner().release_unowned(block) };
        }
    }

    /// Abandon the acquisition: everything it holds is forfeited
    /// ([`crate::bounded::Forfeit::Cancelled`]) into the family that admitted
    /// each obligation, `by` the performer; a block granted and not yet
    /// owned is freed, its release prepaid; and the token is reset for
    /// reuse, bound to no scope, so a later cancel or drop settles nothing
    /// again. Nothing is admitted and nothing can refuse.
    /// An outermost frame: its scope reference released here
    /// ([`with_worklist`]).
    pub fn cancel(&mut self, by: Performer) {
        with_worklist(|worklist| self.cancel_into(by, worklist));
    }

    /// [`Self::cancel`] inside a cleanup step (an operation's cleanup), its
    /// scope reference deferred into `worklist`, the step's; the one
    /// implementation of cancelling.
    pub(crate) fn cancel_into(&mut self, by: Performer, worklist: &mut Worklist<A>) {
        self.pending.settle_all(by);
        self.holder = None;
        self.release_granted();
        if let Some(scope) = self.scope.take() {
            scope.defer(worklist);
        }
    }
}

/// The token's custody, one group under the owner its pending stores (`None`
/// before its first entry made it, when it holds nothing): its pending's
/// obligations toward a record not yet granted, as the pending's own group
/// ([`Pending::observe_custody`]), and, between the record's two stages, the
/// granted block's permit. Read-only.
impl<T: Reclaim<A>, A: TerminalAllocator> Custodial<A::Permit> for Acquisition<'_, T, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        sink.begin(self.pending.owner_id());
        let pending = self.pending.observe_custody(sink);
        if let Some(block) = self.granted {
            // SAFETY: the token holds its granted block exclusively, live
            // until its owner stage or its release; its permit is written
            // before the block is granted and only read. A record block
            // granted to the token, not yet a record.
            sink.permit(
                unsafe { block.as_ref() }.permit(),
                Some(crate::bounded::RecordStage::Granted),
            );
        }
        sink.end();
        let shared = self
            .scope
            .as_ref()
            .map_or(PermitsObserved::Complete, |scope| {
                scope.observe_abandoned(sink)
            });
        observed_all([pending, shared])
    }
}

impl<T: Reclaim<A>, A: TerminalAllocator> Drop for Acquisition<'_, T, A> {
    /// Settle what the token still holds explicitly, by origin, with no
    /// performing policy, and free a block granted and not yet owned; a
    /// token owned or cancelled holds nothing, so nothing is settled or
    /// freed twice. Its scope reference is released after, at this frame.
    fn drop(&mut self) {
        self.cancel(Performer::None);
    }
}

impl<T: Reclaim<A>, A: TerminalAllocator> Default for Acquisition<'_, T, A> {
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
///
/// Admissions a refused initialization holds toward a scope block not yet
/// granted are held credit ([`Self::held_credit`]), in the authority's own
/// pending credit ([`Pending`]), outside the block it acquires: each
/// obligation keeps the origin and identity its admission gave it, so a
/// write admitted under one family and a release, on a retry, under another
/// each settle into their own family. Its owner is made by its first
/// initialization entry ([`Pending::deferred`]), every later entry validated
/// against it. Shut down ([`Self::shutdown_step`]) or dropped holding
/// credit, the authority settles it explicitly by origin,
/// [`crate::bounded::Forfeit::Cancelled`].
pub struct DecodeOwner<'s, A: TerminalAllocator> {
    scope: Option<NonNull<ScopeBlock<A>>>,
    pending: Pending<A::Origin>,
    holder: Option<Ticket>,
    /// Terminal: shutdown completed. A closed authority never acquires a new
    /// scope, so shutdown cannot be undone by a later initialization.
    closed: bool,
    /// The terminal dispatch's unit is written: a refusal of the deferral's
    /// unit after it retries the deferral alone.
    dispatch: bool,
    ready: bool,
    lifetime: Lifetime<'s>,
}

// SAFETY: the authority's own fields (`scope`, `pending`, `holder`,
// `closed`, `ready`) are values it exclusively owns, its pending credit
// `Send` as every origin and owner is; the scope block it points to is
// shared state reached only as for `ScopeRef`, so moving the authority to
// another thread moves only those values.
unsafe impl<A: TerminalAllocator> Send for DecodeOwner<'_, A> where A::Permit: Send {}
// SAFETY: through `&DecodeOwner` the methods are `position`, `outstanding`,
// `held_credit`, `reference`, `allocate_step` and `step`. They read the
// authority's own fields without writing them (only `initialize_step`,
// `shutdown_step` and `Drop` change `pending`, through `&mut self` or
// ownership; `held_credit` reads it, every origin and owner `Sync`), and
// reach the scope block only
// through `scope`, whose shared access is the atomics and the
// `stepping`-guarded fields `ScopeRef`'s `Sync` argument covers. Concurrent
// `step` calls are serialized by the `stepping` flag: the loser performs and
// admits nothing and returns `Waiting`.
unsafe impl<A: TerminalAllocator> Sync for DecodeOwner<'_, A> where A::Permit: Send {}

impl<A: TerminalAllocator> Default for DecodeOwner<'_, A> {
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

impl<'s, A: TerminalAllocator> DecodeOwner<'s, A> {
    pub const fn new() -> Self {
        Self {
            scope: None,
            pending: Pending::deferred(),
            holder: None,
            closed: false,
            dispatch: false,
            ready: false,
            lifetime: PhantomData,
        }
    }

    /// Admit and allocate the scope's queue and reference count, then admit
    /// its terminal dispatch write. The block's admissions are held in the
    /// authority's pending credit with their origins ([`stable::acquire`]),
    /// every entry, a retry included, validated against its owner. A refusal
    /// retains what was admitted for the next call. Once `Ok`, later calls
    /// do nothing and return `Ok`. A closed authority refuses with
    /// `PlanMismatch`.
    pub fn initialize_step(&mut self, a: &mut A) -> BoundedResult<(), A> {
        if self.closed {
            return Err(BoundedError::PlanMismatch);
        }
        if self.ready {
            return Ok(());
        }
        if self.scope.is_none() {
            let (pending, holder) = (&mut self.pending, &mut self.holder);
            // SAFETY: the header, the queue and reference count, is written
            // whole at its field; the terminal dispatch is MaybeUninit until
            // the final admitted write.
            let acquired = at(ScopePlace::Initialization, || unsafe {
                stable::acquire::<Scope<A>, ScopeHead<A>, A>(
                    const { scope_contract::<A>() },
                    pending,
                    holder,
                    || true,
                    || ScopeHead {
                        owner: Reclaimer::new(),
                        references: AtomicUsize::new(1),
                    },
                    |scope| ptr::addr_of_mut!((*scope).head),
                    a,
                )
            });
            self.scope = Some(acquired?);
        }
        let block = self.scope.ok_or(BoundedError::PlanMismatch)?;
        if !self.dispatch {
            // The owner the header's acquisition made, never replaced.
            let owner = self.pending.owner_id();
            // SAFETY: no reference is exposed until both of these fields are
            // initialized. Refusal leaves the empty scope retained for
            // initialization or Drop.
            at(ScopePlace::Initialization, || unsafe {
                crate::bounded::decode::initialization::field(
                    ptr::addr_of_mut!((*block.as_ptr()).value.dispatch),
                    || {
                        MaybeUninit::new(Dispatch {
                            terminal: terminal::<A> as Terminal<A>,
                            owner,
                        })
                    },
                    a,
                )
            })?;
            self.dispatch = true;
        }
        // The deferral, the last field, written whole by its own admitted
        // unit, no scope listed and nothing deferred. Its unit is read from
        // the production representation (`Core`'s atomics), as the header's
        // is, so it is the same in every build ([`ScopeTerms::of`]).
        at(ScopePlace::Initialization, || {
            const { Unit::written::<Deferral<A, crate::sync::Core>>(Caller) }.admit(a)
        })?;
        // SAFETY: as above: the field lies in the block this authority
        // holds, no reference exists yet, and the write was admitted.
        unsafe {
            ptr::addr_of_mut!((*block.as_ptr()).value.deferral).write(MaybeUninit::new(Deferral {
                next: Plain::new(None),
                deferred: AtomicUsize::new(0),
            }));
        }
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

    /// The credit the authority holds toward a scope block not yet granted
    /// ([`crate::bounded::Obligation`]), held across a refused
    /// initialization and spent by the retry's grant, or forfeited by
    /// [`Self::shutdown_step`]: its pending's ([`Pending::held_credit`]),
    /// the authority's one holder of obligations; the scope's records'
    /// credit is their acquisitions'. `None` when the sum does not fit.
    pub fn held_credit(&self) -> Option<WriteWork> {
        self.pending.held_credit()
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
    ///
    /// A record is acquired in two admitted units of at most a quantum each:
    /// its header, its state and the permit, read from the production
    /// representation in every build, then its owner's identity. A binding
    /// whose state does not fit the first fails to compile where it is
    /// allocated:
    /// ```compile_fail,E0080
    /// use dcbor::bounded::decode::construction::reclamation::{
    ///     Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot,
    /// };
    /// use dcbor::bounded::decode::construction::{Acquisition, DecodeOwner};
    /// use dcbor::bounded::{BoundedResult, CustodySink, Limits, PermitsObserved, Reservation};
    /// struct Wide;
    /// struct Words([u64; 8]);
    /// impl Custody for Words {
    ///     type Observation = u64;
    ///     fn observe(&mut self) -> u64 {
    ///         self.0[0]
    ///     }
    /// }
    /// // SAFETY: the binding owns nothing; its one cleanup unit is `Done`.
    /// unsafe impl Reclaim<Limits> for Wide {
    ///     type State = Words;
    ///     const INITIAL: Words = Words([0; 8]);
    ///     fn reclaim_step(
    ///         _: Slot<'_, Self, Words>,
    ///         _: &mut Cleanup<'_, Limits>,
    ///     ) -> BoundedResult<Reclaimed, Limits> {
    ///         Ok(Reclaimed::Done)
    ///     }
    ///     fn remaining(_: PeekSlot<'_, Self, Words>) -> Option<u64> {
    ///         Some(1)
    ///     }
    ///     fn observe_permits(
    ///         _: PeekSlot<'_, Self, Words>,
    ///         _: &mut dyn CustodySink<Reservation>,
    ///     ) -> PermitsObserved {
    ///         PermitsObserved::Complete
    ///     }
    /// }
    /// let mut m = Limits::unlimited();
    /// let mut owner = DecodeOwner::<'static, Limits>::new();
    /// owner.initialize_step(&mut m).unwrap();
    /// let _ = owner.allocate_step::<Wide>(&mut m, &mut Acquisition::new());
    /// ```
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
    /// An outermost frame: the scope releases the step defers are performed
    /// before it returns ([`with_worklist`]).
    pub fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        match &self.scope {
            Some(block) => with_worklist(|worklist| scope(block).owner.step(a, worklist)),
            None => Ok(Reclaimed::Done),
        }
    }

    /// Close allocation and perform one unit of shutdown. Done only after
    /// every record and the scope block itself have been released.
    pub fn shutdown_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let Some(block) = self.scope else {
            // A scope block never granted: the admissions a refused
            // initialization held are forfeited as the authority closes,
            // each into the family that admitted it, under this step's
            // performer.
            self.pending.settle_all(a.performer());
            self.holder = None;
            self.closed = true;
            return Ok(Reclaimed::Done);
        };
        // The releases the step defers are performed before the reference
        // check below, so it reads the settled count: a deferral made inside
        // this step costs no extra shutdown call.
        match with_worklist(|worklist| scope(&block).owner.shutdown_step(a, worklist))? {
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

/// The scope's custody, one traversal: the authority's own group, under the
/// owner its pending stores (`None` before its first initialization entry
/// made it, when it holds nothing), its pending's obligations toward a scope
/// block not yet granted as the pending's own group
/// ([`Pending::observe_custody`]) and the scope block's permit; then, once
/// the scope is ready, every record its queue holds, active and queued, each
/// a group under the owner of the acquisition that allocated it
/// ([`Reclaimer::observe_custody`]). Records still held by their handles are
/// their handles' to report. `Contended` when another caller is stepping the
/// queue: its records were not walked, and the observation is not whole.
/// The traversal reads the authority only (its pending credit, the block's
/// permit, written for the block's whole life, and the queue's atomics), so
/// it is defined on a shared borrow: an authority lent to the operations it
/// serves, which share it through `&DecodeOwner` as every acquisition and
/// queue step does, is observed through the borrow they share.
impl<A: TerminalAllocator> Custodial<A::Permit> for &DecodeOwner<'_, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        sink.begin(self.pending.owner_id());
        let pending = self.pending.observe_custody(sink);
        // The authority's counted reference keeps its block live.
        let scope = self
            .scope
            .as_ref()
            .map_or(PermitsObserved::Complete, |block| {
                scope_custody(block, sink)
            });
        sink.end();
        observed_all([pending, scope])
    }
}

/// An owned authority's custody: its shared borrow's traversal.
impl<A: TerminalAllocator> Custodial<A::Permit> for DecodeOwner<'_, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        <&Self as Custodial<A::Permit>>::observe_custody(&mut &*self, sink)
    }
}

impl<A: TerminalAllocator> Drop for DecodeOwner<'_, A> {
    /// Admissions held toward a scope block never granted are settled
    /// explicitly by origin, with no performing policy; an initialized scope
    /// is abandoned to its references' terminal drain, a partially
    /// initialized one freed.
    fn drop(&mut self) {
        self.pending.settle_all(Performer::None);
        if let Some(block) = self.scope.take() {
            if self.ready {
                scope(&block).owner.closed.store(true, Ordering::Release);
                scope(&block).owner.abandoned.store(true, Ordering::Release);
                with_worklist(|worklist| release_reference(block, worklist));
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
    /// The public entry: the cleanup capability is minted here over `a`
    /// ([`Self::reclaim_under`]).
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        with_cleanup(a, |cleanup| Self::reclaim_under(slot, cleanup))
    }

    /// [`Self::reclaim_step`] under `cleanup`, a capability already minted:
    /// how a cleanup that holds this handle steps it, the crate's own records
    /// (an operation's record, a construction's document or input) and a
    /// third-party binding whose state holds the handle ([`Reclaim`]) alike.
    /// The capability grants no allocation, so stepping a nested handle
    /// requests no new allocation either. Supported: a handle of another
    /// scope of the same allocator type, its scope reference deferred into
    /// the step's worklist at `Done` and released by the minting frame.
    /// Unsupported: a handle of another allocator type, which no
    /// `Cleanup<'_, A>` reaches, as no `&mut A` reached it before.
    pub fn reclaim_under(
        slot: &mut Option<Self>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        // An empty slot was released or moved out earlier; a caller stepping
        // its phase through it still admits the completion reported here.
        let Some(current) = slot.as_ref() else {
            EMPTIED.admit(cleanup)?;
            return Ok(Reclaimed::Done);
        };
        let mut held = Some(Record {
            block: current.block,
            owner: current.scope.owner(),
            marker: PhantomData::<(T, fn(T) -> T)>,
        });
        let result = Record::reclaim_step(&mut held, cleanup);
        let released = held.is_none();
        // While the block is not released the slot still owns it, so this
        // temporary view must not transfer it to the queue. Forgetting the
        // emptied view after release is a no-op.
        core::mem::forget(held);
        if released {
            let handle =
                core::mem::ManuallyDrop::new(slot.take().ok_or(BoundedError::PlanMismatch)?);
            // SAFETY: `handle` is never dropped, so its scope reference is read
            // out exactly once and ended here, inside cleanup: deferred into
            // the step's worklist, never released in place.
            unsafe { ptr::read(&handle.scope) }.defer(cleanup.worklist());
        }
        result
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`: an empty
    /// slot, one; otherwise the record's own ([`Reclaim::remaining`]), the
    /// last of which also releases the block. `None` when the record's count
    /// does not fit in `u64`. What a binding holding the handle adds to its
    /// own [`Reclaim::remaining`].
    pub fn remaining(slot: &mut Option<Self>) -> Option<u64> {
        let Some(current) = slot.as_mut() else {
            return Some(1);
        };
        T::remaining(current.destination().into_observe())
    }
}

/// The record's custody, one group under the owner its entry stores, the
/// owner of the acquisition that allocated it: its block's permit and its
/// payload's custody ([`Record::observe_custody`]), the same observation the
/// queue makes of it once retired. Read-only.
impl<T: Reclaim<A>, A: Allocator> Custodial<A::Permit> for OwnedRecord<'_, T, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        // SAFETY: the handle has exclusive custody of its live block, a
        // record (its owner stage made before the handle existed), for the
        // borrow.
        let record = unsafe { Record::<T, A>::observe_custody(self.block, sink) };
        observed_all([record, self.scope.observe_abandoned(sink)])
    }
}

/// The published record's custody, its record's ([`OwnedRecord`]'s
/// traversal), under the owner of the acquisition that allocated it;
/// `&mut self` excludes every reader of the value meanwhile. Read-only.
impl<T: Reclaim<A>, A: Allocator> Custodial<A::Permit> for OwnedInitialized<'_, T, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        self.record.observe_custody(sink)
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

    /// Operation-local cleanup of a published value ([`OwnedRecord::reclaim_step`]),
    /// the cleanup capability minted here over `a`.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        with_cleanup(a, |cleanup| Self::reclaim_under(slot, cleanup))
    }

    /// [`Self::reclaim_step`] under `cleanup`, a capability already minted
    /// ([`OwnedRecord::reclaim_under`]): how a cleanup holding this handle,
    /// the crate's or a third-party binding's, steps it.
    pub fn reclaim_under(
        slot: &mut Option<Self>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            cleanup,
            |Self { record }| record,
            |record| Self { record },
            OwnedRecord::reclaim_under,
        )
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedRecord::remaining`]).
    pub fn remaining(slot: &mut Option<Self>) -> Option<u64> {
        let mut record = slot.take().map(|Self { record }| record);
        let remaining = OwnedRecord::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }
}

#[cfg(test)]
mod tests {
    // The findings name their checks in every build, `no_std` included.
    extern crate alloc;

    use super::*;
    use crate::bounded::Limits;
    use crate::bounded::decode::construction::findings::{Expected, ExpectedHistory, Findings};
    use alloc::format;

    /// A recorded policy, its history read against its counters.
    const READ: ExpectedHistory = ExpectedHistory::Readable;

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
        with_worklist(|worklist| release_last(unsafe { LastReference::new(block) }, worklist));
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
        let mut m = Limits::unlimited();
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

    /// FF-13's premise that workers are interchangeable, which the models'
    /// claims beyond the worker counts they explore rest on: no thread's
    /// identity enters the protocol, so which thread performs an operation
    /// changes nothing it admits, reports or leaves. Six operations (two
    /// allocations, two retirements, two steps), each on the main thread or
    /// on a thread of its own, in every one of the 64 assignments and in the
    /// same order: the admitted calls, every position and every step's
    /// result equal the run on the main thread alone. The census holds the
    /// structural half: the protocol's state is its atomics family's
    /// primitives alone, and no shipped code names a thread
    /// (`tests/unsafe_census.rs`).
    #[cfg(feature = "std")]
    #[test]
    fn which_thread_performs_an_operation_changes_nothing() {
        use crate::bounded::Call;
        use std::vec::Vec;
        const OPERATIONS: u32 = 6;
        fn on<R: Send>(spawned: bool, operation: impl FnOnce() -> R + Send) -> R {
            if spawned {
                std::thread::scope(|threads| {
                    threads
                        .spawn(operation)
                        .join()
                        .expect("an operation's thread panicked")
                })
            } else {
                operation()
            }
        }
        fn run(placement: u32) -> (Vec<Call>, Vec<ScopePosition>, Vec<Reclaimed>) {
            let spawned = |operation: u32| placement & (1 << operation) != 0;
            let session = crate::bounded::Session::new(crate::bounded::Capacity::DEFAULT);
            let mut m = Limits::recorded_unlimited(&session);
            let mut owner = DecodeOwner::<'static, Limits>::new();
            owner.initialize_step(&mut m).unwrap();
            let mut positions = Vec::new();
            let mut steps = Vec::new();
            let first = on(spawned(0), || {
                owner
                    .allocate_step::<u64>(&mut m, &mut Acquisition::new())
                    .unwrap()
            });
            let second = on(spawned(1), || {
                owner
                    .allocate_step::<u64>(&mut m, &mut Acquisition::new())
                    .unwrap()
            });
            positions.push(owner.position());
            on(spawned(2), || drop(first));
            positions.push(owner.position());
            steps.push(on(spawned(3), || owner.step(&mut m).unwrap()));
            positions.push(owner.position());
            on(spawned(4), || drop(second));
            positions.push(owner.position());
            steps.push(on(spawned(5), || owner.step(&mut m).unwrap()));
            positions.push(owner.position());
            loop {
                let step = owner.shutdown_step(&mut m).unwrap();
                steps.push(step);
                if step == Reclaimed::Done {
                    break;
                }
                assert!(steps.len() < 32, "the scope did not shut down");
            }
            assert_eq!(m.live_bytes(), 0, "the record or the scope was kept");
            let admitted = m.admitted_calls();
            // The run's session concluded complete and refined, once the
            // scope's authority and the policy are gone.
            drop(owner);
            let mut findings = Findings::new();
            findings.policies([("m", m, READ)]);
            findings.conclude(&[(
                "the placement's session",
                &session.finish(),
                Expected::Complete,
            )]);
            (admitted, positions, steps)
        }
        let local = run(0);
        for placement in 1..(1 << OPERATIONS) {
            assert_eq!(run(placement), local, "placement {placement:06b}");
        }
    }

    /// The grant's work (its write) and the release of a block of
    /// `contract`, with permits of `Limits`: what an acquisition of it holds
    /// once each is admitted, read from the contract the acquisition admits.
    fn obligations<W, M>(
        contract: stable::Contract<W, M, crate::bounded::Reservation>,
    ) -> (WriteWork, WriteWork) {
        (
            contract.grant(),
            stable::release_credit::<crate::bounded::Reservation>(),
        )
    }

    /// The work of a `u64` record's grant (its write) and of its release.
    fn record_obligations() -> (WriteWork, WriteWork) {
        obligations(const { super::super::contract::<u64, Limits>() })
    }

    /// The work of a scope block's grant (its write) and of its release.
    fn scope_obligations() -> (WriteWork, WriteWork) {
        obligations(const { scope_contract::<Limits>() })
    }

    /// What a token holding `admitted` toward a `u64` record holds, in all:
    /// its write alone, or its write and its release.
    fn held_by(admitted: stable::Admitted) -> WriteWork {
        let (grant, release) = record_obligations();
        match admitted {
            stable::Admitted::Nothing => WriteWork::default(),
            stable::Admitted::Write => grant,
            stable::Admitted::Release => grant
                .checked_then(release)
                .expect("a record's credit fits in u64"),
        }
    }

    /// A token of `owner`'s scope holding `admitted`, admitted under `m`,
    /// whose second admission is refused: its write admitted and its release
    /// refused (`Write`, the grant's work alone), then, for `Release`, the
    /// retry's release admitted and its request refused (both). `m`'s
    /// ledgers conserve with exactly that held.
    fn holding(
        owner: &DecodeOwner<'static, Limits>,
        m: &mut Limits,
        admitted: stable::Admitted,
    ) -> Acquisition<'static, u64, Limits> {
        let mut acquisition = Acquisition::<u64, Limits>::new();
        assert!(owner.allocate_step(m, &mut acquisition).is_err());
        if admitted == stable::Admitted::Release {
            m.fail_request(Some(0));
            assert!(owner.allocate_step(m, &mut acquisition).is_err());
        }
        assert!(
            acquisition.holder.is_some(),
            "a holding token's acquisition is unbound"
        );
        assert!(acquisition.scope.is_some(), "a holding token is unbound");
        assert_ne!(held_by(admitted), WriteWork::default());
        assert_eq!(acquisition.held_credit(), Some(held_by(admitted)));
        assert_eq!(m.credits().conserved_with(held_by(admitted)), Some(true));
        acquisition
    }

    /// Shut the scope down under `m`, asserting: for tests behind no control
    /// row, whose first failure may end them.
    fn shut_down(owner: &mut DecodeOwner<'static, Limits>, m: &mut Limits) {
        for _ in 0..4 {
            if owner.shutdown_step(m).unwrap() == Reclaimed::Done {
                assert_eq!(m.live_bytes(), 0, "the scope was kept");
                return;
            }
        }
        panic!("the scope did not shut down");
    }

    /// The shutdown calls ([`DecodeOwner::shutdown_step`]) a scope takes with
    /// `queued` `u64` records queued and none held by a handle, derived from
    /// its states, there being no production sum of a scope's records'
    /// counts: a queue holding nothing reports `Done` at once
    /// (`Reclaimer::step`, reclamation.rs:1127-1135) and the authority frees
    /// its block in the same call (owned.rs `shutdown_step`, the block freed
    /// once the queue is `Done` and its reference the only one), one call; a
    /// queued record takes one call for its removal (reclamation.rs:1139-1163,
    /// `Progress`) and one per cleanup call its state declares, a `u64`'s
    /// one (`Reclaim::remaining` of an integer binding, the drain's count in
    /// `crate::sync::models`' `DRAINED`), the last record's last call freeing
    /// its block and reporting the queue `Done` (reclamation.rs:1185-1193),
    /// when the authority frees the scope in that same call. So two calls per
    /// queued record, or one for none.
    const fn shutdown_calls(queued: u64) -> u64 {
        if queued == 0 { 1 } else { 2 * queued }
    }

    /// Shut the scope, holding `queued` `u64` records, down under `m`
    /// within its derived calls ([`shutdown_calls`]) and `m`'s refusal
    /// allowance ([`Limits::allowed`]), every failure kept in `findings` and
    /// the test going on to its conclusion: a refused or failed step, a
    /// shutdown past its bound, storage kept after `Done`, or, with no
    /// refusal during it, a shutdown taking other than the derived calls.
    /// Every witness shuts down through here once its first finding is
    /// kept, so a defect that keeps the scope live is named beside the
    /// findings, never in place of them.
    pub(super) fn shut_down_into(
        findings: &mut Findings,
        owner: &mut DecodeOwner<'static, Limits>,
        m: &mut Limits,
        queued: u64,
    ) {
        let derived = shutdown_calls(queued);
        let bound = m
            .allowed::<()>(derived)
            .expect("a fixture's shutdown bound fits in u64");
        let refusals = m.refusals();
        let mut taken = 0u64;
        while taken < bound {
            taken += 1;
            match owner.shutdown_step(m) {
                Ok(Reclaimed::Done) => {
                    findings.equal("the scope's storage after its shutdown", m.live_bytes(), 0);
                    if m.refusals() == refusals {
                        findings.equal("the scope's shutdown calls", taken, derived);
                    }
                    return;
                }
                Ok(_) => {}
                Err(error) => {
                    findings.check(false, || format!("the scope's shutdown failed: {error:?}"));
                    return;
                }
            }
        }
        findings.check(false, || {
            format!("the scope did not shut down within {bound} steps")
        });
    }

    /// A token dropped holding credit, its record's write alone or its
    /// write and release, forfeits exactly that, `Cancelled`, into the
    /// family that admitted it, not the scope's: the admitting family alone
    /// conserves with nothing held, and the scope's family records nothing.
    /// The forfeit admits and allocates nothing. Preconditions are asserted
    /// before the drop ([`holding`]); every check after it is a finding
    /// ([`Findings`]), the shutdown's included ([`shut_down_into`]), so
    /// every family is dropped before the test concludes; each run's
    /// families record into a session of its own, finished complete and
    /// refined.
    #[test]
    fn a_dropped_acquisition_forfeits_into_the_admitting_family() {
        let mut findings = Findings::new();
        let mut sessions = alloc::vec::Vec::new();
        for admitted in [stable::Admitted::Write, stable::Admitted::Release] {
            let held = held_by(admitted);
            let session = recording();
            let mut family = Limits::recorded_unlimited(&session);
            let mut owner = DecodeOwner::<'static, Limits>::new();
            owner.initialize_step(&mut family).unwrap();
            let mut m = Limits::recorded_unlimited(&session).refusing(Some(1));
            let acquisition = holding(&owner, &mut m, admitted);
            let (live, scope_before, before) = (family.live_bytes(), family.credits(), m.credits());
            drop(acquisition);
            findings.equal("the forfeit allocated", family.live_bytes(), live);
            findings.equal(
                "the scope's family recorded a forfeit",
                family.credits(),
                scope_before,
            );
            let after = m.credits();
            findings.equal(
                &format!("{admitted:?}: the admitting family did not record exactly the forfeit"),
                after
                    .checked_sub(before)
                    .map(|delta| (delta.admitted, delta.forfeited)),
                Some((WriteWork::default(), held)),
            );
            findings.equal(
                &format!("{admitted:?}: the admitting family lost credit: {after:?}"),
                after.conserved_with(WriteWork::default()),
                Some(true),
            );
            shut_down_into(&mut findings, &mut owner, &mut family, 0);
            drop(owner);
            findings.policies([("the scope's family", family, READ), ("m", m, READ)]);
            sessions.push((admitted, session.finish()));
        }
        let names = [
            "the session of the write held",
            "the session of the write and release held",
        ];
        let concluded: alloc::vec::Vec<_> = sessions
            .iter()
            .zip(names)
            .map(|((_, finished), name)| (name, finished, Expected::Complete))
            .collect();
        findings.conclude(&concluded);
    }

    /// The reviewer's case on a token: its write admitted under family `a`,
    /// its release refused; the retry under family `b` admits the release
    /// and its request is refused. Dropped, the write is forfeited into `a`
    /// and the release into `b`: each family alone conserves with nothing
    /// held, and each records exactly its own obligation. Preconditions are
    /// asserted before the drop; every check after it is a finding, and the
    /// families record into one session, finished complete and refined.
    #[test]
    fn a_tokens_obligations_each_settle_into_their_own_family() {
        let mut findings = Findings::new();
        let session = recording();
        let mut family = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut family).unwrap();
        let mut a = Limits::recorded_unlimited(&session).refusing(Some(1));
        let mut b = Limits::recorded_unlimited(&session).refusing_request(Some(0));
        let mut acquisition = Acquisition::<u64, Limits>::new();
        assert!(owner.allocate_step(&mut a, &mut acquisition).is_err());
        assert_eq!(
            acquisition.held_credit(),
            Some(held_by(stable::Admitted::Write))
        );
        assert!(owner.allocate_step(&mut b, &mut acquisition).is_err());
        assert_eq!(
            acquisition.held_credit(),
            Some(held_by(stable::Admitted::Release))
        );
        let (grant, release) = record_obligations();
        drop(acquisition);
        settled_alone(&mut findings, "a", &a, grant, false);
        settled_alone(&mut findings, "b", &b, release, false);
        shut_down_into(&mut findings, &mut owner, &mut family, 0);
        drop(owner);
        findings.policies([
            ("the scope's family", family, READ),
            ("a", a, READ),
            ("b", b, READ),
        ]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// The four families of the cross-family case, recorded in `session`:
    /// `a` admits the grant's write and refuses the release (attempt 1);
    /// `b` admits the release and refuses the request (request 0); `c`
    /// grants the request; `d` runs the cleanup.
    fn families(session: &crate::bounded::Session) -> (Limits, Limits, Limits, Limits) {
        (
            Limits::recorded_unlimited(session).refusing(Some(1)),
            Limits::recorded_unlimited(session).refusing_request(Some(0)),
            Limits::recorded_unlimited(session),
            Limits::recorded_unlimited(session),
        )
    }

    /// `family` admitted exactly `work`, held, and settled all of it as
    /// consumed (`spent`) or forfeited, recording nothing else: the credit
    /// of one obligation, settled in the family that admitted it, whoever
    /// settled it. A disagreement is kept in `findings`, naming the family.
    /// A settlement made into any other family than the admitting one
    /// (`pending-settle-wrong-origin`) leaves this family's consumed and
    /// forfeited short of `work`. A settlement into the performing policy's
    /// family is no planted control of its own: it cannot be represented,
    /// since `Retained` owns its origin and no settlement path (`spend`,
    /// `forfeit`, `Pending::settle_all`) receives any budget's origin.
    fn settled_alone(
        findings: &mut Findings,
        name: &str,
        family: &Limits,
        work: WriteWork,
        spent: bool,
    ) {
        let credits = family.credits();
        let (consumed, forfeited) = if spent {
            (work, WriteWork::default())
        } else {
            (WriteWork::default(), work)
        };
        findings.equal(
            &format!("{name}: not exactly its own obligation, settled in place"),
            (
                credits.admitted,
                credits.consumed,
                credits.forfeited,
                credits.violated,
            ),
            (work, consumed, forfeited, false),
        );
    }

    /// The cross-family case on a token, its grant: the write admitted under
    /// `a`, the release under `b`, the record granted under `c`, the record's
    /// cleanup under `d`. The write is consumed in `a` and the release in
    /// `b`, both at `c`'s grant; `c` holds the record's permit, its only
    /// request, until `d`'s cleanup releases it; `d` records none of the
    /// acquisition's credit, and no family records another's. Preconditions
    /// are asserted before the grant; every check after it is a finding,
    /// and the families record into one session, finished complete and
    /// refined.
    #[test]
    fn a_granted_tokens_obligations_are_consumed_in_their_own_families() {
        let mut findings = Findings::new();
        let session = recording();
        let (grant, release) = record_obligations();
        let (mut a, mut b, mut c, mut d) = families(&session);
        let mut scope = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut scope).unwrap();
        let mut acquisition = Acquisition::<u64, Limits>::new();
        assert!(owner.allocate_step(&mut a, &mut acquisition).is_err());
        assert!(owner.allocate_step(&mut b, &mut acquisition).is_err());
        assert_eq!(
            acquisition.held_credit(),
            Some(held_by(stable::Admitted::Release))
        );
        let record = owner
            .allocate_step(&mut c, &mut acquisition)
            .expect("c grants the record");
        settled_alone(&mut findings, "a", &a, grant, true);
        settled_alone(&mut findings, "b", &b, release, true);
        // `c` steps the owner stage, whose one unit it admits and consumes
        // at once (`Reclaimer::own`, `OWNER`); of the acquisition's credit it
        // holds, spends and forfeits nothing.
        let owner_unit = const { super::super::OWNER.work() };
        findings.equal(
            "c admitted other than the owner stage's unit",
            c.credits(),
            crate::bounded::Credits {
                admitted: owner_unit,
                consumed: owner_unit,
                forfeited: WriteWork::default(),
                violated: false,
            },
        );
        findings.equal("c made the record's one request", c.requests(), 1);
        findings.check(
            c.live_bytes() != 0,
            || "c does not hold the record's permit",
        );
        findings.equal("a or b holds a permit", a.live_bytes() + b.live_bytes(), 0);
        drop(acquisition);
        drop(record);
        let before = d.credits();
        // The dropped record is the one queued.
        shut_down_into(&mut findings, &mut owner, &mut d, 1);
        findings.equal(
            "the record's permit outlived its cleanup",
            c.live_bytes(),
            0,
        );
        settled_alone(&mut findings, "a", &a, grant, true);
        settled_alone(&mut findings, "b", &b, release, true);
        findings.equal(
            "d forfeited another family's credit",
            d.credits().checked_sub(before).map(|delta| delta.forfeited),
            Some(WriteWork::default()),
        );
        shut_down_into(&mut findings, &mut owner, &mut scope, 0);
        drop(owner);
        findings.policies([
            ("a", a, READ),
            ("b", b, READ),
            ("c", c, READ),
            ("d", d, READ),
            ("the scope's family", scope, READ),
        ]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// The cross-family case on a token, cancelled after `b`'s refused
    /// request: the write is forfeited in `a`, the release in `b`; `c` and
    /// `d` are never reached. Preconditions are asserted before the cancel;
    /// every check after it is a finding, and the families record into one
    /// session, finished complete and refined.
    #[test]
    fn a_cancelled_tokens_obligations_are_forfeited_in_their_own_families() {
        let mut findings = Findings::new();
        let session = recording();
        let (grant, release) = record_obligations();
        let (mut a, mut b, c, d) = families(&session);
        let mut scope = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut scope).unwrap();
        let mut acquisition = Acquisition::<u64, Limits>::new();
        assert!(owner.allocate_step(&mut a, &mut acquisition).is_err());
        assert!(owner.allocate_step(&mut b, &mut acquisition).is_err());
        acquisition.cancel(Performer::None);
        settled_alone(&mut findings, "a, cancelled", &a, grant, false);
        settled_alone(&mut findings, "b, cancelled", &b, release, false);
        drop(acquisition);
        settled_alone(&mut findings, "a, dropped", &a, grant, false);
        settled_alone(&mut findings, "b, dropped", &b, release, false);
        shut_down_into(&mut findings, &mut owner, &mut scope, 0);
        drop(owner);
        findings.policies([
            ("a", a, READ),
            ("b", b, READ),
            ("c", c, READ),
            ("d", d, READ),
            ("the scope's family", scope, READ),
        ]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// The cross-family case on the authority, its grant: the scope block's
    /// write admitted under `a`, its release under `b`, the block granted
    /// under `c`, the shutdown under `d`. The write is consumed in `a`, the
    /// release in `b`; `c` holds the block's permit until `d`'s shutdown
    /// frees it; `d` records none of the initialization's credit.
    /// Preconditions are asserted before the grant; every check after it is
    /// a finding, and the families record into one session, finished
    /// complete and refined.
    #[test]
    fn an_initialized_owners_obligations_are_consumed_in_their_own_families() {
        let mut findings = Findings::new();
        let session = recording();
        let (grant, release) = scope_obligations();
        let (mut a, mut b, mut c, mut d) = families(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        assert!(owner.initialize_step(&mut a).is_err());
        assert!(owner.initialize_step(&mut b).is_err());
        owner.initialize_step(&mut c).expect("c grants the scope");
        settled_alone(&mut findings, "a", &a, grant, true);
        settled_alone(&mut findings, "b", &b, release, true);
        findings.equal("c made the block's one request", c.requests(), 1);
        findings.check(c.live_bytes() != 0, || "c does not hold the block's permit");
        let before = d.credits();
        shut_down_into(&mut findings, &mut owner, &mut d, 0);
        findings.equal(
            "the block's permit outlived the shutdown",
            c.live_bytes(),
            0,
        );
        findings.equal(
            "d forfeited another family's credit",
            d.credits().checked_sub(before).map(|delta| delta.forfeited),
            Some(WriteWork::default()),
        );
        settled_alone(&mut findings, "a, after the shutdown", &a, grant, true);
        settled_alone(&mut findings, "b, after the shutdown", &b, release, true);
        drop(owner);
        findings.policies([
            ("a", a, READ),
            ("b", b, READ),
            ("c", c, READ),
            ("d", d, READ),
        ]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// The cross-family case on the authority, shut down under `d` after
    /// `b`'s refused request: the write is forfeited in `a`, the release in
    /// `b`, and `d` records nothing. Preconditions are asserted before the
    /// shutdown; every check after it is a finding, and the families record
    /// into one session, finished complete and refined.
    #[test]
    fn a_shut_down_owners_obligations_are_forfeited_in_their_own_families() {
        let mut findings = Findings::new();
        let session = recording();
        let (grant, release) = scope_obligations();
        let (mut a, mut b, c, mut d) = families(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        assert!(owner.initialize_step(&mut a).is_err());
        assert!(owner.initialize_step(&mut b).is_err());
        findings.equal(
            "the uninitialized shutdown",
            owner.shutdown_step(&mut d),
            Ok(Reclaimed::Done),
        );
        settled_alone(&mut findings, "a", &a, grant, false);
        settled_alone(&mut findings, "b", &b, release, false);
        findings.equal(
            "d recorded credit",
            d.credits(),
            crate::bounded::Credits::default(),
        );
        drop(owner);
        settled_alone(&mut findings, "a, after the drop", &a, grant, false);
        settled_alone(&mut findings, "b, after the drop", &b, release, false);
        findings.policies([
            ("a", a, READ),
            ("b", b, READ),
            ("c", c, READ),
            ("d", d, READ),
        ]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// A token cancelled, or granted its record, holds nothing, has no
    /// acquisition bound and is bound to no scope: its drop forfeits nothing
    /// again and records nothing in any family. The cancel forfeits into the
    /// admitting family, which then conserves with nothing held.
    #[test]
    fn a_cancelled_or_granted_token_leaves_nothing_for_its_drop() {
        let mut family = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut family).unwrap();
        let mut m = Limits::unlimited().refusing(Some(1));
        let mut acquisition = holding(&owner, &mut m, stable::Admitted::Release);
        acquisition.cancel(Performer::None);
        assert_eq!(acquisition.held_credit(), Some(WriteWork::default()));
        assert!(acquisition.scope.is_none(), "a cancelled token is bound");
        assert!(
            acquisition.pending.is_idle() && acquisition.holder.is_none(),
            "a cancelled token kept an acquisition"
        );
        let before = (m.credits(), family.credits());
        drop(acquisition);
        assert_eq!(
            (m.credits(), family.credits()),
            before,
            "a cancelled token forfeited again"
        );
        assert_eq!(m.credits().conserved_with(WriteWork::default()), Some(true));
        let mut granted = Limits::unlimited();
        let mut acquisition = Acquisition::<u64, Limits>::new();
        let record = owner.allocate_step(&mut granted, &mut acquisition).unwrap();
        assert!(acquisition.scope.is_none(), "a granted token is bound");
        assert!(
            acquisition.pending.is_idle() && acquisition.holder.is_none(),
            "a granted token kept an acquisition"
        );
        let before = (granted.credits(), family.credits());
        drop(acquisition);
        assert_eq!(
            (granted.credits(), family.credits()),
            before,
            "a granted token forfeited"
        );
        assert_eq!(
            granted.credits().conserved_with(WriteWork::default()),
            Some(true)
        );
        drop(record);
        shut_down(&mut owner, &mut family);
    }

    /// The owner dropped first, the scope abandoned: the holding token's
    /// counted reference keeps the block and its permit live; its drop
    /// forfeits into the admitting family, and only its reference's release
    /// after the forfeit frees the scope. The order is read from the
    /// recorded stream: every forfeit of the token's acquisition precedes
    /// the release of the scope block's permit, identified by its identity
    /// before the drop. Preconditions are asserted before the token's drop;
    /// every check after it is a finding, and the session is concluded
    /// complete and refined.
    #[cfg(feature = "std")]
    #[test]
    fn an_acquisition_outliving_its_owner_forfeits_before_the_scope_is_freed() {
        use crate::bounded::{Credit, Event, Forfeit, Observed};
        let session = recording();
        let mut family = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut family).unwrap();
        let scope = groups(|sink| owner.observe_custody(sink)).permits(0)[0];
        let mut m = Limits::recorded_unlimited(&session).refusing(Some(1));
        let acquisition = holding(&owner, &mut m, stable::Admitted::Release);
        drop(owner);
        assert_ne!(
            family.live_bytes(),
            0,
            "the token's reference did not keep the scope"
        );
        let before = m.credits();
        drop(acquisition);
        let mut findings = Findings::new();
        findings.equal(
            "the last reference did not free the scope",
            family.live_bytes(),
            0,
        );
        findings.equal(
            "the token's forfeit",
            m.credits().checked_sub(before).map(|delta| delta.forfeited),
            Some(held_by(stable::Admitted::Release)),
        );
        findings.equal(
            "the admitting family's conservation",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.policies([("the scope's family", family, READ), ("m", m, READ)]);
        let finished = session.finish();
        if let Ok(observed) = &finished {
            let position = |matches: &dyn Fn(&Observed) -> bool| observed.iter().rposition(matches);
            let forfeited = position(&|observation| {
                matches!(
                    observation.event,
                    Event::Credit(Credit::Forfeit(_, Forfeit::Cancelled))
                )
            });
            let freed = position(&|observation| observation.event == Event::Released(scope));
            findings.check(
                matches!((forfeited, freed), (Some(forfeit), Some(free)) if forfeit < free),
                || {
                    format!(
                        "the scope was freed before the token's forfeit: last forfeit at \
                         {forfeited:?}, the scope permit's release at {freed:?}"
                    )
                },
            );
        }
        findings.conclude(&[("S", &finished, Expected::Complete)]);
    }

    /// The control of [`shut_down_into`]: a finding kept, then a shutdown
    /// whose first unit (the queued record's removal) is refused. Both are
    /// named in the one failure, the shutdown's beside the earlier finding;
    /// the authority's drop then drains the scope terminally, so the
    /// session still finishes complete. Caught to read both, which needs
    /// `std`.
    #[cfg(feature = "std")]
    #[test]
    fn a_shutdown_failure_is_named_beside_an_earlier_finding() {
        let session = recording();
        let mut m = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut m).unwrap();
        let record = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .unwrap();
        drop(record);
        let mut findings = Findings::new();
        findings.check(false, || "the planted earlier finding");
        m.refuse_next();
        shut_down_into(&mut findings, &mut owner, &mut m, 1);
        drop(owner);
        findings.policies([("m", m, READ)]);
        let finished = session.finish();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            findings.conclude(&[("S", &finished, Expected::Complete)]);
        }))
        .expect_err("a test with findings concluded silently");
        let message = failure
            .downcast_ref::<std::string::String>()
            .expect("the conclusion's failure is a formatted message");
        assert!(
            message.contains("the planted earlier finding"),
            "the earlier finding is missing from: {message}"
        );
        assert!(
            message.contains("the scope's shutdown failed: Refused("),
            "the shutdown's failure is missing from: {message}"
        );
    }

    /// An authority whose scope block's request was refused, its write alone
    /// held (its release refused) or its write and release (its request
    /// refused), then dropped uninitialized: it forfeits exactly what it
    /// held into the family that admitted it, which then conserves with
    /// nothing held and keeps no storage. Attempts: the block's write (0)
    /// and release (1); its request is the policy's first (request 0).
    /// Preconditions are asserted before the drop; every check after it is
    /// kept as a finding ([`Findings`]), concluded
    /// once both runs are done and their families dropped; each run records
    /// into a session of its own, finished complete and refined.
    #[test]
    fn an_uninitialized_owner_dropped_holding_credit_settles_it() {
        let mut findings = Findings::new();
        let (write, release) = (recording(), recording());
        let block = |admitted| {
            let (grant, release) = scope_obligations();
            match admitted {
                stable::Admitted::Release => grant
                    .checked_then(release)
                    .expect("a scope's credit fits in u64"),
                _ => grant,
            }
        };
        for (admitted, mut m) in [
            (
                stable::Admitted::Write,
                Limits::recorded_unlimited(&write).refusing(Some(1)),
            ),
            (
                stable::Admitted::Release,
                Limits::recorded_unlimited(&release).refusing_request(Some(0)),
            ),
        ] {
            let mut owner = DecodeOwner::<'static, Limits>::new();
            assert!(owner.initialize_step(&mut m).is_err());
            assert!(owner.holder.is_some(), "{admitted:?}: no acquisition bound");
            assert_ne!(block(admitted), WriteWork::default());
            assert_eq!(owner.held_credit(), Some(block(admitted)));
            assert_eq!(m.credits().conserved_with(block(admitted)), Some(true));
            let before = m.credits();
            drop(owner);
            let after = m.credits();
            findings.equal(
                &format!("{admitted:?}: the drop did not forfeit exactly what was held"),
                after.checked_sub(before).map(|delta| delta.forfeited),
                Some(block(admitted)),
            );
            findings.equal(
                &format!("{admitted:?}: lost credit: {after:?}"),
                after.conserved_with(WriteWork::default()),
                Some(true),
            );
            findings.equal(
                &format!("{admitted:?}: storage was kept"),
                m.live_bytes(),
                0,
            );
            findings.policies([(
                match admitted {
                    stable::Admitted::Write => "the write's family",
                    _ => "the write and release's family",
                },
                m,
                READ,
            )]);
        }
        findings.conclude(&[
            (
                "the session of the write held",
                &write.finish(),
                Expected::Complete,
            ),
            (
                "the session of the write and release held",
                &release.finish(),
                Expected::Complete,
            ),
        ]);
    }

    /// Credit is held only with an obligation: an authority whose first
    /// admission is refused holds nothing, having made exactly that one
    /// attempt and no request, so its drop records nothing. Its acquisition
    /// is bound (the binding is retained progress before the first
    /// admission, not an effect) and holds no obligation.
    #[test]
    fn no_credit_is_held_without_an_obligation() {
        let mut m = Limits::unlimited().refusing(Some(0));
        let mut owner = DecodeOwner::<'static, Limits>::new();
        assert!(owner.initialize_step(&mut m).is_err());
        assert_eq!(owner.held_credit(), Some(WriteWork::default()));
        assert!(
            owner.holder.is_some(),
            "the binding is retained for the retry"
        );
        assert_eq!((m.attempts(), m.requests()), (1, 0));
        assert_eq!(m.credits(), crate::bounded::Credits::default());
        drop(owner);
        assert_eq!(m.credits(), crate::bounded::Credits::default());
        assert_eq!(m.live_bytes(), 0);
    }

    /// The reviewer's case on the authority: the block's write admitted
    /// under `a`, its release refused; the retry under `b` admits the
    /// release and its request is refused. Dropped, the write is forfeited
    /// into `a` and the release into `b`: each family alone conserves with
    /// nothing held, and each records exactly its own obligation.
    #[test]
    fn an_owners_obligations_each_settle_into_their_own_family() {
        let session = recording();
        let mut a = Limits::recorded_unlimited(&session).refusing(Some(1));
        let mut b = Limits::recorded_unlimited(&session).refusing_request(Some(0));
        let mut owner = DecodeOwner::<'static, Limits>::new();
        let (grant, release) = scope_obligations();
        assert!(owner.initialize_step(&mut a).is_err());
        assert_eq!(owner.held_credit(), Some(grant));
        assert!(owner.initialize_step(&mut b).is_err());
        assert_eq!(owner.held_credit(), grant.checked_then(release));
        drop(owner);
        // Every check after the drop kept as a finding ([`Findings`]),
        // concluded once both families are dropped.
        let mut findings = Findings::new();
        findings.equal(
            "the write was not forfeited into a",
            a.credits().forfeited,
            grant,
        );
        findings.equal(
            "the release was not forfeited into b",
            b.credits().forfeited,
            release,
        );
        for (name, family) in [("a", &a), ("b", &b)] {
            findings.equal(
                &format!("{name}: {:?}", family.credits()),
                family.credits().conserved_with(WriteWork::default()),
                Some(true),
            );
        }
        findings.equal("storage kept", a.live_bytes() + b.live_bytes(), 0);
        findings.policies([("a", a, READ), ("b", b, READ)]);
        findings.conclude(&[("S", &session.finish(), Expected::Complete)]);
    }

    /// Shutdown of an authority that never initialized forfeits what it
    /// held into the family that admitted it and keeps no settlement:
    /// nothing is left for its drop.
    #[test]
    fn an_uninitialized_owner_shut_down_leaves_nothing_for_its_drop() {
        let mut m = Limits::unlimited().refusing_request(Some(0));
        let mut owner = DecodeOwner::<'static, Limits>::new();
        assert!(owner.initialize_step(&mut m).is_err());
        assert_eq!(owner.shutdown_step(&mut m), Ok(Reclaimed::Done));
        assert!(owner.pending.is_idle() && owner.holder.is_none());
        assert_eq!(m.live_bytes(), 0);
        assert_eq!(m.credits().conserved_with(WriteWork::default()), Some(true));
        let before = m.credits();
        drop(owner);
        assert_eq!(
            m.credits(),
            before,
            "a closed authority's drop recorded an event"
        );
    }

    /// The `acquisition-drop-unsettled` witness on a recorded family: a token
    /// dropped holding its record's write (its release refused, attempt 1)
    /// forfeits exactly that write into the admitting family, read from that
    /// family's ledgers after the token is gone, its granted-nothing cleanup
    /// and its scope reference's release unaffected; then the scope shuts
    /// down and the session finishes as complete evidence. Both readings are
    /// taken before either is asserted, so a drop that settles nothing
    /// reports its missing forfeit beside the session its leaked custody
    /// keeps live, the forfeit read from the ledgers whatever the recording
    /// concludes. Preconditions are asserted before the drop ([`holding`]);
    /// every check after it is a finding, the shutdown's included
    /// ([`shut_down_into`]).
    #[cfg(feature = "std")]
    #[test]
    fn a_dropped_acquisitions_forfeit_is_recorded_before_its_session_finishes() {
        let session = recording();
        let mut scope_family = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut scope_family).unwrap();
        let mut m = Limits::recorded_unlimited(&session).refusing(Some(1));
        let acquisition = holding(&owner, &mut m, stable::Admitted::Write);
        let before = m.credits();
        drop(acquisition);
        let mut findings = Findings::new();
        findings.equal(
            "the admitting family did not record exactly the forfeit",
            m.credits().checked_sub(before).map(|delta| delta.forfeited),
            Some(held_by(stable::Admitted::Write)),
        );
        findings.equal(
            "the admitting family's conservation",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        shut_down_into(&mut findings, &mut owner, &mut scope_family, 0);
        drop(owner);
        findings.policies([("m", m, READ), ("the scope's family", scope_family, READ)]);
        findings.conclude(&[("the session", &session.finish(), Expected::Complete)]);
    }

    /// The `owner-drop-unsettled` witness on a recorded family: an authority
    /// dropped uninitialized holding its scope block's write and release (its
    /// request refused, request 0) forfeits exactly both into the admitting
    /// family, read from that family's ledgers after the authority is gone,
    /// keeping no storage; then the session finishes as complete evidence.
    /// Preconditions (the refused initialization, the credit held) are
    /// asserted before the drop; every check after it is a finding.
    #[cfg(feature = "std")]
    #[test]
    fn a_dropped_owners_forfeit_is_recorded_before_its_session_finishes() {
        let session = recording();
        let mut m = Limits::recorded_unlimited(&session).refusing_request(Some(0));
        let mut owner = DecodeOwner::<'static, Limits>::new();
        assert!(owner.initialize_step(&mut m).is_err());
        let held = owner.held_credit();
        assert_ne!(
            held,
            Some(WriteWork::default()),
            "the authority holds no credit"
        );
        let before = m.credits();
        drop(owner);
        let mut findings = Findings::new();
        findings.equal(
            "the drop did not forfeit exactly what was held",
            m.credits().checked_sub(before).map(|delta| delta.forfeited),
            held,
        );
        findings.equal(
            "the admitting family's conservation",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.equal("storage was kept", m.live_bytes(), 0);
        findings.policies([("m", m, READ)]);
        findings.conclude(&[("the session", &session.finish(), Expected::Complete)]);
    }

    /// Every group a custody observation opens, in order, with the permits
    /// reported directly inside it, each with its record stage (nested
    /// groups recorded on their own): what the owner-association witnesses
    /// below compare.
    #[derive(Default)]
    struct Groups {
        open: std::vec::Vec<usize>,
        groups: std::vec::Vec<Group>,
    }

    /// One group a custody observation opened: its owner, and each permit
    /// reported directly inside it with its record stage.
    type Group = (
        Option<crate::bounded::Identity>,
        std::vec::Vec<(
            crate::bounded::Identity,
            Option<crate::bounded::RecordStage>,
        )>,
    );

    impl Groups {
        /// The permit identities of group `at`, stages passed over.
        fn permits(&self, at: usize) -> std::vec::Vec<crate::bounded::Identity> {
            self.groups[at].1.iter().map(|(id, _)| *id).collect()
        }
    }

    impl CustodySink<crate::bounded::Reservation> for Groups {
        fn begin(&mut self, owner: Option<crate::bounded::Identity>) {
            self.open.push(self.groups.len());
            self.groups.push((owner, std::vec::Vec::new()));
        }
        /// Bindings are the refinement collector's to compare; these
        /// witnesses compare permit groups alone.
        fn bound(&mut self, _: crate::bounded::Identity) {}
        fn held(&mut self, _: crate::bounded::Hold) {}
        fn permit(
            &mut self,
            permit: &crate::bounded::Reservation,
            record: Option<crate::bounded::RecordStage>,
        ) {
            let at = *self
                .open
                .last()
                .expect("a permit reported outside every group");
            self.groups[at].1.push((
                <Limits as crate::bounded::Releasing>::permit_identity(permit),
                record,
            ));
        }
        fn end(&mut self) {
            self.open.pop().expect("an end without its begin");
        }
        /// Every group the observation reaches, shared custody once: by
        /// the first holder, while its permit is not yet recorded.
        fn shared(&mut self, custody: crate::bounded::Identity) -> bool {
            !self
                .groups
                .iter()
                .any(|(_, permits)| permits.iter().any(|(id, _)| *id == custody))
        }
    }

    /// A recording session of the default capacity.
    fn recording() -> crate::bounded::Session {
        crate::bounded::Session::new(crate::bounded::Capacity::DEFAULT)
    }

    /// The groups `observe` reports, every group closed.
    fn groups(observe: impl FnOnce(&mut Groups) -> PermitsObserved) -> Groups {
        let mut sink = Groups::default();
        assert_eq!(observe(&mut sink), PermitsObserved::Complete);
        assert!(sink.open.is_empty(), "a group was left open");
        sink
    }

    /// An abandoned scope's custody is reported by the handles that keep it
    /// alive, exactly once per observation, under the owner it had: while the
    /// authority lives, the two record handles report their records alone,
    /// the scope block being the authority's; once the authority is dropped,
    /// an observation of both handles reports the scope block once, in a
    /// group under the authority's owner, the block no record block, beside
    /// each handle's record under its own acquisition's owner. The last
    /// handle's drop drains the scope terminally, leaving nothing live, and
    /// the session finishes complete and refined. Planted controls: the
    /// report omitted (`abandoned-scope-unreported`), made by every handle
    /// (`abandoned-scope-reported-twice`), and made under another owner
    /// (`abandoned-scope-owner-misattributed`).
    #[cfg(feature = "std")]
    #[test]
    fn an_abandoned_scope_is_reported_once_by_its_handles_under_its_owner() {
        let session = recording();
        let mut m = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut m).unwrap();
        let authority = owner.pending.owner_id();
        let scope = groups(|sink| owner.observe_custody(sink));
        assert_eq!(scope.groups[0].0, authority, "the authority's own group");
        let block = scope.permits(0)[0];
        let mut first = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .unwrap();
        let mut second = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .unwrap();
        let handles = |first: &mut OwnedRecord<'static, u64, Limits>,
                       second: &mut OwnedRecord<'static, u64, Limits>| {
            groups(|sink| observed_all([first.observe_custody(sink), second.observe_custody(sink)]))
        };
        let reports = |observed: &Groups| -> std::vec::Vec<(
            Option<crate::bounded::Identity>,
            Option<crate::bounded::RecordStage>,
        )> {
            observed
                .groups
                .iter()
                .flat_map(|(group, permits)| {
                    permits
                        .iter()
                        .filter(|(id, _)| *id == block)
                        .map(move |(_, stage)| (*group, *stage))
                })
                .collect()
        };
        let mut findings = Findings::new();
        let live = handles(&mut first, &mut second);
        findings.equal(
            "the live authority's scope block reported by its handles",
            reports(&live),
            std::vec::Vec::new(),
        );
        drop(owner);
        let abandoned = handles(&mut first, &mut second);
        findings.equal(
            "the abandoned scope block, reported once under its owner",
            reports(&abandoned),
            std::vec![(authority, None)],
        );
        findings.equal(
            "the groups of an observation of two handles of an abandoned scope",
            abandoned.groups.len(),
            3,
        );
        drop(first);
        drop(second);
        findings.equal(
            "the abandoned scope outlived its last handle",
            m.live_bytes(),
            0,
        );
        findings.policies([("m", m, READ)]);
        findings.conclude(&[("the session", &session.finish(), Expected::Complete)]);
    }

    /// A record's owner stage refused, then retried: the refusal writes
    /// nothing and requests nothing again; until the retry the granted block
    /// is the acquisition's, reported in the token's own group under its
    /// owner, and no handle exists; the retry admits only the owner unit and
    /// returns the record, its group under that same owner. Attempts: the
    /// record's write, its release and its request, then its owner unit,
    /// refused, its index read from an unrefused acquisition
    /// (`owner_unit_attempt`).
    #[cfg(feature = "std")]
    #[test]
    fn a_refused_owner_stage_keeps_the_block_the_tokens_and_retries_alone() {
        let session = recording();
        let mut scope_family = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut scope_family).unwrap();
        let mut m = Limits::recorded_unlimited(&session).refusing(Some(owner_unit_attempt()));
        let mut acquisition = Acquisition::<u64, Limits>::new();
        assert!(matches!(
            owner.allocate_step(&mut m, &mut acquisition),
            Err(BoundedError::Refused(_))
        ));
        assert!(
            acquisition.granted.is_some(),
            "the granted block was not kept"
        );
        assert_eq!(m.requests(), 1, "the block was requested once");
        assert_eq!(acquisition.held_credit(), Some(WriteWork::default()));
        let token = acquisition
            .pending
            .owner_id()
            .expect("made by the first entry");
        let held = groups(|sink| acquisition.observe_custody(sink));
        assert_eq!(held.groups.len(), 2, "the token's group and its pending's");
        assert_eq!(held.groups[0].0, Some(token));
        assert_eq!(held.groups[0].1.len(), 1, "the granted block, the token's");
        assert_eq!(
            held.groups[0].1[0].1,
            Some(crate::bounded::RecordStage::Granted),
            "the granted block, not yet a record"
        );
        m.clear_refusal();
        let attempts = m.attempts();
        let mut record = owner
            .allocate_step(&mut m, &mut acquisition)
            .expect("the owner stage alone is retried");
        assert_eq!(
            m.attempts(),
            attempts + 1,
            "only the owner unit was admitted"
        );
        assert_eq!(m.requests(), 1, "the block was not requested again");
        assert!(acquisition.granted.is_none() && acquisition.scope.is_none());
        let observed = groups(|sink| record.observe_custody(sink));
        assert_eq!(observed.groups[0].0, Some(token));
        assert_eq!(observed.permits(0), held.permits(0), "the same block");
        assert_eq!(
            observed.groups[0].1[0].1,
            Some(crate::bounded::RecordStage::Handle),
            "the record, its handle's"
        );
        drop((record, acquisition));
        shut_down(&mut owner, &mut scope_family);
        drop(owner);
        let mut findings = Findings::new();
        findings.policies([("m", m, READ), ("the scope's family", scope_family, READ)]);
        findings.conclude(&[("the session", &session.finish(), Expected::Complete)]);
    }

    /// A third-party binding holding `N` published records of `T`, possibly
    /// of another scope of the same allocator type, in a custody field of its
    /// value, as the crate's own records hold the handles they own
    /// (`Constructed`'s document and input in its custody field): reached
    /// only with the record's state borrowed exclusively, never by a reader
    /// of the published value; its state is one byte, so the record's head
    /// unit stays within its quantum. Its cleanup steps every held handle
    /// once per call through the capability it is given
    /// ([`OwnedInitialized::reclaim_under`]), `N` siblings dispatched in one
    /// call; its custody observation reports each held handle's record.
    struct Holder<const N: usize, T: Reclaim<Limits>> {
        /// The record's custody field: the handles it holds, reached only
        /// through the record's place with its state borrowed exclusively
        /// (`Place::custody`), never by a reader of the published value, as
        /// `Constructed`'s document and input are.
        inners: [Option<OwnedInitialized<'static, T, Limits>>; N],
    }

    // SAFETY: the value's one field is its custody, written whole in one
    // admitted unit and recorded `Initialized`; cleanup steps each held
    // handle to `Done` through the capability, which empties its slot, and
    // nothing is dropped. The state is one byte, so the record's head unit
    // (header, state and permit) stays within its quantum. Its depth is its
    // own level and the held record's, whose advance is `T`'s root level:
    // exact.
    unsafe impl<const N: usize, T: Reclaim<Limits>> Reclaim<Limits> for Holder<N, T> {
        const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH + 1;
        type State = Written;
        const INITIAL: Written = Written::Empty;

        fn reclaim_step(
            mut slot: Slot<'_, Self, Written>,
            cleanup: &mut Cleanup<'_, Limits>,
        ) -> BoundedResult<Reclaimed, Limits> {
            let (place, state) = slot.parts();
            if *state == Written::Empty {
                crate::bounded::decode::construction::in_place::admit(cleanup, 0)?;
                return Ok(Reclaimed::Done);
            }
            // SAFETY: the value is written; its custody field is reached by
            // projection with the state borrowed exclusively, and no reader
            // of the published value borrows it.
            let inners =
                unsafe { place.custody(state, |holder| ptr::addr_of_mut!((*holder).inners)) };
            let mut pending = false;
            for inner in inners.iter_mut().filter(|inner| inner.is_some()) {
                if OwnedInitialized::reclaim_under(inner, cleanup)? != Reclaimed::Done {
                    pending = true;
                }
            }
            if pending {
                return Ok(Reclaimed::Progress);
            }
            *state = Written::Empty;
            Ok(Reclaimed::Done)
        }

        /// Every call steps every held handle once: the most of their own
        /// counts, one when none is held.
        fn remaining(mut slot: PeekSlot<'_, Self, Written>) -> Option<u64> {
            let (place, state) = slot.parts();
            if *state == Written::Empty {
                return Some(1);
            }
            // SAFETY: as in `reclaim_step`.
            let inners =
                unsafe { place.custody(state, |holder| ptr::addr_of_mut!((*holder).inners)) };
            let mut most = 1;
            for inner in inners.iter_mut().filter(|inner| inner.is_some()) {
                most = most.max(OwnedInitialized::remaining(inner)?);
            }
            Some(most)
        }

        /// Each held handle's record, a group under its own owner
        /// ([`OwnedInitialized::observe_custody`]), the completeness of each
        /// combined; nothing before the value is written or once every
        /// handle's cleanup completed.
        fn observe_permits(
            mut slot: PeekSlot<'_, Self, Written>,
            sink: &mut dyn CustodySink<<Limits as crate::bounded::Releasing>::Permit>,
        ) -> PermitsObserved {
            let (place, state) = slot.parts();
            if *state == Written::Empty {
                return PermitsObserved::Complete;
            }
            // SAFETY: as in `reclaim_step`.
            let inners =
                unsafe { place.custody(state, |holder| ptr::addr_of_mut!((*holder).inners)) };
            let mut whole = PermitsObserved::Complete;
            for inner in inners.iter_mut().flatten() {
                whole = observed_all([whole, inner.observe_custody(sink)]);
            }
            whole
        }
    }

    /// A holder, published in `owner`'s scope, of `inners`.
    fn holder_of<const N: usize, T: Reclaim<Limits> + Send + 'static>(
        owner: &DecodeOwner<'static, Limits>,
        m: &mut Limits,
        inners: [Option<OwnedInitialized<'static, T, Limits>>; N],
    ) -> OwnedInitialized<'static, Holder<N, T>, Limits>
    where
        T::State: Send,
    {
        published(owner, m, Holder { inners }, |state| {
            *state = Written::Initialized
        })
    }

    /// A published record of `value`, allocated in `owner`'s scope.
    fn published<T: Reclaim<Limits, State = S> + Send + 'static, S: Send>(
        owner: &DecodeOwner<'static, Limits>,
        m: &mut Limits,
        value: T,
        written: impl FnOnce(&mut S),
    ) -> OwnedInitialized<'static, T, Limits> {
        let mut record = owner
            .allocate_step::<T>(m, &mut Acquisition::new())
            .expect("an unlimited policy admits a record");
        crate::bounded::decode::construction::in_place::admit(m, core::mem::size_of::<T>())
            .expect("an unlimited policy admits the write");
        let mut slot = record.destination();
        let (place, state) = slot.parts();
        // SAFETY: the record's empty destination; the write is admitted.
        unsafe { place.write(state, value) };
        written(state);
        // SAFETY: the value is written whole and its state records it.
        unsafe { record.publish() }
    }

    /// Three scopes chained by handles, each scope's authority dropped
    /// (abandoned) while a handle in the scope before it holds its record:
    /// cleanup of the outermost record steps the middle one in place, which
    /// steps the innermost. Every scope reference ended inside those steps
    /// is deferred, then released, and each abandoned scope drained and
    /// freed, by the stepping frame's worklist once the step returns; the
    /// chain completes, nothing live, the credit settled. Completion only:
    /// the order of the drains against the step (the inline-drop control)
    /// is asserted separately, through the recorded release order.
    #[test]
    fn a_chain_of_abandoned_scopes_completes_through_the_worklist() {
        let session = recording();
        let mut m = Limits::recorded_unlimited(&session);
        let mut scopes: [DecodeOwner<'static, Limits>; 3] =
            core::array::from_fn(|_| DecodeOwner::new());
        for scope in &mut scopes {
            scope.initialize_step(&mut m).unwrap();
        }
        let [mut top_scope, middle_scope, leaf_scope] = scopes;
        let leaf = published(&leaf_scope, &mut m, 7u64, |state| {
            *state = Written::Initialized
        });
        let middle = holder_of(&middle_scope, &mut m, [Some(leaf)]);
        let top = holder_of(&top_scope, &mut m, [Some(middle)]);
        drop((leaf_scope, middle_scope));
        drop(top);
        let mut findings = Findings::new();
        // The top holder's record queued: its removal, then its one call.
        shut_down_into(&mut findings, &mut top_scope, &mut m, 1);
        drop(top_scope);
        findings.equal("the storage after the chain", m.live_bytes(), 0);
        findings.equal(
            "the chain's credit, conserved with nothing held",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.policies([("m", m, READ)]);
        findings.conclude(&[("the chain's session", &session.finish(), Expected::Complete)]);
    }

    /// A chain of 65 scopes, one past the dispatch limit, linked by records
    /// rather than by type nesting: scope `i` queues a holder of scope
    /// `i + 1`'s leaf record, and the head holds scope 0's leaf. Every
    /// scope is abandoned in order: each abandonment drains its own queue at
    /// once, its holder releasing the next scope's leaf, a release deferred
    /// and performed at that frame's worklist loop. So the chain collapses
    /// one link per abandonment, each drain a fresh capability at depth
    /// zero; it completes, nothing live, the credit settled. Completion of
    /// this schedule only: every holder is queued before its scope is
    /// abandoned, so this fixture never builds a pending chain. Schedules
    /// that retire into an already-abandoned scope, or concurrently with a
    /// scope being stepped, are not covered here.
    #[test]
    fn a_chain_of_65_abandoned_scopes_completes() {
        const CHAIN: usize = MAX_DISPATCH_DEPTH + 1;
        let session = crate::bounded::Session::new(crate::bounded::Capacity::DEFAULT);
        let mut m = Limits::recorded_unlimited(&session);
        let mut head = DecodeOwner::<'static, Limits>::new();
        head.initialize_step(&mut m).unwrap();
        let mut owners: Vec<DecodeOwner<'static, Limits>> = (0..CHAIN)
            .map(|_| {
                let mut owner = DecodeOwner::new();
                owner.initialize_step(&mut m).unwrap();
                owner
            })
            .collect();
        // Each scope's leaf, held by the scope before it.
        let leaves: Vec<_> = owners
            .iter()
            .map(|owner| {
                Some(published(owner, &mut m, 0u64, |state| {
                    *state = Written::Initialized
                }))
            })
            .collect();
        let mut leaves = leaves.into_iter();
        // The head scope holds scope 0's leaf; scope `i` holds scope
        // `i + 1`'s, its holder retired to its own queue at once.
        let first = holder_of(&head, &mut m, [leaves.next().flatten()]);
        for (owner, leaf) in owners.iter().zip(leaves) {
            drop(holder_of(owner, &mut m, [leaf]));
        }
        // Every scope of the chain abandoned while the previous one holds it.
        owners.clear();
        drop(first);
        let mut findings = Findings::new();
        shut_down_into(&mut findings, &mut head, &mut m, 1);
        drop(head);
        findings.equal("the storage after the chain", m.live_bytes(), 0);
        findings.equal(
            "the chain's credit, conserved with nothing held",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.policies([("m", m, READ)]);
        findings.conclude(&[("the chain's session", &session.finish(), Expected::Complete)]);
    }

    /// Every site in the shipped source that ends a scope reference, in one
    /// table. A row names the module; the function, qualified by its impl
    /// (`Type::f`, or `<Type as Trait>::f` for a trait impl, each the whole
    /// tokens `quote` prints, generic arguments and paths included), by its
    /// trait for a default method, and by every enclosing module or function
    /// (`outer::inner`); the site kind; the exact number of such sites in
    /// that function; and whether the function runs inside a cleanup step
    /// (it must defer the reference into the step's worklist, never release
    /// it in place) or at an outer frame (it releases it there, a drain it
    /// starts processed by that frame's worklist). A site is a call of
    /// `release_reference`, `release_last`, `defer`, `drop` or
    /// `cancel_into`, a `cancel` method call, a `read` of a `scope` field's
    /// address, or an assignment of `None` to a `scope` field or binding.
    /// Construction never runs inside a cleanup step (a step's capability is
    /// no `Allocator`, and every acquisition takes one), so its sites are
    /// outer. Code compiled only in test builds is excluded by evaluating
    /// each `cfg` predicate structurally: `test`, an `all` with a test-only
    /// member, and an `any` whose every member is test-only are test-only;
    /// `not(..)` and every other predicate are shipped. An unlisted site, a
    /// count other than the table's (a missing site is a count of 0), a row
    /// listed twice or of no sites, and an inside function's in-place
    /// release each fail.
    ///
    /// Syntactic sites only. A reference ended implicitly, by a value
    /// holding one going out of scope inside a step, has no site here; its
    /// `Drop` runs inline, a drain within a drain. The nesting oracle in
    /// `drain_terminally` names that nesting and aborts, but only in the
    /// executions that reach a drain: it is not exhaustive over implicit
    /// drops.
    ///
    /// Planted controls under `tests/data/controls`:
    /// `scope-end-in-place.patch`, a `drop` in a cleanup function in place
    /// of its deferral ("unlisted: input release_scope drop x1" and "input
    /// release_scope defer: x0, the table lists x1");
    /// `scope-release-extra-site.patch`, a second release in an already
    /// listed function ("owned process release_reference: x3, the table
    /// lists x2"); `scope-release-other-impl.patch`, the release
    /// `ScopeRef`'s and `DecodeOwner`'s `drop` make, made in another impl's
    /// identically named method (`unlisted: owned <OwnedRecord < '_ , T ,
    /// A > as Drop>::drop release_reference x1`), which a table keyed by
    /// bare function name accepts; `scope-release-same-name-impl.patch`,
    /// `DecodeOwner`'s release moved into the `drop` of another module's
    /// type of the same name, the count unchanged (`unlisted: owned <twin
    /// :: DecodeOwner < A > as Drop>::drop release_reference x1`), which a
    /// table keyed by the self type's last identifier accepts.
    #[cfg(feature = "std")]
    #[test]
    fn every_scope_reference_end_is_classified() {
        use std::collections::BTreeMap;
        use syn::punctuated::Punctuated;
        use syn::visit::Visit;
        const SOURCES: [(&str, &str); 3] = [
            ("owned", include_str!("owned.rs")),
            ("input", include_str!("../input.rs")),
            ("operation", include_str!("../operation.rs")),
        ];
        /// (module, qualified function, site kind, sites, inside a cleanup
        /// step).
        /// Each key's impl is its header's tokens as `quote` prints them.
        const TABLE: &[(&str, &str, &str, usize, bool)] = &[
            // The `n - 1` batch, then the retained release.
            ("owned", "process", "release_reference", 2, false),
            ("owned", "release_reference", "release_last", 1, false),
            (
                "owned",
                "ScopeRef < 's , A >::allocate_step",
                "scope = None",
                1,
                false,
            ),
            ("owned", "ScopeRef < 's , A >::defer", "defer", 1, true),
            (
                "owned",
                "<ScopeRef < '_ , A > as Drop>::drop",
                "release_reference",
                1,
                false,
            ),
            (
                "owned",
                "Acquisition < '_ , T , A >::cancel",
                "cancel_into",
                1,
                false,
            ),
            (
                "owned",
                "Acquisition < '_ , T , A >::cancel_into",
                "defer",
                1,
                true,
            ),
            (
                "owned",
                "<Acquisition < '_ , T , A > as Drop>::drop",
                "cancel",
                1,
                false,
            ),
            // The authority's own counted reference, ended by freeing the
            // block once it is the only one.
            (
                "owned",
                "DecodeOwner < 's , A >::shutdown_step",
                "scope = None",
                1,
                false,
            ),
            (
                "owned",
                "<DecodeOwner < '_ , A > as Drop>::drop",
                "release_reference",
                1,
                false,
            ),
            // The handle's reference read out at `Done`, then deferred.
            (
                "owned",
                "OwnedRecord < 's , T , A >::reclaim_under",
                "read scope",
                1,
                true,
            ),
            (
                "owned",
                "OwnedRecord < 's , T , A >::reclaim_under",
                "defer",
                1,
                true,
            ),
            // Explicit drops, each read: the terminal policy a drain made,
            // which holds no scope reference; a record's queue view, whose
            // drop enqueues it, the handle's own reference released after by
            // the handle's field drop at its outer frame.
            ("owned", "drain_terminally", "drop", 1, false),
            (
                "owned",
                "<OwnedRecord < '_ , T , A > as Drop>::drop",
                "drop",
                1,
                false,
            ),
            ("input", "release_scope", "defer", 1, true),
            // A task's reference ended at publication, outside cleanup.
            (
                "input",
                "<CopyInput < '_ , 's , A > as Task < 's , A >>::publish",
                "scope = None",
                1,
                false,
            ),
            (
                "input",
                "<BorrowInput < 's , A > as Task < 's , A >>::publish",
                "scope = None",
                1,
                false,
            ),
            (
                "operation",
                "Operation < 's , K , A >::step",
                "cancel_into",
                1,
                true,
            ),
            (
                "operation",
                "<Operation < 's , K , A > as Drop>::drop",
                "cancel",
                1,
                false,
            ),
        ];
        /// Whether `predicate` holds only in test builds.
        fn requires_test(predicate: &syn::Meta) -> bool {
            match predicate {
                syn::Meta::Path(path) => path.is_ident("test"),
                syn::Meta::List(list) => {
                    let all = list.path.is_ident("all");
                    if !all && !list.path.is_ident("any") {
                        return false;
                    }
                    let members = list
                        .parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
                        .expect("a cfg predicate's members parse");
                    if all {
                        members.iter().any(requires_test)
                    } else {
                        members.iter().all(requires_test)
                    }
                }
                syn::Meta::NameValue(_) => false,
            }
        }
        fn test_only(attrs: &[syn::Attribute]) -> bool {
            attrs
                .iter()
                .filter(|attr| attr.path().is_ident("cfg"))
                .any(|attr| {
                    requires_test(
                        &attr
                            .parse_args::<syn::Meta>()
                            .expect("a cfg attribute holds one predicate"),
                    )
                })
        }
        fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
            match item {
                syn::Item::Const(item) => &item.attrs,
                syn::Item::Enum(item) => &item.attrs,
                syn::Item::ExternCrate(item) => &item.attrs,
                syn::Item::Fn(item) => &item.attrs,
                syn::Item::ForeignMod(item) => &item.attrs,
                syn::Item::Impl(item) => &item.attrs,
                syn::Item::Macro(item) => &item.attrs,
                syn::Item::Mod(item) => &item.attrs,
                syn::Item::Static(item) => &item.attrs,
                syn::Item::Struct(item) => &item.attrs,
                syn::Item::Trait(item) => &item.attrs,
                syn::Item::TraitAlias(item) => &item.attrs,
                syn::Item::Type(item) => &item.attrs,
                syn::Item::Union(item) => &item.attrs,
                syn::Item::Use(item) => &item.attrs,
                syn::Item::Verbatim(_) => &[],
                other => panic!(
                    "an item kind the census does not classify: {}",
                    quote::quote!(#other)
                ),
            }
        }
        fn impl_item_attrs(item: &syn::ImplItem) -> &[syn::Attribute] {
            match item {
                syn::ImplItem::Const(item) => &item.attrs,
                syn::ImplItem::Fn(item) => &item.attrs,
                syn::ImplItem::Type(item) => &item.attrs,
                syn::ImplItem::Macro(item) => &item.attrs,
                syn::ImplItem::Verbatim(_) => &[],
                other => panic!(
                    "an impl item kind the census does not classify: {}",
                    quote::quote!(#other)
                ),
            }
        }
        fn trait_item_attrs(item: &syn::TraitItem) -> &[syn::Attribute] {
            match item {
                syn::TraitItem::Const(item) => &item.attrs,
                syn::TraitItem::Fn(item) => &item.attrs,
                syn::TraitItem::Type(item) => &item.attrs,
                syn::TraitItem::Macro(item) => &item.attrs,
                syn::TraitItem::Verbatim(_) => &[],
                other => panic!(
                    "a trait item kind the census does not classify: {}",
                    quote::quote!(#other)
                ),
            }
        }
        fn expr_attrs(expr: &syn::Expr) -> &[syn::Attribute] {
            match expr {
                syn::Expr::Array(expr) => &expr.attrs,
                syn::Expr::Assign(expr) => &expr.attrs,
                syn::Expr::Async(expr) => &expr.attrs,
                syn::Expr::Await(expr) => &expr.attrs,
                syn::Expr::Binary(expr) => &expr.attrs,
                syn::Expr::Block(expr) => &expr.attrs,
                syn::Expr::Break(expr) => &expr.attrs,
                syn::Expr::Call(expr) => &expr.attrs,
                syn::Expr::Cast(expr) => &expr.attrs,
                syn::Expr::Closure(expr) => &expr.attrs,
                syn::Expr::Const(expr) => &expr.attrs,
                syn::Expr::Continue(expr) => &expr.attrs,
                syn::Expr::Field(expr) => &expr.attrs,
                syn::Expr::ForLoop(expr) => &expr.attrs,
                syn::Expr::Group(expr) => &expr.attrs,
                syn::Expr::If(expr) => &expr.attrs,
                syn::Expr::Index(expr) => &expr.attrs,
                syn::Expr::Infer(expr) => &expr.attrs,
                syn::Expr::Let(expr) => &expr.attrs,
                syn::Expr::Lit(expr) => &expr.attrs,
                syn::Expr::Loop(expr) => &expr.attrs,
                syn::Expr::Macro(expr) => &expr.attrs,
                syn::Expr::Match(expr) => &expr.attrs,
                syn::Expr::MethodCall(expr) => &expr.attrs,
                syn::Expr::Paren(expr) => &expr.attrs,
                syn::Expr::Path(expr) => &expr.attrs,
                syn::Expr::Range(expr) => &expr.attrs,
                syn::Expr::RawAddr(expr) => &expr.attrs,
                syn::Expr::Reference(expr) => &expr.attrs,
                syn::Expr::Repeat(expr) => &expr.attrs,
                syn::Expr::Return(expr) => &expr.attrs,
                syn::Expr::Struct(expr) => &expr.attrs,
                syn::Expr::Try(expr) => &expr.attrs,
                syn::Expr::TryBlock(expr) => &expr.attrs,
                syn::Expr::Tuple(expr) => &expr.attrs,
                syn::Expr::Unary(expr) => &expr.attrs,
                syn::Expr::Unsafe(expr) => &expr.attrs,
                syn::Expr::While(expr) => &expr.attrs,
                syn::Expr::Yield(expr) => &expr.attrs,
                syn::Expr::Verbatim(_) => &[],
                other => panic!(
                    "an expression kind the census does not classify: {}",
                    quote::quote!(#other)
                ),
            }
        }
        /// The expression an expression statement's outer attributes attach
        /// to: syn moves them onto the leftmost operand of an assignment, a
        /// binary operation or a cast, so `#[cfg(test)] a = b;` carries its
        /// predicate on `a`, and the statement is gated as a whole.
        fn statement_target(mut expr: &syn::Expr) -> &syn::Expr {
            loop {
                expr = match expr {
                    syn::Expr::Assign(assign) => &*assign.left,
                    syn::Expr::Binary(binary) => &*binary.left,
                    syn::Expr::Cast(cast) => &*cast.expr,
                    _ => return expr,
                };
            }
        }
        /// The impl's name in a qualified function: its self type's whole
        /// tokens, as `<Type as Trait>` for a trait impl, the trait's whole
        /// path: two impls on types or traits of one last identifier (other
        /// modules' types, other generic arguments) are two names.
        fn implementation(item: &syn::ItemImpl) -> String {
            let ty = &item.self_ty;
            let ty = quote::quote!(#ty).to_string();
            match &item.trait_ {
                // syn 3 keeps a negative impl's `!` in the impl's modifiers.
                Some((path, _)) => format!(
                    "<{ty} as {}{}>",
                    if item.modifiers.polarity.is_some() {
                        "!"
                    } else {
                        ""
                    },
                    quote::quote!(#path)
                ),
                None => ty,
            }
        }
        /// A `scope` field or binding.
        fn names_scope(expr: &syn::Expr) -> bool {
            match expr {
                syn::Expr::Field(field) => {
                    matches!(&field.member, syn::Member::Named(name) if name == "scope")
                }
                syn::Expr::Path(path) => path.path.is_ident("scope"),
                _ => false,
            }
        }
        /// Sites per (module, qualified function, kind).
        type Census = BTreeMap<(&'static str, String, &'static str), usize>;
        struct Sites<'f> {
            module: &'static str,
            path: Vec<String>,
            found: &'f mut Census,
        }
        impl Sites<'_> {
            fn within(&mut self, segment: String, visit: impl FnOnce(&mut Self)) {
                self.path.push(segment);
                visit(self);
                self.path.pop();
            }
            fn record(&mut self, kind: &'static str) {
                *self
                    .found
                    .entry((self.module, self.path.join("::"), kind))
                    .or_insert(0) += 1;
            }
        }
        impl<'ast> Visit<'ast> for Sites<'_> {
            fn visit_item(&mut self, item: &'ast syn::Item) {
                if !test_only(item_attrs(item)) {
                    syn::visit::visit_item(self, item);
                }
            }
            fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
                if !test_only(impl_item_attrs(item)) {
                    syn::visit::visit_impl_item(self, item);
                }
            }
            fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
                if !test_only(trait_item_attrs(item)) {
                    syn::visit::visit_trait_item(self, item);
                }
            }
            fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
                let attrs: &[syn::Attribute] = match stmt {
                    syn::Stmt::Local(local) => &local.attrs,
                    syn::Stmt::Macro(mac) => &mac.attrs,
                    syn::Stmt::Expr(expr, _) => expr_attrs(statement_target(expr)),
                    // Gated by `visit_item`.
                    syn::Stmt::Item(_) => &[],
                };
                if !test_only(attrs) {
                    syn::visit::visit_stmt(self, stmt);
                }
            }
            fn visit_expr(&mut self, expr: &'ast syn::Expr) {
                if !test_only(expr_attrs(expr)) {
                    syn::visit::visit_expr(self, expr);
                }
            }
            fn visit_arm(&mut self, arm: &'ast syn::Arm) {
                if !test_only(&arm.attrs) {
                    syn::visit::visit_arm(self, arm);
                }
            }
            fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
                if !test_only(&field.attrs) {
                    syn::visit::visit_field_value(self, field);
                }
            }
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_item_mod(sites, item);
                });
            }
            fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                self.within(implementation(item), |sites| {
                    syn::visit::visit_item_impl(sites, item);
                });
            }
            fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_item_trait(sites, item);
                });
            }
            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                self.within(item.sig.ident.to_string(), |sites| {
                    syn::visit::visit_item_fn(sites, item);
                });
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                self.within(item.sig.ident.to_string(), |sites| {
                    syn::visit::visit_impl_item_fn(sites, item);
                });
            }
            fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
                self.within(item.sig.ident.to_string(), |sites| {
                    syn::visit::visit_trait_item_fn(sites, item);
                });
            }
            fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_item_const(sites, item);
                });
            }
            fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_item_static(sites, item);
                });
            }
            fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_impl_item_const(sites, item);
                });
            }
            fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
                self.within(item.ident.to_string(), |sites| {
                    syn::visit::visit_trait_item_const(sites, item);
                });
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(function) = &*call.func
                    && let Some(name) = function.path.segments.last()
                {
                    match name.ident.to_string().as_str() {
                        "release_reference" => self.record("release_reference"),
                        "release_last" => self.record("release_last"),
                        "defer" => self.record("defer"),
                        "drop" => self.record("drop"),
                        "read"
                            if call.args.len() == 1
                                && matches!(
                                    &call.args[0],
                                    syn::Expr::Reference(address) if names_scope(&address.expr)
                                ) =>
                        {
                            self.record("read scope");
                        }
                        _ => {}
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                match call.method.to_string().as_str() {
                    "defer" => self.record("defer"),
                    "cancel_into" => self.record("cancel_into"),
                    "cancel" => self.record("cancel"),
                    _ => {}
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
                if names_scope(&assign.left)
                    && matches!(&*assign.right, syn::Expr::Path(none) if none.path.is_ident("None"))
                {
                    self.record("scope = None");
                }
                syn::visit::visit_expr_assign(self, assign);
            }
        }
        let mut found = Census::new();
        for (module, source) in SOURCES {
            let file = syn::parse_file(source).expect("the shipped source parses");
            Sites {
                module,
                path: Vec::new(),
                found: &mut found,
            }
            .visit_file(&file);
        }
        let mut faults = Vec::new();
        let mut listed = Census::new();
        for &(module, function, kind, sites, inside) in TABLE {
            if listed
                .insert((module, function.to_owned(), kind), sites)
                .is_some()
            {
                faults.push(format!("listed twice: {module} {function} {kind}"));
            }
            if sites == 0 {
                faults.push(format!("a row of no sites: {module} {function} {kind}"));
            }
            if inside && !matches!(kind, "defer" | "cancel_into" | "read scope") {
                faults.push(format!(
                    "inside a cleanup step, released in place: {module} {function} {kind}"
                ));
            }
        }
        for (key @ (module, function, kind), sites) in &found {
            match listed.get(key) {
                None => faults.push(format!("unlisted: {module} {function} {kind} x{sites}")),
                Some(table) if table != sites => faults.push(format!(
                    "{module} {function} {kind}: x{sites}, the table lists x{table}"
                )),
                Some(_) => {}
            }
        }
        for (key @ (module, function, kind), table) in &listed {
            if !found.contains_key(key) {
                faults.push(format!(
                    "{module} {function} {kind}: x0, the table lists x{table}"
                ));
            }
        }
        assert!(faults.is_empty(), "scope reference ends: {faults:#?}");
    }

    /// Retirement into already-abandoned scopes, the schedule the 65-scope
    /// completion does not reach: four scopes, scope `i` holding a holder of
    /// scope `i + 1`'s leaf as a live handle, every authority dropped first,
    /// so each scope is abandoned with its records still held (counted by
    /// its position: the leaf and the holder). Only then are the holders
    /// retired, forward and in reverse, so the chain's next link is reached
    /// only through those later retirements: each retirement drains its own
    /// abandoned scope at its release, its holder's leaf released inside
    /// that drain deferred, never drained in place. Measured: at most one
    /// terminal drain active at any time ([`drains_nested`]); the chain
    /// completes, nothing live, the credit settled, the session concluded.
    /// Planted control `tests/data/controls/deferral-inline-drop.patch` (the
    /// reference dropped in place at `reclaim_under`'s `Done`) drains the
    /// next scope inside the drain releasing it, the finding "more than one
    /// terminal drain was active at once".
    #[cfg(feature = "std")]
    #[test]
    fn retirement_into_abandoned_scopes_never_nests_a_drain() {
        const SCOPES: usize = 4;
        for reverse in [false, true] {
            let session = crate::bounded::Session::new(crate::bounded::Capacity::DEFAULT);
            let mut m = Limits::recorded_unlimited(&session);
            let mut owners: Vec<DecodeOwner<'static, Limits>> = (0..SCOPES)
                .map(|_| {
                    let mut owner = DecodeOwner::new();
                    owner.initialize_step(&mut m).unwrap();
                    owner
                })
                .collect();
            // Scope `i`'s leaf, for `i` past the first.
            let mut leaves: Vec<_> = owners[1..]
                .iter()
                .map(|owner| {
                    Some(published(owner, &mut m, 0u64, |state| {
                        *state = Written::Initialized
                    }))
                })
                .collect();
            // Scope `i`'s holder of scope `i + 1`'s leaf, kept live.
            let mut holders: Vec<_> = owners[..SCOPES - 1]
                .iter()
                .zip(leaves.iter_mut())
                .map(|(owner, leaf)| Some(holder_of(owner, &mut m, [leaf.take()])))
                .collect();
            let mut findings = Findings::new();
            // Abandoned with their records held, none yet queued.
            owners.clear();
            for (at, holder) in holders.iter().enumerate() {
                let outstanding = holder.as_ref().map(|holder| holder.scope().outstanding());
                // The first scope holds its holder; every later one its leaf
                // and its holder.
                let held = if at == 0 { 1 } else { 2 };
                findings.equal(
                    "an abandoned scope's records before the retirements",
                    outstanding,
                    Some(held),
                );
            }
            let order: Vec<usize> = if reverse {
                (0..SCOPES - 1).rev().collect()
            } else {
                (0..SCOPES - 1).collect()
            };
            let nested = drains_nested(|| {
                for at in order {
                    drop(holders[at].take());
                }
            });
            findings.check(nested <= 1, || {
                format!("more than one terminal drain was active at once: {nested}")
            });
            findings.equal("the storage after the chain", m.live_bytes(), 0);
            findings.equal(
                "the chain's credit, conserved with nothing held",
                m.credits().conserved_with(WriteWork::default()),
                Some(true),
            );
            findings.policies([("m", m, READ)]);
            findings.conclude(&[(
                "the retirement session",
                &session.finish(),
                Expected::Complete,
            )]);
        }
    }

    /// Three handles of one abandoned scope released inside one step: the
    /// scope is listed once, its count reaching three; processing performs
    /// two releases, the first of which starts the scope's drain while the
    /// other references remain, then clears the count and performs the
    /// retained release last, which frees the block. Nothing live, the
    /// credit settled, every held handle observed in its holder's custody,
    /// the session concluded complete. The three siblings are dispatched in
    /// one cleanup call. Planted control
    /// `tests/data/controls/deferral-one-release.patch` (one release in place
    /// of `n - 1`) leaks a reference, the finding "a deferred reference was
    /// never performed". Depth restoration between siblings is controlled by
    /// its resource-free witness
    /// (`successive_siblings_each_enter_the_level_after_their_parents`), not
    /// here.
    #[test]
    fn several_handles_of_one_scope_released_in_one_step_are_all_performed() {
        let session = recording();
        let mut m = Limits::recorded_unlimited(&session);
        let mut stepping = DecodeOwner::<'static, Limits>::new();
        stepping.initialize_step(&mut m).unwrap();
        let mut held = DecodeOwner::<'static, Limits>::new();
        held.initialize_step(&mut m).unwrap();
        let inners = core::array::from_fn::<_, 3, _>(|value| {
            Some(published(&held, &mut m, value as u64, |state| {
                *state = Written::Initialized
            }))
        });
        #[cfg_attr(
            not(feature = "std"),
            expect(
                unused_mut,
                reason = "only the std custody observation borrows it mutably"
            )
        )]
        let mut many = holder_of(&stepping, &mut m, inners);
        let mut findings = Findings::new();
        // The holder's custody: its own record's group, then one group per
        // held record (`Holder::observe_permits`), each a permit of its own
        // under the owner of the acquisition that allocated it. Read with
        // `std`, as every custody witness of this module.
        #[cfg(feature = "std")]
        {
            let observed = groups(|sink| many.observe_custody(sink));
            let owners: std::collections::BTreeSet<_> =
                observed.groups.iter().map(|group| group.0).collect();
            let permits: std::collections::BTreeSet<_> = observed
                .groups
                .iter()
                .flat_map(|group| group.1.iter().map(|(id, _)| *id))
                .collect();
            findings.check(
                observed.groups.len() == 4
                    && observed.groups.iter().all(|group| group.1.len() == 1)
                    && owners.len() == 4
                    && !owners.contains(&None)
                    && permits.len() == 4,
                || {
                    format!(
                        "the holder's custody does not report its three held records, each \
                         under its own owner: {:?}",
                        observed.groups
                    )
                },
            );
        }
        // Abandoned while its three records are held.
        drop(held);
        drop(many);
        // The removal, then the one call stepping all three siblings.
        shut_down_into(&mut findings, &mut stepping, &mut m, 1);
        drop(stepping);
        findings.equal(
            "a deferred reference was never performed",
            m.live_bytes(),
            0,
        );
        findings.equal(
            "the credit, conserved with nothing held",
            m.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.policies([("m", m, READ)]);
        findings.conclude(&[(
            "the several-handles session",
            &session.finish(),
            Expected::Complete,
        )]);
    }

    /// A scope whose initialization is refused between its terminal-dispatch
    /// unit and its deferral unit, the last admission initialization makes
    /// (its index read from an unrefused run, not assumed): no reference is
    /// exposed and the scope is not ready. Dropped there, the block is freed
    /// with neither field read, nothing live. Retried instead, only the
    /// deferral unit is admitted, the dispatch not written again, and the
    /// scope completes and shuts down holding nothing.
    #[test]
    fn a_scope_refused_between_its_dispatch_and_its_deferral_drops_or_retries_clean() {
        let mut unrefused = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut unrefused).unwrap();
        let deferral_unit = unrefused.attempts() - 1;
        shut_down(&mut owner, &mut unrefused);
        drop(owner);
        for retried in [false, true] {
            let mut m = Limits::unlimited().refusing(Some(deferral_unit));
            let mut owner = DecodeOwner::<'static, Limits>::new();
            assert!(matches!(
                owner.initialize_step(&mut m),
                Err(BoundedError::Refused(_))
            ));
            assert!(
                owner.dispatch,
                "{retried}: the dispatch unit was not written"
            );
            assert!(!owner.ready, "{retried}: ready before the deferral unit");
            assert!(
                owner.reference().is_none(),
                "{retried}: a reference exposed"
            );
            assert_ne!(m.live_bytes(), 0, "{retried}: the block is held");
            if retried {
                m.clear_refusal();
                let attempts = m.attempts();
                owner
                    .initialize_step(&mut m)
                    .expect("the deferral unit alone");
                assert_eq!(
                    m.attempts(),
                    attempts + 1,
                    "the retry admitted more than the deferral unit"
                );
                assert!(owner.ready);
                shut_down(&mut owner, &mut m);
            }
            drop(owner);
            assert_eq!(m.live_bytes(), 0, "{retried}: the block outlived the scope");
            assert_eq!(m.credits().conserved_with(WriteWork::default()), Some(true));
        }
    }

    /// An acquisition cancelled, or dropped, between its two stages frees its
    /// granted block without its owner, a release paid for, and leaves no
    /// record outstanding: the scope shuts down holding nothing.
    #[test]
    fn an_acquisition_stopped_between_its_stages_frees_its_block() {
        for cancelled in [true, false] {
            let mut scope_family = Limits::unlimited();
            let mut owner = DecodeOwner::<'static, Limits>::new();
            owner.initialize_step(&mut scope_family).unwrap();
            let mut m = Limits::unlimited().refusing(Some(owner_unit_attempt()));
            let mut acquisition = Acquisition::<u64, Limits>::new();
            assert!(owner.allocate_step(&mut m, &mut acquisition).is_err());
            assert_eq!(owner.outstanding(), 1, "the granted block is outstanding");
            assert_ne!(m.live_bytes(), 0);
            let attempts = m.attempts();
            if cancelled {
                acquisition.cancel(Performer::None);
                assert!(acquisition.granted.is_none() && acquisition.scope.is_none());
            }
            drop(acquisition);
            assert_eq!(
                m.attempts(),
                attempts,
                "{cancelled}: the release was admitted again"
            );
            assert_eq!(m.live_bytes(), 0, "{cancelled}: the granted block was kept");
            assert_eq!(owner.outstanding(), 0, "{cancelled}: still outstanding");
            assert_eq!(m.credits().conserved_with(WriteWork::default()), Some(true));
            shut_down(&mut owner, &mut scope_family);
        }
    }

    /// The attempt index of a record acquisition's owner unit, read from an
    /// unrefused acquisition rather than assumed: every call a policy makes
    /// is an attempt, work and allocation alike (`Limits::refusing`), so the
    /// head stage's write, release and request precede it.
    fn owner_unit_attempt() -> usize {
        let mut family = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut family).unwrap();
        let mut m = Limits::unlimited();
        let record = owner
            .allocate_step::<u64>(&mut m, &mut Acquisition::new())
            .expect("an unlimited policy acquires a record");
        let unit = m.attempts() - 1;
        drop(record);
        shut_down(&mut owner, &mut family);
        unit
    }

    /// A record reports one owner association for its whole life: the owner
    /// of the acquisition that allocated it, read from the entry, under its
    /// handle before publication, under the published handle, and from the
    /// queue once retired, never the scope's owner.
    #[cfg(feature = "std")]
    #[test]
    fn a_record_keeps_its_acquisitions_owner_through_publication_and_retirement() {
        let session = recording();
        let mut scope_family = Limits::recorded_unlimited(&session);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut scope_family).unwrap();
        let mut m = Limits::recorded_unlimited(&session);
        let mut acquisition = Acquisition::<u64, Limits>::new();
        let mut record = owner.allocate_step(&mut m, &mut acquisition).unwrap();
        let token = acquisition
            .pending
            .owner_id()
            .expect("made by the first entry");
        let authority = owner.pending.owner_id().expect("made by initialization");
        assert_ne!(token, authority, "the token's owner is the scope's");
        let before = groups(|sink| record.observe_custody(sink));
        assert_eq!(before.groups.len(), 1);
        assert_eq!(before.groups[0].0, Some(token), "before publication");
        {
            let mut slot = record.destination();
            let (place, state) = slot.parts();
            // SAFETY: the record's own place and state, nothing written.
            unsafe { place.write(state, 7u64) };
            *state = Written::Initialized;
        }
        // SAFETY: the `u64` is written and its state records it.
        let mut published = unsafe { record.publish() };
        let after = groups(|sink| published.observe_custody(sink));
        assert_eq!(after.groups, before.groups, "after publication");
        drop(published);
        let queued = groups(|sink| owner.observe_custody(sink));
        assert_eq!(
            before.groups[0].1[0].1,
            Some(crate::bounded::RecordStage::Handle),
            "before retirement, the handle's"
        );
        let record_group = queued
            .groups
            .iter()
            .find(|group| group.1.iter().map(|(id, _)| *id).eq(before.permits(0)))
            .expect("the retired record is reported by the queue");
        assert_eq!(record_group.0, Some(token), "after queue retirement");
        assert_eq!(
            record_group.1[0].1,
            Some(crate::bounded::RecordStage::Queued),
            "after retirement, the queue's"
        );
        assert_eq!(queued.groups[0].0, Some(authority), "the scope's own group");
        drop(acquisition);
        shut_down(&mut owner, &mut scope_family);
        drop(owner);
        let mut findings = Findings::new();
        findings.policies([("m", m, READ), ("the scope's family", scope_family, READ)]);
        findings.conclude(&[("the session", &session.finish(), Expected::Complete)]);
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
            scope_contract::<Limits>().write(),
            const { scope_contract::<Limits>() }.write()
        );
        assert_eq!(
            scope_contract::<Limits>().block(),
            const { scope_contract::<Limits>() }.block()
        );
    }
}
