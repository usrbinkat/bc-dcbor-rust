//! Typed construction from an owned document, and typed decoding as parse
//! followed by construction.
//!
//! The constructed value is built in its final stable record. After it is
//! complete the document's input handle moves into the record without copying
//! (identity and signature checks keep the original bytes), and the document's
//! record, holding only its arena, is retired to the scope queue.
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use super::Context;
use super::in_place::{self, Built, InPlace, Session, Transferable};
use super::input::DecodeInput;
use super::operation::{Observed, Operation, OperationTerms, Position, Task};
use super::parse::{
    DocumentDecoder, InputClassOf, InputObservation, OwnedDocument, ParseClass, ParseDetail,
};
use super::reclamation::{
    Cleanup, Custody, EMPTIED, Mode, OwnedInitialized, PeekSlot, Place, Prefix, Reclaim, Reclaimed,
    ScopeRef, Slot, reclaim_within, slot_place,
};
use super::stable::{self, PENDING_UNITS, Pending};
use crate::bounded::boundary::{Bound, Predicate};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::{ConstructResult, DecodeError};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Budget, Custodial, CustodySink, PermitsObserved,
    Places, ResourceBound, Resumable, Step, TerminalAllocator, Unit, WriteWork, at, observed_all,
};

places! {
    /// The places a construction's task charges ([`Construction`]), one term
    /// of [`construction_bound`]'s task each.
    pub(crate) enum ConstructPlace {
        /// The value's construction and cleanup ([`InPlace::COST`]).
        Build,
        Detach,
        Publish,
        /// The record's cleanup: its transition and its emptied slots.
        Cleanup,
        /// The document the record holds until detachment, accounted by its
        /// parse ([`super::parse_bound`]).
        Document,
        /// The input the record holds after detachment, accounted by its
        /// acquisition ([`super::copy_bound`], [`super::borrow_bound`]).
        Input,
    }
}

/// Detaching the document's input.
const DETACH: Unit<ConstructPlace> = Unit::new(ConstructPlace::Detach, 1, 0);

/// Publishing the value.
const PUBLISH: Unit<ConstructPlace> = Unit::new(ConstructPlace::Publish, 1, 0);

/// A construction record entering its cleanup, or released before its
/// initialization completed.
const CLEANUP: Unit<ConstructPlace> = Unit::new(ConstructPlace::Cleanup, 1, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConstructPhase {
    Build,
    Detach,
    Publish,
    Published,
    ReclaimValue,
    ReclaimDocument,
    ReclaimInput,
    Done,
}

/// The construction record. Public only as the unnameable state of
/// [`Construct`].
pub struct Constructed<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> {
    /// Everything the record holds besides the value.
    custody: ConstructCustody<'s, I, T, A>,
    value: MaybeUninit<T>,
}

/// A construction record's own custody ([`Place::custody`]): the document
/// it holds until detachment, the input it holds after, the value's
/// construction state, the phase, and the credit of the one acquisition
/// the value's construction holds pending. Initialized field by field, the
/// pending credit one unit per its own field ([`PENDING_UNITS`]); reached
/// whole, once initialized, through one exclusive borrow of the record's
/// progress, its fields then borrowing disjointly.
struct ConstructCustody<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> {
    document: Option<OwnedDocument<'s, I, A>>,
    input: Option<OwnedInitialized<'s, I, A>>,
    /// The value's session over its own construction state: the root's
    /// binding, which the engine binds to the document's root node, the
    /// document this record owns.
    build: Session<T::State>,
    phase: ConstructPhase,
    /// The value's construction's pending acquisition, whose credit is held
    /// here once and by no part of the value's state; its owner is this
    /// record's, minted when its unit is written. The record's own
    /// acquisition, by the operation's scope, is not among it: that credit
    /// stays with the operation's acquisition, outside the record it
    /// acquires.
    pending: Pending<A::Origin>,
}

impl<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> Constructed<'s, I, T, A> {
    /// The fields written before the pending credit's: document, input,
    /// session and phase.
    const OWN_STEPS: usize = 4;

    /// Every custody field's unit: the record's own, then the pending
    /// credit's ([`PENDING_UNITS`]).
    const INIT_STEPS: usize = Self::OWN_STEPS + PENDING_UNITS;

    /// The pending credit's initialized units, from the record's progress.
    const fn pending_units(initialized: usize) -> usize {
        initialized.saturating_sub(Self::OWN_STEPS)
    }

    /// The value's place within the record's, in the record's mode: the one
    /// projection its construction, its cleanup and its count share.
    fn value<M: Mode>(slot: &mut Slot<'_, Self, Prefix, M>) -> Place<T, M> {
        let (place, _) = slot.parts();
        // SAFETY: a field projection by raw pointer within the slot's own
        // record, forming no reference; `MaybeUninit<T>` lays out a `T` at
        // its start.
        unsafe { place.project(|record| addr_of_mut!((*record).value).cast::<T>()) }
    }

    /// The record's whole custody, for as long as the slot is borrowed;
    /// refused unless its progress records every custody field initialized.
    fn custody<'p, M: Mode, R>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Result<&'p mut ConstructCustody<'s, I, T, A>, BoundedError<R>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() < Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records every custody field initialized; the custody field is
        // disjoint from the value, no place lies within it, and no reader
        // of the published value borrows it.
        Ok(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody)) })
    }

    /// The document slot alone, for as long as the slot is borrowed: what
    /// the record holds before its other custody fields are initialized;
    /// `None` before the document field is.
    fn document<'p, M: Mode>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Option<&'p mut Option<OwnedDocument<'s, I, A>>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() == 0 {
            return None;
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records the document field initialized; the projection reaches that
        // field alone.
        Some(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody.document)) })
    }

    /// The record's observation ([`ConstructDetail`]), the one every holder
    /// of it reads: its construction task, and an owned preparation holding
    /// the published value ([`TypedValue::detail`]). `unwritten` is the
    /// document's observation while the record's document field is not
    /// written (a task that still holds the document, or none). Each custody
    /// field is read only once the prefix records it written: the document
    /// and the input through their own exclusive custody
    /// ([`OwnedDocument::detail`], [`OwnedInitialized::state`]), whose
    /// cleanups are this record's, and the value's construction state under
    /// the prefix's exclusive borrow; the value, which a reader of the
    /// published record may hold borrowed, is never read. Nothing is
    /// changed, admitted or allocated.
    fn detail<M: Mode>(
        slot: &mut Slot<'_, Self, Prefix, M>,
        unwritten: Option<ParseDetail<InputObservation<I, A>>>,
    ) -> ConstructDetail<InputObservation<I, A>, <Session<T::State> as Custody>::Observation> {
        let (place, prefix) = slot.parts();
        let initialized = prefix.initialized();
        // SAFETY: the slot pairs the record's place with its progress; each
        // custody field is read only once the prefix records it written,
        // through a view of that field alone, the prefix borrowed for each
        // read; no custody field is borrowed by a reader of the published
        // value, and the value itself is never read.
        unsafe {
            ConstructDetail {
                document: if initialized > 0 {
                    place
                        .custody(&mut *prefix, |record| {
                            addr_of_mut!((*record).custody.document)
                        })
                        .as_mut()
                        .map(OwnedDocument::detail)
                } else {
                    unwritten
                },
                input: if initialized > 1 {
                    place
                        .custody(&mut *prefix, |record| addr_of_mut!((*record).custody.input))
                        .as_mut()
                        .map(OwnedInitialized::state)
                } else {
                    None
                },
                build: (initialized > 2).then(|| {
                    place
                        .custody(&mut *prefix, |record| addr_of_mut!((*record).custody.build))
                        .observe()
                }),
                phase: (initialized > 3).then(|| {
                    *place
                        .project(|record| addr_of_mut!((*record).custody.phase))
                        .get(&*prefix)
                }),
            }
        }
    }
}

// SAFETY: initial: no prefix unit initialized. state: the prefix (the
// document handle, the input slot, the value's initial construction state,
// the phase and the pending credit's units), the value's own state and the
// session record everything initialized and acquired. admission: each
// cleanup unit, the record's and the value's (through its session), is
// admitted before it runs, a refusal changing nothing. cleanup: it settles
// the pending credit at its entry, reclaims the value through its own
// state, then the document and the input in place, and drops the pending
// credit's written units in place; no destructor of T runs, nothing is
// allocated and nothing unwinds. done: `Done` once the value, the document
// and the input are released; an incomplete prefix's release leaves it
// released (`Prefix::release`). order: a step after `Done` reports `Done`,
// admitting nothing, from `ConstructPhase::Done` or a released prefix alike;
// the count and observation read only the recorded prefix and state,
// nothing of a released prefix, and never the dropped pending. depth:
// the larger of `T`'s plus one and the input's plus three, the two chains its
// cleanup dispatches. count: the value's remaining plus the record's own
// units, composed checked.
unsafe impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Reclaim<A>
    for Constructed<'_, I, T, A>
{
    const DISPATCH_DEPTH: usize = {
        let value = T::DISPATCH_DEPTH.saturating_add(1);
        let input = I::DISPATCH_DEPTH.saturating_add(3);
        if value > input { value } else { input }
    };
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(
        mut slot: Slot<'_, Self, Prefix>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        let a = cleanup;
        // Released: terminal, `Done` admitting nothing.
        if slot.custody().released() {
            return Ok(Reclaimed::Done);
        }
        if Bound::new(Predicate::Prefix, Self::INIT_STEPS).below(a, slot.custody().initialized()) {
            if let Some(document) = Self::document(&mut slot)
                && document.is_some()
            {
                at(ConstructPlace::Document, || {
                    OwnedDocument::reclaim_under(document, a)
                })?;
                return Ok(Reclaimed::Progress);
            }
            // The rest of the prefix holds no admitted credit: the empty
            // input slot, the value's initial state, the phase, and the
            // pending credit's written units, idle (no acquisition binds
            // before the prefix is complete), whose owner is dropped in
            // place after the admitted unit.
            CLEANUP.admit(a)?;
            let (place, prefix) = slot.parts();
            let written = Self::pending_units(prefix.initialized());
            let raw = place.as_ptr(prefix);
            // SAFETY: the progress records exactly `written` units of the
            // pending credit initialized; the projection forms no reference,
            // and the progress is released below, so nothing reads them
            // again.
            unsafe { stable::drop_pending(addr_of_mut!((*raw).custody.pending), written) };
            slot.custody().release();
            return Ok(Reclaimed::Done);
        }
        let value = Self::value(&mut slot);
        let ConstructCustody {
            document,
            input,
            build,
            phase,
            pending,
        } = Self::custody(&mut slot)?;
        match *phase {
            ConstructPhase::ReclaimValue => {
                // SAFETY: the value's place, paired with its session, which
                // the record keeps beside it and which describes every
                // initialized part.
                if at(ConstructPlace::Build, || {
                    in_place::reclaim::<T, A>(unsafe { Slot::new(value, &mut *build) }, a)
                })? == Reclaimed::Done
                {
                    *phase = ConstructPhase::ReclaimDocument;
                }
            }
            ConstructPhase::ReclaimDocument => {
                let charge =
                    slot_place(document, ConstructPlace::Document, ConstructPlace::Cleanup);
                if at(charge, || OwnedDocument::reclaim_under(document, a))? == Reclaimed::Done {
                    *phase = ConstructPhase::ReclaimInput;
                }
            }
            ConstructPhase::ReclaimInput => {
                let charge = slot_place(input, ConstructPlace::Input, ConstructPlace::Cleanup);
                if at(charge, || OwnedInitialized::reclaim_under(input, a))? == Reclaimed::Done {
                    *phase = ConstructPhase::Done;
                    // The record's last unit: the pending credit, idle since
                    // cleanup's entry, dropped in place, releasing its
                    // owner's session reference. Nothing reads it in `Done`.
                    // SAFETY: every unit of it is initialized and settled,
                    // and no later step or observation of a `Done` record
                    // reads the pending credit.
                    unsafe { stable::drop_pending(core::ptr::from_mut(pending), PENDING_UNITS) };
                    return Ok(Reclaimed::Done);
                }
            }
            ConstructPhase::Done => return Ok(Reclaimed::Done),
            _ => {
                // Cleanup's entry, in this order: the pending acquisition's
                // credit settled by origin, explicitly, each obligation
                // forfeited into the family that admitted it under this
                // step's performer, and the pending idle (never through a
                // retained obligation's drop); then the admitted transition;
                // then the value's installed resources, reclaimed from
                // `ReclaimValue` on. Settlement is idempotent, so a refused
                // transition retried settles nothing twice.
                pending.settle_all(a.performer());
                CLEANUP.admit(a)?;
                *phase = ConstructPhase::ReclaimValue;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held document's own calls, then
    /// the one releasing the record. After it: the transition into cleanup
    /// unless it has begun, the value's own count, the document slot's and
    /// the input slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> Option<u64> {
        // Released: the one call reporting `Done`.
        if slot.custody().released() {
            return Some(1);
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::document(&mut slot) {
                Some(document) if document.is_some() => {
                    OwnedDocument::remaining(document)?.checked_add(1)
                }
                _ => Some(1),
            };
        }
        // The value, which a reader of the published record may hold
        // borrowed, is never reborrowed: its place is observed.
        let value = Self::value(&mut slot);
        let Ok(ConstructCustody {
            document,
            input,
            build,
            phase,
            ..
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return Some(1);
        };
        let phase = *phase;
        let input = OwnedInitialized::remaining(input)?;
        let document = OwnedDocument::remaining(document)?.checked_add(input)?;
        // SAFETY: the value's place, observed, paired with its own session,
        // as its cleanup steps it.
        let value = super::in_place::remaining::<T, A>(unsafe { Slot::new(value, build) })?
            .checked_add(document)?;
        match phase {
            ConstructPhase::Done => Some(1),
            ConstructPhase::ReclaimInput => Some(input),
            ConstructPhase::ReclaimDocument => Some(document),
            ConstructPhase::ReclaimValue => Some(value),
            _ => value.checked_add(1),
        }
    }

    /// The record's value's custody, each independently owning part a group
    /// of its own inside the record's ([`CustodySink`]): the document, while
    /// held, under the owner its own record stores
    /// ([`OwnedDocument::observe_custody`]); once the prefix is complete and
    /// until the record's last unit drops it, the value's construction, a
    /// group under the owner its pending stores, every acquisition of the
    /// value's bound under it: the pending's held obligations
    /// ([`Pending::observe_custody`]) and the value's permits
    /// ([`in_place::observe_permits`]); and the detached input, under the
    /// owner its own record stores. The prefix's pending units hold no
    /// credit (no acquisition binds before the prefix is complete) and its
    /// value holds nothing. Read-only; the completeness of every part,
    /// combined.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Prefix>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        // Released: nothing held, nothing read.
        if slot.custody().released() {
            return PermitsObserved::Complete;
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::document(&mut slot) {
                Some(Some(document)) => document.observe_custody(sink),
                _ => PermitsObserved::Complete,
            };
        }
        // The value, which a reader of the published record may hold
        // borrowed, is never reborrowed: its place is observed.
        let value = Self::value(&mut slot);
        let Ok(ConstructCustody {
            document,
            input,
            build,
            phase,
            pending,
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return PermitsObserved::Complete;
        };
        let document = match document {
            Some(document) => document.observe_custody(sink),
            None => PermitsObserved::Complete,
        };
        let construction = if *phase == ConstructPhase::Done {
            // The record's last unit dropped the pending in place, after the
            // value's cleanup released everything it held.
            PermitsObserved::Complete
        } else {
            sink.begin(pending.owner_id());
            let held = pending.observe_custody(sink);
            // SAFETY: the value's place, observed, paired with its own
            // session, as its cleanup count reads it.
            let owned = in_place::observe_permits::<T, A>(unsafe { Slot::new(value, build) }, sink);
            sink.end();
            observed_all([held, owned])
        };
        let input = match input {
            Some(input) => input.observe_custody(sink),
            None => PermitsObserved::Complete,
        };
        observed_all([document, construction, input])
    }
}

/// Observation of a construction, `N` its input's state observation and `O`
/// its value's custody observation: the record's phase; the document's
/// record observed ([`OwnedDocument::detail`]) while the record, or before
/// the record holds it the task, holds it; the detached input's state while
/// the record holds it; and the value's construction state, observed whole,
/// once the record's prefix is written. The document's and the input's
/// cleanups are the record's, so their states, not only their presence, are
/// observed. Whether an acquisition of the value's construction is bound is
/// the record's custody's to report ([`CustodySink::bound`], from
/// [`Pending::observe_custody`]), not its progress's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConstructDetail<N, O> {
    pub phase: Option<ConstructPhase>,
    pub document: Option<ParseDetail<N>>,
    pub input: Option<N>,
    pub build: Option<O>,
}

pub struct Construct<'s, I: DecodeInput<A>, T, A: Allocator> {
    document: Option<OwnedDocument<'s, I, A>>,
    marker: core::marker::PhantomData<fn() -> T>,
}

// SAFETY: prefix: initialization moves the document handle in and writes
// three resource-free fields, one unit each, recorded as it is written;
// every prefix is reclaimable by `Constructed`'s cleanup, and past
// `INIT_STEPS`, or once released, it refuses, changing nothing. advance:
// refused until the prefix is whole, a released prefix recording none;
// every later phase is recorded before it acquires, and
// completion is reported only once the value is built whole. detail:
// `detail` and `observe_custody` read only the recorded prefix and the
// value's observation, changing, admitting and allocating nothing.
// provenance: every field and the value are reached through the record's
// slot place, by raw projection.
unsafe impl<'s, I, T, A> Task<'s, A> for Construct<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    type State = Constructed<'s, I, T, A>;
    type Output = TypedValue<'s, I, T, A>;
    type Error = DecodeError<A::Refusal>;
    type Detail =
        ConstructDetail<InputObservation<I, A>, <Session<T::State> as Custody>::Observation>;
    const INIT_STEPS: usize = Constructed::<'s, I, T, A>::INIT_STEPS;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.document.as_ref().map(OwnedDocument::scope)
    }

    fn initialized(prefix: &Prefix) -> usize {
        prefix.initialized()
    }

    fn initialize(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let (place, prefix) = slot.parts();
        // A released record is terminal: nothing is written again.
        if prefix.released() {
            return Err(BoundedError::PlanMismatch.into());
        }
        let raw = place.as_ptr(prefix);
        // SAFETY: the slot pairs the record's place with its progress, so the
        // unit the progress names next is uninitialized; each unit writes
        // that one custody field by raw projection, forming no reference to
        // the rest, and every unit past the last is refused.
        unsafe {
            match prefix.initialized() {
                0 => field(
                    addr_of_mut!((*raw).custody.document),
                    || self.document.take(),
                    a,
                )?,
                1 => field(addr_of_mut!((*raw).custody.input), || None, a)?,
                2 => field(
                    addr_of_mut!((*raw).custody.build),
                    || Session::new(T::INITIAL),
                    a,
                )?,
                3 => field(
                    addr_of_mut!((*raw).custody.phase),
                    || ConstructPhase::Build,
                    a,
                )?,
                written if Bound::new(Predicate::Prefix, Self::INIT_STEPS).below(a, written) => {
                    let unit = Constructed::<'s, I, T, A>::pending_units(written);
                    // The record's owner, minted with the pending credit's
                    // head, the unit that stores it: the one capability of
                    // this custody, held in the pending credit alone.
                    let owner = if unit == 0 {
                        Some(a.owner().map_err(BoundedError::Refused)?)
                    } else {
                        None
                    };
                    stable::initialize_pending(
                        addr_of_mut!((*raw).custody.pending),
                        unit,
                        owner,
                        a,
                    )?
                }
                _ => return Err(BoundedError::PlanMismatch.into()),
            }
        }
        prefix.advance();
        Ok(())
    }

    /// The value's acquisitions bind on the pending the record keeps, under
    /// the owner the record's construction group reports: the operation's
    /// pending is left idle.
    fn advance(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        _: &mut Pending<A::Origin>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // The value is reached only through its place; the custody is refused
        // until initialization is complete.
        let value = Constructed::value(&mut slot);
        let ConstructCustody {
            document,
            input,
            build,
            phase,
            pending,
        } = Constructed::custody(&mut slot)?;
        match *phase {
            ConstructPhase::Build => {
                let document = document.as_ref().ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the value's place and its session, kept in the
                // record's custody, are retained across every call; the
                // document view ends with this call. The context is minted
                // here, from the document this record owns and the pending
                // credit it keeps, at its root: the only context the value's
                // construction ever receives.
                let built = at(ConstructPlace::Build, || {
                    document.with_document(|view| {
                        let slot = unsafe { Slot::new(value, &mut *build) };
                        in_place::build::<T, A>(Context::root(view, slot, &mut *pending), a)
                    })
                })?;
                if built == Built::Done {
                    *phase = ConstructPhase::Detach;
                }
            }
            ConstructPhase::Detach => {
                DETACH.admit(a)?;
                let document = document.take().ok_or(BoundedError::PlanMismatch)?;
                // The input moves without copying; the document's arena and
                // parser record is retired to the scope queue.
                *input = Some(document.into_input());
                *phase = ConstructPhase::Publish;
            }
            ConstructPhase::Publish => {
                // A value is published only with no credit pending: every
                // acquisition of its construction ended.
                if !pending.is_idle() {
                    return Err(BoundedError::PlanMismatch.into());
                }
                PUBLISH.admit(a)?;
                *phase = ConstructPhase::Published;
                return Ok(true);
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(false)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output {
        TypedValue { record }
    }

    fn reclaim_step(&mut self, cleanup: &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A> {
        let place = slot_place(
            &self.document,
            ConstructPlace::Document,
            ConstructPlace::Cleanup,
        );
        at(place, || {
            OwnedDocument::reclaim_under(&mut self.document, cleanup)
        })
    }

    /// The task holds no pending credit of its own: the value's
    /// construction keeps its pending acquisition in the record's custody,
    /// settled at the record's own cleanup entry ([`Constructed`]).
    fn settle(&mut self, _: crate::bounded::Performer) {}

    /// The task's custody outside its record: the document while the task,
    /// not yet its record, holds it, under the owner its own record stores
    /// ([`OwnedDocument::observe_custody`]). Everything inside the record is
    /// the record's to report ([`Constructed`]'s
    /// [`Reclaim::observe_permits`]).
    fn observe_custody(
        &mut self,
        _: Observed<'_, 's, Self, A>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        match self.document.as_mut() {
            Some(document) => document.observe_custody(sink),
            None => PermitsObserved::Complete,
        }
    }

    /// The record's observation ([`Constructed::detail`]), the document the
    /// task still holds observed while the record's document field is
    /// unwritten.
    fn detail(&mut self, record: Observed<'_, 's, Self, A>) -> Self::Detail {
        let held = self.document.as_mut().map(OwnedDocument::detail);
        match record {
            Some(mut slot) => Constructed::detail(&mut slot, held),
            None => ConstructDetail {
                phase: None,
                document: held,
                input: None,
                build: None,
            },
        }
    }
}

/// A published typed value with its original input. Moving the handle never
/// moves the value; dropping it queues the record for scope cleanup.
pub struct TypedValue<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: OwnedInitialized<'s, Constructed<'s, I, T, A>, A>,
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> TypedValue<'s, I, T, A> {
    /// The dispatch depth of the construction record behind this handle.
    pub(crate) const DISPATCH_DEPTH: usize =
        <Constructed<'s, I, T, A> as Reclaim<A>>::DISPATCH_DEPTH;

    /// The scope holding this value's record.
    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        self.record.scope()
    }

    pub fn value(&self) -> &T {
        // SAFETY: publication follows a completed build.
        unsafe { self.record.value().value.assume_init_ref() }
    }

    /// The original input the value was decoded from.
    pub fn input(&self) -> &I {
        match self.record.value().custody.input.as_ref() {
            Some(input) => input.value(),
            None => unreachable!("a published value retains its input"),
        }
    }

    /// The original input bytes the value was decoded from. Identity and
    /// signature checks run over these, never over a re-encoding, which may
    /// differ when decoding skipped unknown fields.
    pub fn bytes(&self) -> &[u8] {
        self.input().bytes()
    }

    /// Operation-local cleanup of this value and its input, the cleanup
    /// capability minted here over `a`.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        super::reclamation::with_cleanup(a, |cleanup| Self::reclaim_under(slot, cleanup))
    }

    /// [`Self::reclaim_step`] under `cleanup`, a capability already minted:
    /// how a cleanup that holds this handle (an owned preparation's record
    /// or task, or a third-party binding's state) steps it
    /// ([`OwnedInitialized::reclaim_under`]).
    pub fn reclaim_under(
        slot: &mut Option<Self>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            cleanup,
            |value| value.record,
            |record| Self { record },
            OwnedInitialized::reclaim_under,
        )
    }

    /// The value's record observed ([`Constructed::detail`]): what a holder
    /// stepping its cleanup (an owned preparation's record or task) reads of
    /// it. `&mut self` excludes every reader of the value meanwhile; nothing
    /// is changed, admitted or allocated.
    pub fn detail(
        &mut self,
    ) -> ConstructDetail<InputObservation<I, A>, <Session<T::State> as Custody>::Observation> {
        Constructed::detail(&mut self.record.destination(), None)
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedInitialized::remaining`]).
    pub fn remaining(slot: &mut Option<Self>) -> Option<u64> {
        let mut record = slot.take().map(|value| value.record);
        let remaining = OwnedInitialized::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }
}

/// The [`ResourceBound`] of constructing `T` from an owned document of at
/// most `len` bytes ([`Construction`]): the record, initialized in four
/// fields; `T`'s own construction and cleanup ([`InPlace::COST`], its subtree
/// at most the input); the document's detachment and publication; and the
/// record's cleanup units around the value: its transition and the empty
/// document and input slots. The document and the input are accounted by
/// their own operations. The value and its record are what publication
/// retains.
pub fn construction_bound<I, T, A, R>(len: u64) -> Result<ResourceBound, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    construct_terms::<I, T, A, R>(len, ResourceBound::default(), ResourceBound::default())?
        .0
        .bound()
}

/// The terms of a construction ([`construction_bound`]): its operation's,
/// whose task is the second's, the record holding a document whose own
/// cleanup is `document` and an input whose own cleanup is `input`. The
/// record's size and initialization do not depend on its scope.
pub(crate) fn construct_terms<I, T, A, R>(
    len: u64,
    document: ResourceBound,
    input: ResourceBound,
) -> Result<(OperationTerms, ConstructTerms), BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    let task = ConstructTerms::of::<T, A, R>(len, document, input)?;
    let operation = OperationTerms::of::<Constructed<'static, I, T, A>, A, R>(
        Constructed::<'static, I, T, A>::INIT_STEPS,
        task.bound()?,
    )?;
    Ok((operation, task))
}

/// The terms of a construction's task, one per [`ConstructPlace`].
pub(crate) struct ConstructTerms {
    build: ResourceBound,
    detach: WriteWork,
    publish: WriteWork,
    cleanup: WriteWork,
    document: ResourceBound,
    input: ResourceBound,
}

impl ConstructTerms {
    /// The task of constructing `T` from a document of at most `len` bytes,
    /// the record holding a document whose own cleanup is `document` and an
    /// input whose own cleanup is `input`.
    pub(crate) fn of<T: InPlace<A>, A: Allocator, R>(
        len: u64,
        document: ResourceBound,
        input: ResourceBound,
    ) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            // The value's own cost and its session's two transitions.
            build: in_place::root_cost(T::COST)
                .ok_or(BoundedError::Overflow)?
                .bound(len)?,
            detach: DETACH.times(1)?,
            publish: PUBLISH.times(1)?,
            // The record's transition, or its release before initialization
            // completed; then two emptied slots: the record never holds both
            // the document and the input, and the task's document moved into
            // the record at its first initialization unit.
            cleanup: CLEANUP
                .times(1)?
                .checked_then(EMPTIED.times(2)?)
                .ok_or(BoundedError::Overflow)?,
            document,
            input,
        })
    }
}

impl Places for ConstructTerms {
    type Place = ConstructPlace;

    fn term(&self, place: ConstructPlace) -> ResourceBound {
        match place {
            ConstructPlace::Build => self.build,
            ConstructPlace::Detach => ResourceBound::of_work(self.detach),
            ConstructPlace::Publish => ResourceBound::of_work(self.publish),
            ConstructPlace::Cleanup => ResourceBound::of_work(self.cleanup),
            ConstructPlace::Document => self.document,
            ConstructPlace::Input => self.input,
        }
    }
}

/// The [`ResourceBound`] of decoding `T` from an input handle of at most
/// `len` bytes ([`TypedDecoder`]): the parse under `T`'s wire profile
/// ([`super::parse::parse_bound`], [`InPlace::WIRE`]), then the construction
/// while the document is still held ([`construction_bound`]). Both records
/// are what publication retains until the scope reclaims the document's.
pub fn typed_decode_bound<I, T, A, R>(len: u64) -> Result<ResourceBound, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    super::parse::parse_bound::<I, A, R>(len, T::WIRE)?
        .checked_then(construction_bound::<I, T, A, R>(len)?)
        .ok_or(BoundedError::Overflow)
}

/// Construction from an owned document.
pub type Construction<'s, I, T, A> = Operation<'s, Construct<'s, I, T, A>, A>;

impl<'s, I, T, A> Construction<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    /// Construct `T` from `document`'s root. Construction allocates nothing.
    pub fn construct(document: OwnedDocument<'s, I, A>) -> Self {
        Operation::new(Construct {
            document: Some(document),
            marker: core::marker::PhantomData,
        })
    }
}

/// Where a construction record's cleanup stands (`Constructed`'s
/// `reclaim_step`): every phase before reclamation enters it by the same
/// admitted unit; the reclaiming phases are distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ConstructStage {
    Active,
    ReclaimValue,
    ReclaimDocument,
    ReclaimInput,
    Done,
}

/// What a construction's cleanup admits from its detail
/// ([`ConstructDetail`]), `D` its input's class and `C` its value's: the
/// record's stage (every phase before reclamation alike), its held document
/// by the parse's own class ([`ParseClass`]) and its held input by the
/// input's ([`DecodeInput`]), each of whose cleanup the record steps, and
/// its value through the value's own cleanup, whose class the value's
/// session declares ([`super::Reduction`] of [`Session`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct ConstructClass<D, C> {
    pub record: Option<ConstructStage>,
    pub document: Option<ParseClass<D>>,
    pub input: Option<D>,
    pub value: Option<C>,
}

impl<N, O> ConstructDetail<N, O> {
    /// The class of a record whose prefix is complete ([`ConstructClass`]),
    /// its input's by `D`, the input state's reduction, and its value's by
    /// `S`, the value's session's: the record's stage (every phase before
    /// reclamation alike), its held document by the parse's own class, its
    /// held input by the input's, and its value through the value's own
    /// cleanup. What a published value's holder reads of it
    /// ([`TypedValue::detail`]), and the complete-prefix part of an
    /// operation's class ([`Position::class`]).
    pub fn class<D, S>(&self) -> ConstructClass<D::Class, S::Class>
    where
        D: super::Reduction<Observation = N>,
        S: super::Reduction<Observation = O>,
    {
        ConstructClass {
            record: self.phase.map(|phase| match phase {
                ConstructPhase::Build
                | ConstructPhase::Detach
                | ConstructPhase::Publish
                | ConstructPhase::Published => ConstructStage::Active,
                ConstructPhase::ReclaimValue => ConstructStage::ReclaimValue,
                ConstructPhase::ReclaimDocument => ConstructStage::ReclaimDocument,
                ConstructPhase::ReclaimInput => ConstructStage::ReclaimInput,
                ConstructPhase::Done => ConstructStage::Done,
            }),
            document: self.document.as_ref().map(ParseDetail::class::<D>),
            input: self.input.as_ref().map(D::class),
            value: self.build.as_ref().map(S::class),
        }
    }

    /// This detail with its input's and its value's custody observations
    /// elided to whether each is held: what a record of positions of any
    /// typed decode, kept in fixed storage, holds.
    pub fn outline(self) -> ConstructDetail<(), ()> {
        ConstructDetail {
            phase: self.phase,
            document: self.document.map(ParseDetail::outline),
            input: self.input.map(|_| ()),
            build: self.build.map(|_| ()),
        }
    }
}

impl<N, O> Position<ConstructDetail<N, O>> {
    /// A construction's class, its input's by `D`, the input state's
    /// reduction, and its value's by `S`, the value's session's. Before the
    /// record's prefix is complete its cleanup (`Constructed`'s
    /// `reclaim_step`, `remaining`) reads only the document slot, stepping
    /// the held document's own cleanup, then releases the record in one unit;
    /// the rest of the prefix (the empty input slot, the value's initial
    /// state, the phase, the pending credit's idle units) owns nothing. So
    /// every partial prefix of an allocated record is classed by its
    /// document alone; past it, the record's stage, its document, its input
    /// and its value's class. Two positions of one class take each unit
    /// alike and land again in one class.
    pub fn class<D, S>(
        &self,
    ) -> super::operation::OperationClass<ConstructClass<D::Class, S::Class>>
    where
        D: super::Reduction<Observation = N>,
        S: super::Reduction<Observation = O>,
    {
        use super::operation::PrefixClass;
        let position = self;
        let detail = &position.detail;
        let prefix = position.partial();
        let task = if prefix == PrefixClass::Partial {
            ConstructClass {
                record: None,
                document: detail.document.as_ref().map(ParseDetail::class::<D>),
                input: None,
                value: None,
            }
        } else {
            detail.class::<D, S>()
        };
        position.operation_class(prefix, task)
    }
}

/// A construction's class is its position's, its input's by the input
/// state's reduction and its value's by the value's session's
/// ([`Position::class`]).
impl<'s, I, T, A> super::Reduction for Construction<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
    Session<T::State>: super::Reduction,
{
    type Class = super::operation::OperationClass<
        ConstructClass<InputClassOf<I, A>, <Session<T::State> as super::Reduction>::Class>,
    >;

    fn class(
        position: &Position<
            ConstructDetail<InputObservation<I, A>, <Session<T::State> as Custody>::Observation>,
        >,
    ) -> Self::Class {
        position.class::<I::State, Session<T::State>>()
    }
}

/// What a typed decode's cleanup admits, `D` its input's class: its
/// parse's while it parses ([`DocumentDecoder`]'s reduction), its
/// construction's once the parsed document moved into it
/// ([`Construction`]'s), nothing once finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TypedClass<D, C> {
    Parse(super::operation::OperationClass<ParseClass<D>>),
    Construct(C),
    Finished,
}

/// What a typed decode holds: its position ([`TypedDecoder::position`]).
impl<'s, I, T, A> Custody for TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    type Observation =
        TypedPosition<InputObservation<I, A>, <Session<T::State> as Custody>::Observation>;

    fn observe(&mut self) -> Self::Observation {
        self.position()
    }
}

/// A typed decode's class is its position's ([`TypedPosition::class`]).
impl<'s, I, T, A> super::Reduction for TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
    Session<T::State>: super::Reduction,
{
    type Class =
        TypedClass<InputClassOf<I, A>, <Construction<'s, I, T, A> as super::Reduction>::Class>;

    fn class(position: &Self::Observation) -> Self::Class {
        position.class::<I::State, Session<T::State>>()
    }
}

impl<N, O> TypedPosition<N, O> {
    /// A typed decode's class, its input's by `D`, the input state's
    /// reduction, and its value's by `S`, the value's session's: the stage's
    /// own operation's, the decode's cleanup being that operation's, and a
    /// finished decode holding nothing.
    #[expect(
        clippy::type_complexity,
        reason = "the class is the stage operations' own class types, composed"
    )]
    pub fn class<D, S>(
        &self,
    ) -> TypedClass<D::Class, super::operation::OperationClass<ConstructClass<D::Class, S::Class>>>
    where
        D: super::Reduction<Observation = N>,
        S: super::Reduction<Observation = O>,
    {
        match self {
            TypedPosition::Parse(parse) => TypedClass::Parse(parse.class::<D>()),
            TypedPosition::Construct(construct) => TypedClass::Construct(construct.class::<D, S>()),
            TypedPosition::Finished => TypedClass::Finished,
        }
    }
}

/// Where a typed decode is, `N` its input's state observation and `O` its
/// value's custody observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypedPosition<N, O> {
    Parse(Position<ParseDetail<N>>),
    Construct(Position<ConstructDetail<N, O>>),
    Finished,
}

impl<N, O> TypedPosition<N, O> {
    /// This position with the input's and the value's custody observations
    /// elided to whether each is held, whatever their types: what a record
    /// of positions of any typed decode, kept in fixed storage, holds.
    pub fn outline(self) -> TypedPosition<(), ()> {
        match self {
            Self::Parse(position) => TypedPosition::Parse(Position {
                queue: position.queue,
                allocated: position.allocated,
                initialized: position.initialized,
                initialization_steps: position.initialization_steps,
                cancelling: position.cancelling,
                finished: position.finished,
                outstanding: position.outstanding,
                detail: position.detail.outline(),
            }),
            Self::Construct(position) => TypedPosition::Construct(Position {
                queue: position.queue,
                allocated: position.allocated,
                initialized: position.initialized,
                initialization_steps: position.initialization_steps,
                cancelling: position.cancelling,
                finished: position.finished,
                outstanding: position.outstanding,
                detail: position.detail.outline(),
            }),
            Self::Finished => TypedPosition::Finished,
        }
    }
}

enum Stage<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    Parse(DocumentDecoder<'s, I, A>),
    Construct(Construction<'s, I, T, A>),
    Finished,
}

/// The value's custody: its record's group, under the owner of the
/// acquisition that allocated it, with its construction and its input
/// inside (its record's [`Custodial`] traversal), the completeness returned
/// whole; `&mut self` excludes every reader of the value meanwhile.
/// Read-only.
impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Custodial<A::Permit>
    for TypedValue<'s, I, T, A>
{
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        self.record.observe_custody(sink)
    }
}

/// The decode's custody ([`CustodySink`]): its current stage's operation's,
/// the parse's while it parses and the construction's once the parsed
/// document moved into it, its completeness returned whole. A finished
/// decode holds nothing: its published value or its cleaned-up records are
/// no longer its own. Read-only.
impl<'s, I, T, A> Custodial<A::Permit> for TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        match &mut self.stage {
            Stage::Parse(operation) => operation.observe_custody(sink),
            Stage::Construct(operation) => operation.observe_custody(sink),
            Stage::Finished => PermitsObserved::Complete,
        }
    }
}

/// Typed decoding: a parse, then construction from the parsed document.
pub struct TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A>,
    T: Transferable<A>,
    A: TerminalAllocator,
    A::Permit: Send,
{
    stage: Stage<'s, I, T, A>,
}

impl<'s, I, T, A> TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    /// A typed decode of `input`, parsed under `T`'s wire profile
    /// ([`InPlace::WIRE`]): a document nested past it, or holding a text it
    /// leaves unproven, is refused by the parse. Construction allocates
    /// nothing.
    pub fn new(input: OwnedInitialized<'s, I, A>) -> Self {
        Self {
            stage: Stage::Parse(DocumentDecoder::parse(input, T::WIRE)),
        }
    }

    pub fn cancel(&mut self) {
        match &mut self.stage {
            Stage::Parse(operation) => operation.cancel(),
            Stage::Construct(operation) => operation.cancel(),
            Stage::Finished => {}
        }
    }

    pub fn position(
        &mut self,
    ) -> TypedPosition<InputObservation<I, A>, <Session<T::State> as Custody>::Observation> {
        match &mut self.stage {
            Stage::Parse(operation) => TypedPosition::Parse(operation.position()),
            Stage::Construct(operation) => TypedPosition::Construct(operation.position()),
            Stage::Finished => TypedPosition::Finished,
        }
    }

    /// One step of the decode. A construction record whose dispatch depth
    /// exceeds the limit fails to compile where this decoder is used
    /// ([`super::reclamation::MAX_DISPATCH_DEPTH`]), so no step can reach it.
    pub fn step(&mut self, a: &mut A) -> ConstructResult<Step<TypedValue<'s, I, T, A>>, A> {
        match &mut self.stage {
            Stage::Parse(operation) => match operation.step(a)? {
                Step::Complete(document) => {
                    self.stage = Stage::Construct(Construction::construct(document));
                    Ok(Step::Progress)
                }
                Step::Progress => Ok(Step::Progress),
                Step::Finished => {
                    self.stage = Stage::Finished;
                    Ok(Step::Finished)
                }
            },
            Stage::Construct(operation) => match operation.step(a)? {
                Step::Complete(value) => {
                    self.stage = Stage::Finished;
                    Ok(Step::Complete(value))
                }
                Step::Progress => Ok(Step::Progress),
                Step::Finished => {
                    self.stage = Stage::Finished;
                    Ok(Step::Finished)
                }
            },
            Stage::Finished => Ok(Step::Finished),
        }
    }
}

impl<'s, I, T, A> Resumable<A> for TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: TerminalAllocator + 's,
    A::Permit: Send,
{
    type Output = TypedValue<'s, I, T, A>;
    type Error = DecodeError<A::Refusal>;
    type Position =
        TypedPosition<InputObservation<I, A>, <Session<T::State> as Custody>::Observation>;

    fn step(&mut self, a: &mut A) -> Result<Step<TypedValue<'s, I, T, A>>, Self::Error> {
        TypedDecoder::step(self, a)
    }

    fn position(&mut self) -> Self::Position {
        TypedDecoder::position(self)
    }
}

/// The construction record's cleanup at every cut of its task
/// ([`super::cuts::every_cut`]): every capability released exactly once,
/// the value's pending dropped in place at the record's last unit, and
/// after `Done`, released prefix or `ConstructPhase::Done`, nothing
/// admitted, initialization and advance refused, and neither document nor
/// input observed.
#[cfg(all(test, feature = "std"))]
mod released {
    use super::super::cuts::{completed, every_cut, scope};
    use super::*;
    use crate::ByteString;
    use crate::bounded::Limits;
    use crate::bounded::decode::Options;

    #[test]
    fn a_construction_records_cleanup_releases_every_capability_and_admits_nothing_after_done() {
        // The text "first", canonical.
        const TEXT: [u8; 6] = [0x65, b'f', b'i', b'r', b's', b't'];
        every_cut(
            "a construction record",
            |a| {
                let owner = scope(a);
                let input = completed(owner.copy_input(&TEXT), a);
                let document = completed(DocumentDecoder::parse(input, Options::normalizing(8)), a);
                (
                    owner,
                    Construct::<'static, ByteString, String, Limits> {
                        document: Some(document),
                        marker: core::marker::PhantomData,
                    },
                )
            },
            |detail: &ConstructDetail<_, _>, released, what| {
                if released {
                    assert_eq!(detail.phase, None, "{what}: a released record's phase read");
                    assert_eq!(detail.build, None, "{what}: a released record's value read");
                } else {
                    assert_eq!(detail.phase, Some(ConstructPhase::Done), "{what}");
                    assert_eq!(
                        detail.document, None,
                        "{what}: the released document observed"
                    );
                    assert_eq!(detail.input, None, "{what}: the released input observed");
                }
            },
        );
    }
}

/// The records' dispatch census: each record's declared dispatch depth less
/// the deepest level its whole life reaches, driven through its public
/// operations and handles alone, its scope shut down after, exactly. A
/// record is dispatched by its cleanup (its own advance, then the records
/// its custody holds), and a value's construction by the engine below it.
/// `Parsed` declares one level over its input chain (1). `Constructed`
/// declares the larger of its value's chain (0, the value dominating) and
/// its document's (1, `Parsed`'s margin, reached when the construction is
/// cancelled while the record still holds the document). `Planned` declares
/// one level over the published value it holds, so its margin is that
/// value's (0). A change in either direction fails here and is re-recorded
/// deliberately. Planted control
/// `tests/data/controls/parsed-depth-margin-changed.patch` (`Parsed`
/// declaring one level more) fails "Parsed".
#[cfg(all(test, feature = "std"))]
mod depth {
    use super::super::parse::Parsed;
    use super::super::reclamation::{DecodeOwner, deepest_reached};
    use super::*;
    use crate::ByteString;
    use crate::bounded::Limits;
    use crate::bounded::decode::Options;
    use crate::bounded::encoding::{OwnedPreparation, OwnedPrepared, Planned};

    /// A value whose chain dominates its input's: three sequences over a
    /// scalar, four levels.
    type Nested = Vec<Vec<Vec<u64>>>;

    /// `[[[7]]]`, canonical.
    const NESTED: [u8; 4] = [0x81, 0x81, 0x81, 0x07];

    /// `operation` stepped to its output.
    fn completed<'s, K: Task<'s, Limits>>(
        mut operation: Operation<'s, K, Limits>,
        a: &mut Limits,
    ) -> K::Output
    where
        K::Error: core::fmt::Debug,
    {
        loop {
            match operation.step(a).unwrap() {
                Step::Complete(output) => return output,
                Step::Progress => {}
                Step::Finished => panic!("an operation finished without its output"),
            }
        }
    }

    /// `wire` copied into `owner`'s scope and parsed into a document.
    fn parsed(
        owner: &DecodeOwner<'static, Limits>,
        wire: &[u8],
        a: &mut Limits,
    ) -> OwnedDocument<'static, ByteString, Limits> {
        let input = completed(owner.copy_input(wire), a);
        completed(DocumentDecoder::parse(input, Options::normalizing(8)), a)
    }

    /// An initialized scope.
    fn scope(a: &mut Limits) -> DecodeOwner<'static, Limits> {
        let mut owner = DecodeOwner::new();
        owner.initialize_step(a).unwrap();
        owner
    }

    /// `owner` shut down to `Done`, every record it queued reclaimed.
    fn shut_down(mut owner: DecodeOwner<'static, Limits>, a: &mut Limits) {
        while owner.shutdown_step(a).unwrap() != Reclaimed::Done {}
    }

    /// `run`'s deepest dispatch level against `declared`: their difference is
    /// `expected`, and `run` left no storage held.
    fn margin(what: &str, declared: usize, expected: usize, run: impl FnOnce(&mut Limits)) {
        let mut a = Limits::unlimited();
        let measured = deepest_reached(|| run(&mut a));
        assert_eq!(a.live_bytes(), 0, "{what}: storage left held");
        assert_eq!(
            declared.checked_sub(measured),
            Some(expected),
            "{what}: declared {declared}, measured {measured}"
        );
    }

    #[test]
    fn every_records_declaration_exceeds_its_dispatch_by_its_recorded_margin() {
        margin(
            "Parsed",
            <Parsed<'static, ByteString, Limits> as Reclaim<Limits>>::DISPATCH_DEPTH,
            1,
            |a| {
                let owner = scope(a);
                let mut document = Some(parsed(&owner, &[0x07], a));
                while OwnedDocument::reclaim_step(&mut document, a).unwrap() != Reclaimed::Done {}
                shut_down(owner, a);
            },
        );
        margin(
            "Constructed, its value",
            <Constructed<'static, ByteString, Nested, Limits> as Reclaim<Limits>>::DISPATCH_DEPTH,
            0,
            |a| {
                let owner = scope(a);
                let document = parsed(&owner, &NESTED, a);
                let mut value = Some(completed(
                    Construction::<'static, ByteString, Nested, Limits>::construct(document),
                    a,
                ));
                let expected: Nested = vec![vec![vec![7]]];
                assert_eq!(value.as_ref().map(TypedValue::value), Some(&expected));
                while TypedValue::reclaim_step(&mut value, a).unwrap() != Reclaimed::Done {}
                shut_down(owner, a);
            },
        );
        margin(
            "Constructed, its document",
            <Constructed<'static, ByteString, u64, Limits> as Reclaim<Limits>>::DISPATCH_DEPTH,
            1,
            |a| {
                let owner = scope(a);
                let document = parsed(&owner, &[0x07], a);
                let mut construction =
                    Construction::<'static, ByteString, u64, Limits>::construct(document);
                // The record holds the document from its first unit; its
                // phase is written before the value is built or detached.
                while construction.position().detail.phase != Some(ConstructPhase::Build) {
                    assert!(matches!(construction.step(a).unwrap(), Step::Progress));
                }
                construction.cancel();
                while !matches!(construction.step(a).unwrap(), Step::Finished) {}
                drop(construction);
                shut_down(owner, a);
            },
        );
        margin(
            "Planned",
            <Planned<'static, ByteString, Nested, Limits> as Reclaim<Limits>>::DISPATCH_DEPTH,
            0,
            |a| {
                let owner = scope(a);
                let document = parsed(&owner, &NESTED, a);
                let value = completed(
                    Construction::<'static, ByteString, Nested, Limits>::construct(document),
                    a,
                );
                let mut plan = Some(completed(OwnedPreparation::prepare(value), a));
                assert_eq!(plan.as_ref().map(OwnedPrepared::len), Some(NESTED.len()));
                while OwnedPrepared::reclaim_step(&mut plan, a).unwrap() != Reclaimed::Done {}
                shut_down(owner, a);
            },
        );
    }

    /// A valid construction whose declaration is its true depth (its value
    /// dominating, margin 0), suspended once its value's build has
    /// dispatched its innermost element, is dropped (its record queued in
    /// the scope, unpublished) and its scope abandoned: the authority's drop
    /// releases the last reference, and the terminal drain reclaims the
    /// record through every level its declaration names and no further,
    /// under the terminal policy, nothing refused, nothing left held. On a
    /// recorded session, its stream concluded complete and refined. Planted
    /// control `tests/data/controls/constructed-depth-overstated.patch` (the
    /// record declaring one level over its value's) keeps the finding "the
    /// terminal drain's deepest level".
    #[test]
    fn a_construction_suspended_at_its_declared_depth_drains_terminally() {
        use super::super::findings::{Expected, ExpectedHistory, Findings};
        use crate::bounded::{Capacity, Session};
        let declared =
            <Constructed<'static, ByteString, Nested, Limits> as Reclaim<Limits>>::DISPATCH_DEPTH;
        let innermost = <Nested as Reclaim<Limits>>::DISPATCH_DEPTH;
        let session = Session::new(Capacity::DEFAULT);
        let mut m = Limits::recorded_unlimited(&session);
        let mut findings = Findings::new();
        let owner = scope(&mut m);
        let document = parsed(&owner, &NESTED, &mut m);
        let mut construction =
            Construction::<'static, ByteString, Nested, Limits>::construct(document);
        // Stepped until the value's build reaches its own declaration, its
        // innermost element dispatched; every step of it is progress.
        let mut built = 0;
        while built < innermost {
            let mut progressed = false;
            built = built.max(deepest_reached(|| {
                progressed = matches!(construction.step(&mut m), Ok(Step::Progress));
            }));
            if !progressed {
                findings.check(
                    false,
                    || "the construction stopped before its innermost element was dispatched",
                );
                break;
            }
        }
        findings.equal("the build's deepest level", built, innermost);
        // Dropped mid-construction: its record is queued, the settled
        // acquisition holds nothing; then the scope is abandoned and drained
        // terminally by its last reference's release.
        drop(construction);
        let drained = deepest_reached(|| drop(owner));
        findings.equal("the terminal drain's deepest level", drained, declared);
        findings.equal("the storage after the drain", m.live_bytes(), 0);
        findings.policies([("m", m, ExpectedHistory::Readable)]);
        findings.conclude(&[(
            "the suspended construction's session",
            &session.finish(),
            Expected::Complete,
        )]);
    }
}
