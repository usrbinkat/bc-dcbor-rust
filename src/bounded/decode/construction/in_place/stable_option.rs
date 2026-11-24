//! An optional payload whose native representation never contains T inline.
use super::*;
use crate::bounded::decode::construction::reclamation::{Custody, Place, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed, Ticket};
use crate::sync::{Atomics, Representation};
use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

/// Optional stable storage for payloads that cannot use a bounded native
/// `Option<T>` placeholder. Construction publishes the pointer only after T is
/// initialized. Its enclosing decode record owns incremental reclamation.
///
/// The allocator parameter identifies the reservation stored with the payload.
/// Access is borrowed; there is no by-value extraction or synchronous Drop path.
pub struct StableOption<T, A: Allocator> {
    /// The published payload: a view into the payload block, which the
    /// option's state holds the authority over.
    payload: Option<NonNull<T>>,
    marker: PhantomData<(T, A::Permit)>,
}

// SAFETY: the payload is reached only through this value, which moves with
// the state holding its block; access is &T, as for a `Box<T>`.
unsafe impl<T: Send, A: Allocator> Send for StableOption<T, A> where A::Permit: Send {}
// SAFETY: shared access yields only &T.
unsafe impl<T: Sync, A: Allocator> Sync for StableOption<T, A> {}

/// What the payload block's acquisition writes, whole: the payload's
/// construction state and the block's phase.
struct Head<S> {
    child: S,
    phase: Phase,
}

/// The payload block: its header, then the payload itself, built in place
/// afterwards.
struct Body<S, T> {
    head: Head<S>,
    value: MaybeUninit<T>,
}

impl<S> Representation for Head<S> {
    type In<F: Atomics> = Self;
}

impl<S, T> Representation for Body<S, T> {
    type In<F: Atomics> = Self;
}

/// Where the payload block is: the payload under construction, complete
/// and its view next to publish, its cleanup under way, or reclaimed and
/// the block's release next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Build,
    Publish,
    /// The payload's cleanup under way: entered by the first cleanup unit
    /// the payload completes without finishing, so no build reaches a
    /// payload being cleaned up.
    Reclaim,
    Clean,
}

/// What construction has decided before the option is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    /// Nothing inspected.
    Undecided,
    /// Present: null excluded, the payload to be built.
    Present,
    /// Null, decided by an admitted inspection; its write not yet admitted.
    Null,
    /// The option written, null or published.
    Written,
}

/// The construction state of a [`StableOption`] whose payload's state is
/// `S`, of payload `T`, with permits of `P`: the decision, the ticket of the
/// payload block's acquisition while it is pending ([`Ticket`]), whose credit
/// is the operation's, and the payload block once acquired. Only the
/// option's own construction reads or changes it.
pub struct OptionState<S, T, P> {
    decision: Decision,
    ticket: Option<Ticket>,
    body: Option<Installed<Body<S, T>, P>>,
}

// SAFETY: the state exclusively owns its payload block, which holds the
// payload's state (an `S`), the payload (a `T`) and its permit, as the auto
// traits would derive through `Installed`; stated once here so a nested
// option's proof is one obligation per level.
unsafe impl<S: Send, T: Send, P: Send> Send for OptionState<S, T, P> {}

/// Construction progress: its decision and no payload block, or the block
/// at a phase with the payload's whole observation. Acquisition bindings
/// are reported separately by the root pending's custody observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StableOptionObservation<S> {
    Unallocated {
        decision: Decision,
    },
    Held {
        decision: Decision,
        phase: Phase,
        child: S,
    },
}

/// The cleanup classes of a stable option ([`Reduction`]), `C` its
/// payload's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum StableOptionClass<C> {
    /// No payload block: one unit completes cleanup.
    Unallocated,
    /// The block held, its payload of class `C` under construction or
    /// complete: the payload's cleanup units, then `Clean`.
    Live(C),
    /// The payload reclaimed: the block's release completes cleanup.
    Clean,
}

// Cleanup reads the block's presence and whether the payload is reclaimed,
// stepping the payload in `Build` and `Publish` alike; the decision and
// whether an unacquired block's acquisition is pending (its credit settled at
// the operation's cleanup entry) never change a cleanup unit.
// The payload's own relation is a simulation of its cleanup, and the option
// leaves `Live` exactly when the payload's cleanup reports done.
impl<S: Reduction, T, P> Reduction for OptionState<S, T, P> {
    type Class = StableOptionClass<S::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            StableOptionObservation::Unallocated { .. } => StableOptionClass::Unallocated,
            StableOptionObservation::Held { phase, child, .. } => match phase {
                Phase::Build | Phase::Publish | Phase::Reclaim => {
                    StableOptionClass::Live(S::class(child))
                }
                Phase::Clean => StableOptionClass::Clean,
            },
        }
    }
}

impl<S: Custody, T, P> Custody for OptionState<S, T, P> {
    type Observation = StableOptionObservation<S::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let decision = self.decision;
        let Some(installed) = self.body.as_mut() else {
            return StableOptionObservation::Unallocated { decision };
        };
        let (head, _) = parts(installed);
        StableOptionObservation::Held {
            decision,
            phase: head.phase,
            child: head.child.observe(),
        }
    }
}

/// What the payload block's acquisition admits and holds, for a payload `T`
/// whose state is `S`, with permits of `P` ([`stable::Contract`]): its
/// header, whole, and the permit written, the payload built afterwards; and
/// the whole block, the payload's bytes included. The one definition its
/// installation and the option's cost read, evaluated in a constant by
/// both.
const fn contract<S, T, P>() -> stable::Contract<Head<S>, Body<S, T>, P> {
    stable::Contract::of()
}

/// The payload block's two parts, each projected from the block's own
/// pointer: the header, the option's own custody, borrowed alone; and the
/// payload's place ([`Place`]), which stays valid for the block's life.
/// Every access to the block goes through here: borrowing the whole body
/// would also reborrow the payload, invalidating every place the payload's
/// construction keeps within itself. A handle to the block exists only once
/// its acquisition wrote the header whole ([`stable::install`]), so the
/// header is initialized whenever this can be called.
fn parts<S, T, P>(installed: &mut Installed<Body<S, T>, P>) -> (&mut Head<S>, Place<T>) {
    let body = installed.place();
    // SAFETY: the handle proves the header written; both projections stay
    // within the live block, and the header and the payload are disjoint.
    // The header is the option's own custody, which no reader borrows,
    // borrowed for as long as the handle, the block's custody, is;
    // `MaybeUninit<T>` lays out a `T` at its start.
    unsafe {
        let payload = body.project(|body| ptr::addr_of_mut!((*body).value).cast::<T>());
        (
            body.custody(installed, |body| ptr::addr_of_mut!((*body).head)),
            payload,
        )
    }
}

/// The cost of a stable option `O` of payload `T` costing `payload`, whose
/// state is `S`, with permits of `P`: the present-field marker; the null
/// decision; the payload block's admission, the block, holding `T`, held
/// for the value's life; the null or published write; cleanup's empty unit
/// and the block's release. The payload is built in the block. None when a
/// quantity does not fit in `u64`.
const fn cost<S, T, O, P>(payload: ConstructionCost) -> Option<ConstructionCost> {
    let body = contract::<S, T, P>();
    let decided = cost!(STEP_COST.checked_mul(2));
    let written = cost!(body.write().checked_add(sized::<O>().bound()));
    let released = cost!(
        cost!(STEP_COST.checked_add(stable::release_cost::<P>())).checked_add(held(body.block()))
    );
    let fixed = cost!(cost!(decided.checked_add(written)).checked_add(released));
    ConstructionCost::fixed(fixed).checked_add(payload)
}

impl<T, A: Allocator> StableOption<T, A> {
    pub fn as_ref(&self) -> Option<&T> {
        self.payload.map(|payload| {
            // SAFETY: publication installs the view only after the payload
            // returns Done. The enclosing value borrow excludes reclamation.
            unsafe { payload.as_ref() }
        })
    }

    pub fn is_some(&self) -> bool {
        self.payload.is_some()
    }
}

/// The payload's own state, a part of the option's: what the block's header
/// holds.
type Payload<T, A> = <T as Reclaim<A>>::State;

// SAFETY: admission: the decision, the payload block's allocation and every
// payload step (`build_part`) are admitted before they run. state: the state
// records the payload block before construction starts, and each step's
// progress before it returns, on error too. done: `Done` once the payload is
// built in its block and the view published, or `None` decided. escape: the
// payload block is held by the state's installed handle and never returned.
// provenance: the payload's slot is paired in place from its block for the
// block's whole life; no native Option<T> layout or placeholder is required,
// irrespective of T size. order: a build once cleanup began (`Reclaim`,
// `Clean`) or past completion is refused `PlanMismatch`, nothing changed.
// cost: `cost` of the option's parts plus `T::COST`.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for StableOption<T, A> {
    const OPTIONAL: bool = true;

    /// The option's own parts (`cost`) and its payload's.
    const COST: ConstructionCost =
        crate::const_cost!(cost::<Payload<T, A>, T, Self, A::Permit>(T::COST));

    fn build_present<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let mut slot = ctx.slot();
        let state = slot.custody();
        if state.decision == Decision::Undecided {
            STEP.admit(a)?;
            state.decision = Decision::Present;
            return Ok(Building::Progress);
        }
        Self::build_step(ctx, a)
    }

    fn build_absent<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let assembly = ctx.assembly();
        let mut slot = ctx.slot();
        let (place, state) = slot.parts();
        if state.body.is_some()
            || state.ticket.is_some()
            || !matches!(state.decision, Decision::Undecided | Decision::Present)
        {
            return Err(BoundedError::PlanMismatch.into());
        }
        sized::<Self>().admit(a)?;
        // SAFETY: the slot pairs the place with this state, whose decision
        // says nothing is written yet; the write is admitted above.
        unsafe {
            place.write(
                state,
                Self {
                    payload: None,
                    marker: PhantomData,
                },
            )
        };
        state.decision = Decision::Written;
        // SAFETY: the whole option, null, was written above by an admitted
        // unit, and the decision records it.
        Ok(Building::Done(unsafe { assembly.assemble() }))
    }

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let index = ctx.index();
        let node = ctx.node();
        let assembly = ctx.assembly();
        let (mut slot, pending) = ctx.acquiring();
        let (place, state) = slot.parts();
        if state.decision == Decision::Written {
            return Err(BoundedError::PlanMismatch.into());
        }
        let Some(installed) = state.body.as_mut() else {
            match state.decision {
                Decision::Undecided => {
                    STEP.admit(a)?;
                    // Retain the null decision separately from its admitted write.
                    state.decision = if matches!(node.ok_or_else(wrong_type)?.kind(), Kind::Null) {
                        Decision::Null
                    } else {
                        Decision::Present
                    };
                    return Ok(Building::Progress);
                }
                Decision::Null => {
                    sized::<Self>().admit(a)?;
                    // SAFETY: nothing is written yet; the write is admitted.
                    unsafe {
                        place.write(
                            state,
                            Self {
                                payload: None,
                                marker: PhantomData,
                            },
                        )
                    };
                    state.decision = Decision::Written;
                    // SAFETY: the whole option, null, was written by the
                    // admitted unit above, and the decision records it.
                    return Ok(Building::Done(unsafe { assembly.assemble() }));
                }
                Decision::Present => {
                    // SAFETY: only the header is written, projected to its
                    // field; T stays uninitialized until built. The block's
                    // acquisition admits the header's bytes ([`contract`]).
                    unsafe {
                        stable::install::<Body<Payload<T, A>, T>, Head<Payload<T, A>>, A>(
                            const { contract::<Payload<T, A>, T, A::Permit>() },
                            &mut state.body,
                            pending,
                            &mut state.ticket,
                            || Head {
                                child: T::INITIAL,
                                phase: Phase::Build,
                            },
                            |body| ptr::addr_of_mut!((*body).head),
                            a,
                        )?
                    };
                    return Ok(Building::Progress);
                }
                Decision::Written => return Err(BoundedError::PlanMismatch.into()),
            }
        };
        let (head, payload) = parts(installed);
        match head.phase {
            Phase::Build => {
                // The payload is a part from the option's own node, the
                // context's index; the option keeps no index of its own. It
                // is built only in `Build`, which a refused or erroring part
                // leaves unchanged and only the payload's `Done` ends.
                // SAFETY: the payload's place, rooted at its block, and its
                // own state in the block's header, the block this option's
                // state holds.
                let child = unsafe {
                    ctx.part(index, |slot| {
                        let installed = slot
                            .into_parts()
                            .1
                            .body
                            .as_mut()
                            .ok_or(BoundedError::PlanMismatch)?;
                        let (head, payload) = parts(installed);
                        Ok::<_, BoundedError<A::Refusal>>(Slot::new(payload, &mut head.child))
                    })
                }?;
                // The payload's record is verified and consumed by the part
                // entry in this step; `Publish` is the coverage recording
                // its `Done`, set right after it and nowhere else.
                if build_part::<T, A>(child, a)? == Built::Done {
                    let mut slot = ctx.slot();
                    let installed = slot
                        .custody()
                        .body
                        .as_mut()
                        .ok_or(BoundedError::PlanMismatch)?;
                    parts(installed).0.phase = Phase::Publish;
                }
                Ok(Building::Progress)
            }
            Phase::Publish => {
                sized::<Self>().admit(a)?;
                // The published view is the payload's place, whose
                // provenance is the block's for the block's life, its raw
                // pointer taken under the payload's own state.
                // SAFETY: the place is nonnull.
                let view = unsafe { NonNull::new_unchecked(payload.as_ptr(&mut head.child)) };
                // SAFETY: nothing is written yet; the write is admitted.
                unsafe {
                    place.write(
                        state,
                        Self {
                            payload: Some(view),
                            marker: PhantomData,
                        },
                    )
                };
                state.decision = Decision::Written;
                // SAFETY: the option was written whole above by an admitted
                // unit, its view over a payload `Publish` records done, that
                // payload's record, confined by its brand to the step that
                // minted it, verified against the payload's place and
                // consumed in that step.
                Ok(Building::Done(unsafe { assembly.assemble() }))
            }
            // Cleanup began ([`Reclaim::reclaim_step`] moves the block out
            // of `Build` with the payload's first completed unit): no part is
            // built again.
            Phase::Reclaim | Phase::Clean => Err(BoundedError::PlanMismatch.into()),
        }
    }
}

// SAFETY: initial: undecided, no ticket, no body. state: the decision, the
// ticket and the installed body record every block and the payload's state.
// admission: each cleanup unit, the option's and the payload's
// (`reclaim_part`), is admitted before it runs, a refusal changing nothing.
// cleanup: it uses the state's payload block, including before its view is
// published, and releases the payload only after its mandatory incremental
// cleanup completes, and only once every borrow of the option has ended;
// nothing is allocated and nothing unwinds. done: `Done` once the payload is
// reclaimed and its block released. order: a step after `Done` reports
// `Done`; the count and observation read only the state. depth: the
// payload's plus two, one more than its counted dispatches, the census
// recording the margin. count: the payload's remaining plus the option's own
// units.
unsafe impl<T: InPlace<A>, A: Allocator> Reclaim<A> for StableOption<T, A> {
    // One level more than its counted dispatches (its own and the
    // payload's, `build_part` and `reclaim_part` straight from its own
    // frame, the payload's slot paired in place from its block): no stack
    // frame accounts for it. Kept for compatibility with every declaration
    // composed over it; the census records the margin.
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);
    type State = OptionState<Payload<T, A>, T, A::Permit>;
    const INITIAL: Self::State = OptionState {
        decision: Decision::Undecided,
        ticket: None,
        body: None,
    };

    fn reclaim_step(
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        let state = slot.custody();
        let Some(installed) = state.body.as_mut() else {
            STEP.admit(a)?;
            state.decision = Decision::Undecided;
            // The block's acquisition, if pending, had its credit settled at
            // the operation's cleanup entry: the ticket is forgotten.
            state.ticket = None;
            return Ok(Reclaimed::Done);
        };
        let (head, payload) = parts(installed);
        if !matches!(head.phase, Phase::Clean) {
            // SAFETY: the payload's place, rooted at its block, paired with
            // its own state in the block's header.
            let child = unsafe { Slot::new(payload, &mut head.child) };
            // A refused unit returned above, the phase unchanged; one the
            // payload completed moves the block into cleanup, so no build
            // reaches the payload again.
            head.phase = match reclaim_part::<T, A>(child, a)? {
                Reclaimed::Done => Phase::Clean,
                _ => Phase::Reclaim,
            };
            return Ok(Reclaimed::Progress);
        }
        // SAFETY: the payload's cleanup completed; it owns nothing. The
        // block's release was paid for by its installation.
        unsafe { stable::uninstall(&mut state.body) };
        state.decision = Decision::Undecided;
        state.ticket = None;
        Ok(Reclaimed::Done)
    }

    /// No block: one call. The payload not yet clean: its own calls, the
    /// last of which marks it clean, then one to release the block. Clean:
    /// one.
    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        let Some(installed) = slot.custody().body.as_mut() else {
            return Some(1);
        };
        let (head, payload) = parts(installed);
        if matches!(head.phase, Phase::Clean) {
            Some(1)
        } else {
            // SAFETY: the payload's place, observed, paired with its own
            // state: a reader of the option may hold the payload borrowed.
            remaining_part::<T, A>(unsafe { Slot::new(payload.observe(), &mut head.child) })?
                .checked_add(1)
        }
    }

    /// The payload block's permit, then the payload's own until it is
    /// reclaimed ([`observe_part`]); none without a block.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        let Some(installed) = slot.custody().body.as_mut() else {
            return PermitsObserved::Complete;
        };
        sink.permit(installed.permit(), None);
        let (head, payload) = parts(installed);
        if matches!(head.phase, Phase::Clean) {
            return PermitsObserved::Complete;
        }
        // SAFETY: the payload's place, observed, paired with its own state,
        // as the cleanup count reads it.
        observe_part::<T, A>(
            unsafe { Slot::new(payload.observe(), &mut head.child) },
            sink,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::decode::construction::stable::Pending;
    use crate::bounded::decode::{DecodeError, decode};
    use crate::bounded::{Budget, Limits, Reservation};
    use core::ops::ControlFlow;

    type Field = StableOption<u64, Limits>;

    type FieldSession = Session<<Field as Reclaim<Limits>>::State>;

    /// Cleanup of `slot` to `Done` within its declared count.
    fn reclaimed(slot: &mut Slot<'_, Field, FieldSession>, a: &mut Limits) {
        let declared = remaining::<Field, Limits>(slot.observe())
            .expect("a stable option's cleanup count fits in u64");
        crate::bounded::within_steps("a stable option's cleanup", declared, || {
            match reclaim::<Field, Limits>(slot.reborrow(), &mut Cleanup::new(&mut *a)).unwrap() {
                Reclaimed::Done => ControlFlow::Break(()),
                _ => ControlFlow::Continue(()),
            }
        });
    }

    /// The binding's own observation within its session.
    fn inner_observation(
        slot: &mut Slot<'_, Field, FieldSession>,
    ) -> StableOptionObservation<<Payload<u64, Limits> as Custody>::Observation> {
        slot.custody().observe().inner
    }

    /// A stable option as a map field, through the engine: omitted, its
    /// session binds absence in one unit and it is written null in one
    /// admitted write, and absence asked again is refused; present, its
    /// session binds the node, its first unit decides presence before any
    /// block is acquired, and it is built to the payload, after which
    /// absence is refused. Cleanup releases everything, each within its
    /// declared count.
    #[test]
    fn an_omitted_field_is_written_null_and_a_present_one_is_built() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x07], 1, &mut parser).unwrap();
        let mut a = Limits::unlimited();

        let mut omitted = MaybeUninit::<Field>::uninit();
        let mut session = Session::new(<Field as Reclaim<Limits>>::INITIAL);
        // SAFETY: the test owns the destination and pairs it with its
        // initial session; every access to either is through this slot.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut omitted)), &mut session) };
        let mut pending = Pending::new(a.owner().expect("an ordinary family mints an owner"));
        let attempts = a.attempts();
        assert_eq!(
            build_absent::<Field, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a
            )
            .unwrap(),
            Built::Progress,
            "the session binds absence"
        );
        assert_eq!(
            build_absent::<Field, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a
            )
            .unwrap(),
            Built::Done
        );
        assert!(pending.is_idle(), "a null option acquires nothing");
        assert_eq!(
            a.attempts(),
            attempts + 2,
            "one bind unit and one admitted write"
        );
        let (place, written) = slot.parts();
        // SAFETY: the option was written.
        assert!(!unsafe { place.get(&written.inner) }.is_some());
        assert!(matches!(
            build_absent::<Field, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a
            ),
            Err(DecodeError::Resource(BoundedError::PlanMismatch))
        ));
        reclaimed(&mut slot, &mut a);

        let mut present = MaybeUninit::<Field>::uninit();
        let mut session = Session::new(<Field as Reclaim<Limits>>::INITIAL);
        // SAFETY: as above.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut present)), &mut session) };
        let mut pending = Pending::new(a.owner().expect("an ordinary family mints an owner"));
        for _ in 0..2 {
            assert_eq!(
                build_present::<Field, Limits>(
                    Context::root(&document, slot.reborrow(), &mut pending),
                    &mut a
                )
                .unwrap(),
                Built::Progress
            );
        }
        assert_eq!(
            inner_observation(&mut slot),
            StableOptionObservation::Unallocated {
                decision: Decision::Present,
            },
            "presence is decided before any block is acquired"
        );
        crate::bounded::within_steps("a present stable option's construction", 16, || {
            match build_present::<Field, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a,
            )
            .unwrap()
            {
                Built::Done => ControlFlow::Break(()),
                Built::Progress => ControlFlow::Continue(()),
            }
        });
        let (place, built) = slot.parts();
        // SAFETY: construction reported the option written.
        assert_eq!(unsafe { place.get(&built.inner) }.as_ref(), Some(&7));
        assert!(pending.is_idle(), "a built option left credit pending");
        assert!(matches!(
            build_absent::<Field, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a
            ),
            Err(DecodeError::Resource(BoundedError::PlanMismatch))
        ));
        reclaimed(&mut slot, &mut a);
        assert_eq!(a.live_bytes(), 0);
        let body = contract::<Written, u64, Reservation>();
        let constant = const { contract::<Written, u64, Reservation>() };
        assert_eq!(body.write(), constant.write());
        assert_eq!(body.block(), constant.block());
    }
}
