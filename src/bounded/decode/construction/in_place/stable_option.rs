//! An optional payload whose native representation never contains T inline.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Place, Reduction};
use crate::bounded::decode::construction::stable::{self, Held, Installed};
use core::{
    marker::PhantomData,
    mem::{MaybeUninit, size_of},
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

/// Where the payload block is: the payload under construction, complete
/// and its view next to publish, or reclaimed and the block's release next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Build,
    Publish,
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
/// `S`, of payload `T`, with permits of `P`: the decision, what the payload
/// block's acquisition has admitted, and the payload block once acquired.
/// Only the option's own construction reads or changes it.
pub struct OptionState<S, T, P> {
    decision: Decision,
    admitted: stable::Admitted,
    body: Option<Installed<Body<S, T>, P>>,
}

// SAFETY: the state exclusively owns its payload block, which holds the
// payload's state (an `S`), the payload (a `T`) and its permit, as the auto
// traits would derive through `Installed`; stated once here so a nested
// option's proof is one obligation per level.
unsafe impl<S: Send, T: Send, P: Send> Send for OptionState<S, T, P> {}

/// What a stable option's construction holds: its decision, and no payload
/// block, with the admissions held toward it, or the block, at a phase,
/// holding the payload's construction state, whose whole observation it
/// carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StableOptionObservation<S> {
    Unallocated {
        decision: Decision,
        admitted: Admitted,
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
// stepping the payload in `Build` and `Publish` alike; the decision and the
// admissions held toward an unacquired block never change a cleanup unit.
// The payload's own relation is a simulation of its cleanup, and the option
// leaves `Live` exactly when the payload's cleanup reports done.
impl<S: Reduction, T, P> Reduction for OptionState<S, T, P> {
    type Class = StableOptionClass<S::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            StableOptionObservation::Unallocated { .. } => StableOptionClass::Unallocated,
            StableOptionObservation::Held { phase, child, .. } => match phase {
                Phase::Build | Phase::Publish => StableOptionClass::Live(S::class(child)),
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
            return StableOptionObservation::Unallocated {
                decision,
                admitted: self.admitted,
            };
        };
        let (head, _) = parts(installed);
        StableOptionObservation::Held {
            decision,
            phase: head.phase,
            child: head.child.observe(),
        }
    }
}

/// What the payload block's acquisition writes, for a payload `T` whose
/// state is `S`, with permits of `P`: its header, whole, and the permit; the
/// payload itself is built afterwards. Evaluated in a constant by every
/// caller.
const fn metadata<S, T, P>() -> stable::Metadata {
    stable::Metadata::header::<Head<S>, Body<S, T>, P>()
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

// SAFETY: the state records the payload block before construction starts.
// No native Option<T> layout or placeholder is required, irrespective of T size.
unsafe impl<T: InPlace<A>, A: Allocator> InPlace<A> for StableOption<T, A> {
    const OPTIONAL: bool = true;

    /// The present-field marker; the null decision; the payload block's
    /// admission, the block, holding T, held for the value's life; the null
    /// or published write; cleanup's empty unit and the block's release. The
    /// payload is built in the option's own bytes.
    const COST: ConstructionCost = {
        let block = size_of::<Held<Body<T::State, T>, A::Permit>>();
        ConstructionCost::fixed(plus(
            plus(
                times(STEP_COST, 2),
                plus(
                    stable::acquire_cost(metadata::<T::State, T, A::Permit>()),
                    sized::<Self>().bound(),
                ),
            ),
            plus(
                plus(STEP_COST, stable::release_cost::<A::Permit>()),
                held(block),
            ),
        ))
        .plus(T::COST)
    };

    fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let state = slot.custody();
        if state.decision == Decision::Undecided {
            STEP.admit(a)?;
            state.decision = Decision::Present;
            return Ok(Built::Progress);
        }
        Self::build_step(document, index, slot, a)
    }

    fn build_absent(mut slot: Slot<'_, Self, Self::State>, a: &mut A) -> ConstructResult<Built, A> {
        let (place, state) = slot.parts();
        if state.body.is_some()
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
        Ok(Built::Done)
    }

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let (place, state) = slot.parts();
        if state.decision == Decision::Written {
            return Err(BoundedError::PlanMismatch.into());
        }
        let Some(installed) = state.body.as_mut() else {
            match state.decision {
                Decision::Undecided => {
                    STEP.admit(a)?;
                    // Retain the null decision separately from its admitted write.
                    state.decision = if matches!(
                        node_at(document, index).ok_or_else(wrong_type)?.kind(),
                        Kind::Null
                    ) {
                        Decision::Null
                    } else {
                        Decision::Present
                    };
                    return Ok(Built::Progress);
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
                    return Ok(Built::Done);
                }
                Decision::Present => {
                    // SAFETY: only the header is written, projected to its
                    // field; T stays uninitialized until built. The block's
                    // acquisition admits the header's bytes ([`metadata`]).
                    unsafe {
                        stable::install::<Body<T::State, T>, Head<T::State>, A>(
                            &mut state.body,
                            &mut state.admitted,
                            || Head {
                                child: T::INITIAL,
                                phase: Phase::Build,
                            },
                            |body| ptr::addr_of_mut!((*body).head),
                            a,
                        )?
                    };
                    return Ok(Built::Progress);
                }
                Decision::Written => return Err(BoundedError::PlanMismatch.into()),
            }
        };
        let (head, payload) = parts(installed);
        match head.phase {
            Phase::Build => {
                // SAFETY: the payload's place, rooted at its block, paired
                // with its own state in the block's header.
                let child = unsafe { Slot::new(payload, &mut head.child) };
                if T::build_step(document, index, child, a)? == Built::Done {
                    head.phase = Phase::Publish;
                }
                Ok(Built::Progress)
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
                Ok(Built::Done)
            }
            Phase::Clean => Err(BoundedError::PlanMismatch.into()),
        }
    }
}

// SAFETY: cleanup uses the state's payload block, including before its view
// is published. It releases the payload only after its mandatory incremental
// cleanup completes, and only once every borrow of the option has ended.
unsafe impl<T: Reclaim<A>, A: Allocator> Reclaim<A> for StableOption<T, A> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);
    type State = OptionState<T::State, T, A::Permit>;
    const INITIAL: Self::State = OptionState {
        decision: Decision::Undecided,
        admitted: stable::Admitted::Nothing,
        body: None,
    };

    fn reclaim_step(
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let state = slot.custody();
        let Some(installed) = state.body.as_mut() else {
            STEP.admit(a)?;
            state.decision = Decision::Undecided;
            state.admitted = stable::Admitted::Nothing;
            return Ok(Reclaimed::Done);
        };
        let (head, payload) = parts(installed);
        if !matches!(head.phase, Phase::Clean) {
            // SAFETY: the payload's place, rooted at its block, paired with
            // its own state in the block's header.
            let child = unsafe { Slot::new(payload, &mut head.child) };
            if T::reclaim_step(child, a)? == Reclaimed::Done {
                head.phase = Phase::Clean;
            }
            return Ok(Reclaimed::Progress);
        }
        // SAFETY: the payload's cleanup completed; it owns nothing. The
        // block's release was paid for by its installation.
        unsafe { stable::uninstall(&mut state.body) };
        state.decision = Decision::Undecided;
        state.admitted = stable::Admitted::Nothing;
        Ok(Reclaimed::Done)
    }

    /// No block: one call. The payload not yet clean: its own calls, the
    /// last of which marks it clean, then one to release the block. Clean:
    /// one.
    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        let Some(installed) = slot.custody().body.as_mut() else {
            return 1;
        };
        let (head, payload) = parts(installed);
        if matches!(head.phase, Phase::Clean) {
            1
        } else {
            // SAFETY: the payload's place, observed, paired with its own
            // state: a reader of the option may hold the payload borrowed.
            T::remaining(unsafe { Slot::new(payload.observe(), &mut head.child) }).saturating_add(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::decode::{DecodeError, decode};
    use crate::bounded::{Limits, Reservation};
    use core::ops::ControlFlow;

    type Field = StableOption<u64, Limits>;

    /// Cleanup of `slot` to `Done` within its declared count.
    fn reclaimed(slot: &mut Slot<'_, Field, <Field as Reclaim<Limits>>::State>, a: &mut Limits) {
        let declared = <Field as Reclaim<Limits>>::remaining(slot.observe());
        crate::bounded::within_steps("a stable option's cleanup", declared, || {
            match <Field as Reclaim<Limits>>::reclaim_step(slot.reborrow(), a).unwrap() {
                Reclaimed::Done => ControlFlow::Break(()),
                _ => ControlFlow::Continue(()),
            }
        });
    }

    /// A stable option as a map field: omitted, it is written null in one
    /// admitted write, and absence asked again is refused; present, its
    /// first unit decides presence before any block is acquired, and it is
    /// built to the payload, after which absence is refused. Cleanup
    /// releases everything, each within its declared count.
    #[test]
    fn an_omitted_field_is_written_null_and_a_present_one_is_built() {
        let mut parser = Limits::unlimited();
        let document = decode(&[0x07], 1, &mut parser).unwrap();
        let mut a = Limits::unlimited();

        let mut omitted = MaybeUninit::<Field>::uninit();
        let mut state = <Field as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its
        // initial state; every access to either is through this slot.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut omitted)), &mut state) };
        let attempts = a.attempts();
        assert_eq!(
            <Field as InPlace<Limits>>::build_absent(slot.reborrow(), &mut a).unwrap(),
            Built::Done
        );
        assert_eq!(a.attempts(), attempts + 1, "one admitted write");
        let (place, written) = slot.parts();
        // SAFETY: the option was written.
        assert!(!unsafe { place.get(&*written) }.is_some());
        assert!(matches!(
            <Field as InPlace<Limits>>::build_absent(slot.reborrow(), &mut a),
            Err(DecodeError::Resource(BoundedError::PlanMismatch))
        ));
        reclaimed(&mut slot, &mut a);

        let mut present = MaybeUninit::<Field>::uninit();
        let mut state = <Field as Reclaim<Limits>>::INITIAL;
        // SAFETY: as above.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut present)), &mut state) };
        assert_eq!(
            <Field as InPlace<Limits>>::build_present(&document, 0, slot.reborrow(), &mut a)
                .unwrap(),
            Built::Progress
        );
        assert_eq!(
            slot.custody().observe(),
            StableOptionObservation::Unallocated {
                decision: Decision::Present,
                admitted: Admitted::Nothing
            },
            "presence is decided before any block is acquired"
        );
        crate::bounded::within_steps("a present stable option's construction", 16, || {
            match <Field as InPlace<Limits>>::build_present(&document, 0, slot.reborrow(), &mut a)
                .unwrap()
            {
                Built::Done => ControlFlow::Break(()),
                Built::Progress => ControlFlow::Continue(()),
            }
        });
        let (place, built) = slot.parts();
        // SAFETY: construction reported the option written.
        assert_eq!(unsafe { place.get(&*built) }.as_ref(), Some(&7));
        assert!(matches!(
            <Field as InPlace<Limits>>::build_absent(slot.reborrow(), &mut a),
            Err(DecodeError::Resource(BoundedError::PlanMismatch))
        ));
        reclaimed(&mut slot, &mut a);
        assert_eq!(a.live_bytes(), 0);
        assert_eq!(
            metadata::<Written, u64, Reservation>().bytes(),
            const { metadata::<Written, u64, Reservation>() }.bytes()
        );
    }
}
