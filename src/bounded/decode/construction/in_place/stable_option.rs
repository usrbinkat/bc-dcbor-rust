//! An optional payload whose native representation never contains T inline.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Reduction};
use crate::bounded::decode::construction::stable::{self, Held, Installed};
use core::{marker::PhantomData, mem::size_of, ptr};

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

/// The payload block: the payload's construction state, its phase, and the
/// payload itself, built in place.
struct Body<S, T> {
    child: S,
    phase: Phase,
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
        let body = installed.get();
        StableOptionObservation::Held {
            decision,
            phase: body.phase,
            child: body.child.observe(),
        }
    }
}

/// What the payload block's acquisition writes, for a payload `T` whose
/// state is `S`, with permits of `P`: the payload's state, the phase and the
/// permit; the payload itself is built afterwards. Evaluated in a constant
/// by every caller.
const fn metadata<S, T, P>() -> stable::Metadata {
    stable::Metadata::new::<Body<S, T>, P>(size_of::<S>() + size_of::<Phase>() + size_of::<P>())
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

    unsafe fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if state.decision == Decision::Undecided {
            STEP.admit(a)?;
            state.decision = Decision::Present;
            return Ok(Built::Progress);
        }
        unsafe { Self::build_step(document, index, place, state, a) }
    }

    unsafe fn build_absent(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if state.body.is_some()
            || !matches!(state.decision, Decision::Undecided | Decision::Present)
        {
            return Err(BoundedError::PlanMismatch.into());
        }
        sized::<Self>().admit(a)?;
        unsafe {
            place.as_ptr().write(MaybeUninit::new(Self {
                payload: None,
                marker: PhantomData,
            }));
        }
        state.decision = Decision::Written;
        Ok(Built::Done)
    }

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
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
                    unsafe {
                        place.as_ptr().write(MaybeUninit::new(Self {
                            payload: None,
                            marker: PhantomData,
                        }));
                    }
                    state.decision = Decision::Written;
                    return Ok(Built::Done);
                }
                Decision::Present => {
                    // SAFETY: only metadata is written; T stays uninitialized
                    // until built. The block's acquisition admits the
                    // metadata's bytes, as `metadata` counts them.
                    unsafe {
                        stable::install::<Body<T::State, T>, A>(
                            &mut state.body,
                            &mut state.admitted,
                            const { metadata::<T::State, T, A::Permit>() },
                            |body| {
                                ptr::addr_of_mut!((*body).child).write(T::INITIAL);
                                ptr::addr_of_mut!((*body).phase).write(Phase::Build);
                            },
                            a,
                        )?
                    };
                    return Ok(Built::Progress);
                }
                Decision::Written => return Err(BoundedError::PlanMismatch.into()),
            }
        };
        match installed.get().phase {
            Phase::Build => {
                let payload = installed.get();
                if unsafe {
                    T::build_step(
                        document,
                        index,
                        NonNull::from(&mut payload.value),
                        &mut payload.child,
                        a,
                    )?
                } == Built::Done
                {
                    payload.phase = Phase::Publish;
                }
                Ok(Built::Progress)
            }
            Phase::Publish => {
                sized::<Self>().admit(a)?;
                let block = installed.view();
                // SAFETY: the view is the handle's own pointer; projecting
                // the payload field keeps it within the block.
                let value = unsafe {
                    NonNull::new_unchecked(ptr::addr_of_mut!((*block.as_ptr()).value.value))
                        .cast::<T>()
                };
                unsafe {
                    place.as_ptr().write(MaybeUninit::new(Self {
                        payload: Some(value),
                        marker: PhantomData,
                    }));
                }
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

    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let Some(installed) = state.body.as_mut() else {
            STEP.admit(a)?;
            state.decision = Decision::Undecided;
            state.admitted = stable::Admitted::Nothing;
            return Ok(Reclaimed::Done);
        };
        let payload = installed.get();
        if !matches!(payload.phase, Phase::Clean) {
            if unsafe { T::reclaim_step(NonNull::from(&mut payload.value), &mut payload.child, a)? }
                == Reclaimed::Done
            {
                payload.phase = Phase::Clean;
            }
            return Ok(Reclaimed::Progress);
        }
        // SAFETY: the payload's cleanup completed; it owns nothing. The
        // block's release was paid for by its installation.
        unsafe { stable::uninstall(&mut state.body) };
        Ok(Reclaimed::Done)
    }

    /// No block: one call. The payload not yet clean: its own calls, the
    /// last of which marks it clean, then one to release the block. Clean:
    /// one.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        let Some(installed) = state.body.as_mut() else {
            return 1;
        };
        let payload = installed.get();
        if matches!(payload.phase, Phase::Clean) {
            1
        } else {
            // SAFETY: the block holds the payload's stable place, paired with
            // its own state, as cleanup steps it.
            unsafe { T::remaining(NonNull::from(&mut payload.value), &mut payload.child) }
                .saturating_add(1)
        }
    }
}
