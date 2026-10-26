//! Tag validation with independently retained payload initialization.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed};

/// Generated aligned projections for a tagged schema's untagged payload.
///
/// # Safety
/// [`Self::UNTAGGED`] must be the payload construction's initial state. The
/// callbacks must retain the destination and payload state and obey InPlace
/// and Reclaim respectively. They must not inspect or initialize the outer
/// tag.
pub unsafe trait Payload<A: Allocator>: Sized {
    const TAG: u64;
    /// The construction state of the untagged payload, and its custody.
    type Untagged: Custody;
    /// The untagged payload's state before anything is built.
    const UNTAGGED: Self::Untagged;
    /// # Safety
    /// The destination and state obey InPlace::build_step's contract.
    unsafe fn build_payload(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Untagged,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The destination and state are the original payload construction pair.
    unsafe fn reclaim_payload(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Untagged,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_payload`] still takes from `state`: the
    /// untagged payload's [`Reclaim::remaining`].
    ///
    /// # Safety
    /// As [`Self::reclaim_payload`].
    unsafe fn remaining_payload(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Untagged,
    ) -> u64;
}

/// Where a tagged value's construction or cleanup is: the tag inspection,
/// the untagged payload under construction, complete, then reclaimed and
/// the metadata's release next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Inspect,
    Build,
    Complete,
    Release,
}
struct Meta<U> {
    child: U,
    index: usize,
    phase: Phase,
}

/// The construction state of a tagged value whose untagged payload's state
/// is `U`, with permits of `P`: its metadata, once installed, and what that
/// installation has admitted. Only the tagged engine reads or changes it.
pub struct State<U, P> {
    meta: Option<Installed<Meta<U>, P>>,
    admitted: stable::Admitted,
}

impl<U, P> State<U, P> {
    /// Nothing installed.
    pub const INITIAL: Self = Self {
        meta: None,
        admitted: stable::Admitted::Nothing,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// untagged payload's state (a `U`), its permit and a plain index, as the
// auto traits would derive through `Installed`; stated once here so a nested
// tagged value's proof is one obligation per level.
unsafe impl<U: Send, P: Send> Send for State<U, P> {}

/// What a tagged value's construction holds: no metadata block, with the
/// admissions held toward it; or the block, at a document index and phase,
/// holding the untagged payload's construction state, whose whole
/// observation it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaggedObservation<U> {
    Unallocated(Admitted),
    Held {
        index: usize,
        phase: Phase,
        child: U,
    },
}

/// The cleanup classes of a tagged value ([`Reduction`]), `C` its untagged
/// payload's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaggedClass<C> {
    /// No metadata: one unit completes cleanup.
    Unallocated,
    /// The tag not yet inspected: one unit reaches `Release`.
    Inspect,
    /// The untagged payload of class `C` under construction or complete:
    /// its cleanup units, then `Release`.
    Live(C),
    /// The payload reclaimed: the metadata's release completes cleanup.
    Release,
}

// Cleanup reads the metadata's presence and the phase, grouped as above,
// stepping the payload in `Build` and `Complete` alike; the document index
// never changes a cleanup unit. The payload's own relation is a simulation
// of its cleanup, and the value leaves `Live` exactly when the payload's
// cleanup reports done.
impl<U: Reduction, P> Reduction for State<U, P> {
    type Class = TaggedClass<U::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            TaggedObservation::Unallocated(_) => TaggedClass::Unallocated,
            TaggedObservation::Held { phase, child, .. } => match phase {
                Phase::Inspect => TaggedClass::Inspect,
                Phase::Build | Phase::Complete => TaggedClass::Live(U::class(child)),
                Phase::Release => TaggedClass::Release,
            },
        }
    }
}

impl<U: Custody, P> Custody for State<U, P> {
    type Observation = TaggedObservation<U::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return TaggedObservation::Unallocated(self.admitted);
        };
        let meta = installed.get();
        TaggedObservation::Held {
            index: meta.index,
            phase: meta.phase,
            child: meta.child.observe(),
        }
    }
}

/// The cost of a tagged value whose untagged payload costs `payload`, whose
/// state is `U`, with permits of type `P`: the metadata block, held for the
/// value's life; the tag inspection; cleanup's unit before any payload and
/// the metadata's release. The payload is built in the tagged value's own
/// bytes.
pub const fn cost<U, P>(payload: ConstructionCost) -> ConstructionCost {
    let meta = stable::Metadata::whole::<Meta<U>, P>().bytes();
    ConstructionCost::fixed(plus(
        plus(stable::install_cost::<Meta<U>, P>(), STEP_COST),
        plus(plus(STEP_COST, stable::release_cost::<P>()), held(meta)),
    ))
    .plus(payload)
}

/// # Safety
/// The caller provides a unique stable destination and its retained state.
pub unsafe fn build<T: Payload<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Untagged, A::Permit>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: every metadata field is written.
        unsafe {
            stable::install::<Meta<T::Untagged>, A>(
                &mut state.meta,
                &mut state.admitted,
                const { stable::Metadata::whole::<Meta<T::Untagged>, A::Permit>() },
                |meta| {
                    meta.write(Meta {
                        child: T::UNTAGGED,
                        index,
                        phase: Phase::Inspect,
                    })
                },
                a,
            )?
        };
        return Ok(Built::Progress);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            match node_at(document, meta.index).map(|node| node.kind()) {
                Some(Kind::Tagged(found)) if found == T::TAG => {}
                Some(Kind::Tagged(found)) => {
                    return Err(crate::bounded::decode::DecodeError::Invalid(
                        crate::Error::WrongTag(
                            crate::Tag::with_value(T::TAG),
                            crate::Tag::with_value(found),
                        ),
                    ));
                }
                _ => return Err(wrong_type()),
            }
            meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.phase = Phase::Build;
            Ok(Built::Progress)
        }
        Phase::Build => {
            // SAFETY: only the payload callback uses the payload state.
            let result =
                unsafe { T::build_payload(document, meta.index, place, &mut meta.child, a)? };
            if result == Built::Done {
                meta.phase = Phase::Complete;
            }
            Ok(result)
        }
        _ => Err(BoundedError::PlanMismatch.into()),
    }
}

/// # Safety
/// The destination and state must be the pair previously passed to build.
pub unsafe fn reclaim<T: Payload<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Untagged, A::Permit>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            meta.phase = Phase::Release;
        }
        Phase::Build | Phase::Complete => {
            // SAFETY: the payload state tracks all partial initialization.
            if unsafe { T::reclaim_payload(place, &mut meta.child, a)? } == Reclaimed::Done {
                meta.phase = Phase::Release;
            }
        }
        Phase::Release => {
            // SAFETY: the payload owns no resources now. The metadata's
            // release was paid for by its installation.
            unsafe { stable::uninstall(&mut state.meta) };
            return Ok(Reclaimed::Done);
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from `state`: no metadata, one; the tag
/// inspected, one to `Release` and one to release; the payload live, its own
/// calls, the last of which reaches `Release`, then one; `Release`, one.
///
/// # Safety
/// As [`reclaim`].
pub unsafe fn remaining<T: Payload<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Untagged, A::Permit>,
) -> u64 {
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => 2,
        Phase::Build | Phase::Complete => {
            // SAFETY: the payload state tracks the payload at `place`.
            unsafe { T::remaining_payload(place, &mut meta.child) }.saturating_add(1)
        }
        Phase::Release => 1,
    }
}
