//! Tag validation with independently retained payload initialization.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed};

/// Generated aligned projections for a tagged schema's untagged payload.
///
/// Each callback receives a [`Slot`] of the tagged value's place and its
/// untagged payload's state: a caller holding one has nothing to promise.
///
/// # Safety
/// [`Self::UNTAGGED`] must be the payload construction's initial state. The
/// callbacks must retain the destination and payload state and obey InPlace
/// and Reclaim respectively, sound for every call in any order. They must not
/// inspect or initialize the outer tag.
pub unsafe trait Payload<A: Allocator>: Sized {
    const TAG: u64;
    /// The construction state of the untagged payload, and its custody.
    type Untagged: Custody;
    /// The untagged payload's state before anything is built.
    const UNTAGGED: Self::Untagged;
    /// One unit of construction of the untagged payload.
    fn build_payload(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::Untagged>,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// One unit of cleanup of the untagged payload.
    fn reclaim_payload(
        slot: Slot<'_, Self, Self::Untagged>,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_payload`] still takes from the slot's state:
    /// the untagged payload's [`Reclaim::remaining`].
    fn remaining_payload(slot: PeekSlot<'_, Self, Self::Untagged>) -> u64;
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

/// One unit of construction of the tagged value in `slot`. Without metadata
/// the state is `INITIAL`, so construction begins; a completed or released
/// value is refused.
pub fn build<T: Payload<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    mut slot: Slot<'_, T, State<T::Untagged, A::Permit>>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: the header is the whole metadata, every field written.
        unsafe {
            stable::install::<Meta<T::Untagged>, Meta<T::Untagged>, A>(
                &mut state.meta,
                &mut state.admitted,
                || Meta {
                    child: T::UNTAGGED,
                    index,
                    phase: Phase::Inspect,
                },
                |meta| meta,
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
            // SAFETY: the tagged value's place and its untagged payload's
            // state, which only the payload callback uses.
            let payload = unsafe { Slot::new(place, &mut meta.child) };
            let result = T::build_payload(document, meta.index, payload, a)?;
            if result == Built::Done {
                meta.phase = Phase::Complete;
            }
            Ok(result)
        }
        _ => Err(BoundedError::PlanMismatch.into()),
    }
}

/// One unit of cleanup of the tagged value in `slot`. Releasing the metadata
/// leaves the state `INITIAL`.
pub fn reclaim<T: Payload<A>, A: Allocator>(
    mut slot: Slot<'_, T, State<T::Untagged, A::Permit>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
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
            // SAFETY: the payload state tracks all partial initialization of
            // the payload at this place.
            let payload = unsafe { Slot::new(place, &mut meta.child) };
            if T::reclaim_payload(payload, a)? == Reclaimed::Done {
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

/// The calls [`reclaim`] still takes from the slot's state: no metadata, one;
/// the tag inspected, one to `Release` and one to release; the payload live,
/// its own calls, the last of which reaches `Release`, then one; `Release`,
/// one.
pub fn remaining<T: Payload<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Untagged, A::Permit>>,
) -> u64 {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => 2,
        Phase::Build | Phase::Complete => {
            // SAFETY: the payload state tracks the payload at `place`.
            T::remaining_payload(unsafe { Slot::new(place, &mut meta.child) }).saturating_add(1)
        }
        Phase::Release => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Reservation;

    /// A tagged value's cost, evaluated at run time as the derive evaluates
    /// it in constants, is affine in its payload's: a fixed part (the
    /// metadata installed, the tag inspected, cleanup's unit before any
    /// payload, the metadata released), the payload's cost added unchanged,
    /// it being built in the value's own bytes.
    #[test]
    fn a_tagged_values_cost_is_its_own_fixed_part_and_its_payloads() {
        let bare = cost::<Written, Reservation>(ConstructionCost::ZERO);
        assert_eq!(bare.per_byte, ConstructionCost::ZERO.per_byte);
        assert_eq!(
            bare.fixed.values,
            stable::install_cost::<Meta<Written>, Reservation>().values
                + 2 * STEP_COST.values
                + stable::release_cost::<Reservation>().values,
            "the install, the inspection, cleanup's unit and the release"
        );
        let payload = ConstructionCost::fixed(unit(16)).plus(ConstructionCost::per_byte(unit(3)));
        let tagged = cost::<Written, Reservation>(payload);
        assert_eq!(tagged.fixed, plus(bare.fixed, payload.fixed));
        assert_eq!(tagged.per_byte, payload.per_byte);
    }
}
