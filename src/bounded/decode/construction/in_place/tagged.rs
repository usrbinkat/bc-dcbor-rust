//! Tag validation with independently retained payload initialization.
use super::*;
use crate::bounded::decode::construction::reclamation::{Custody, Reduction, Uniform};
use crate::bounded::decode::construction::stable::{self, Installed, Ticket};
use crate::sync::{Atomics, Representation};

/// Generated aligned projections for a tagged schema's untagged payload.
///
/// Each callback receives a [`Slot`] of the tagged value's place and its
/// untagged payload's state: a caller holding one has nothing to promise.
///
/// # Safety
/// An implementation keeps four obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *initial*: [`Self::UNTAGGED`] is the payload construction's initial
///   state.
/// - *projection*: the callbacks retain the destination and the payload
///   state and obey InPlace and Reclaim respectively.
/// - *tag*: the callbacks do not inspect or initialize the outer tag.
/// - *order*: each callback is sound for every call, in any order.
pub unsafe trait Payload<A: Allocator>: Sized {
    const TAG: u64;
    /// The construction state of the untagged payload, and its custody.
    type Untagged: Custody;
    /// The untagged payload's state before anything is built.
    const UNTAGGED: Self::Untagged;
    /// One unit of construction of the untagged payload, from the tag's
    /// child node, in the tagged value's own document ([`build`]).
    fn build_payload(
        ctx: Context<'_, '_, '_, '_, Self, Self::Untagged, A>,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// One unit of cleanup of the untagged payload.
    fn reclaim_payload(
        slot: Slot<'_, Self, Self::Untagged>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_payload`] still takes from the slot's state:
    /// the untagged payload's [`Reclaim::remaining`], `None` when it does not
    /// fit in `u64`.
    fn remaining_payload(slot: PeekSlot<'_, Self, Self::Untagged>) -> Option<u64>;
    /// The permits the untagged payload's state owns, reported inside the
    /// caller's open group: its [`Reclaim::observe_permits`].
    fn observe_payload(
        slot: PeekSlot<'_, Self, Self::Untagged>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved;
}

/// Where a tagged value's construction or cleanup is: the tag inspection,
/// the untagged payload under construction, complete, then reclaimed and
/// the metadata's release next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Inspect,
    Build,
    Complete,
    /// The payload's cleanup under way: entered by the first cleanup unit
    /// the payload completes without finishing, so no build reaches a
    /// payload being cleaned up.
    Reclaim,
    Release,
}
/// The tagged value's metadata: the untagged payload's state and the phase.
/// No node index: which node the value is built from is its session's record
/// (the engine's), and the payload's node is that node's child, recomputed
/// from the context at every step, never a second stored copy.
struct Meta<U> {
    child: U,
    phase: Phase,
}

impl<U> Representation for Meta<U> {
    type In<F: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds, its whole value
/// written with the permit ([`stable::Contract`]): the one definition its
/// installation and the tagged value's cost read.
const fn contract<U, P>() -> stable::Contract<Meta<U>, Meta<U>, P> {
    stable::Contract::of()
}

/// The construction state of a tagged value whose untagged payload's state
/// is `U`, with permits of `P`: its metadata, once installed, and the ticket
/// of that installation's acquisition while it is pending ([`Ticket`]), whose
/// credit is the operation's. Only the tagged engine reads or changes it.
pub struct State<U, P> {
    meta: Option<Installed<Meta<U>, P>>,
    ticket: Option<Ticket>,
}

impl<U, P> State<U, P> {
    /// Nothing installed.
    pub const INITIAL: Self = Self {
        meta: None,
        ticket: None,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// untagged payload's state (a `U`) and its permit, as the auto traits would
// derive through `Installed`; stated once here so a nested tagged value's
// proof is one obligation per level.
unsafe impl<U: Send, P: Send> Send for State<U, P> {}

/// What a tagged value's construction holds: no metadata block; or the
/// block, at a phase, holding the untagged payload's construction state,
/// whose whole observation it carries. Progress alone: an acquisition bound
/// for the block is the root pending's custody (`CustodySink::bound`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaggedObservation<U> {
    Unallocated,
    Held { phase: Phase, child: U },
}

/// The cleanup classes of a tagged value ([`Reduction`]), `C` its untagged
/// payload's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
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
// stepping the payload in `Build` and `Complete` alike. The payload's own
// relation is a simulation of its cleanup, and the value leaves `Live`
// exactly when the payload's cleanup reports done.
impl<U: Reduction, P> Reduction for State<U, P> {
    type Class = TaggedClass<U::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            TaggedObservation::Unallocated => TaggedClass::Unallocated,
            TaggedObservation::Held { phase, child, .. } => match phase {
                Phase::Inspect => TaggedClass::Inspect,
                Phase::Build | Phase::Complete | Phase::Reclaim => {
                    TaggedClass::Live(U::class(child))
                }
                Phase::Release => TaggedClass::Release,
            },
        }
    }
}

// A tagged value reports `Done` exactly when its untagged payload does, its
// phase then `Complete`, which classes as `Live` of the payload's class; the
// payload, complete, is of its one complete class.
impl<U: Uniform, P> Uniform for State<U, P> {
    const COMPLETE: Self::Class = TaggedClass::Live(U::COMPLETE);
}

impl<U: Custody, P> Custody for State<U, P> {
    type Observation = TaggedObservation<U::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return TaggedObservation::Unallocated;
        };
        let meta = installed.get();
        TaggedObservation::Held {
            phase: meta.phase,
            child: meta.child.observe(),
        }
    }
}

/// The cost of a tagged value whose untagged payload costs `payload`, whose
/// state is `U`, with permits of type `P`: the metadata block, held for the
/// value's life; the tag inspection; cleanup's unit before any payload and
/// the metadata's release. The payload is built in the tagged value's own
/// bytes. None when a quantity does not fit in `u64`.
pub const fn cost<U, P>(payload: ConstructionCost) -> Option<ConstructionCost> {
    let meta = contract::<U, P>();
    let inspected = cost!(meta.write().checked_add(STEP_COST));
    let released = cost!(
        cost!(STEP_COST.checked_add(stable::release_cost::<P>())).checked_add(held(meta.block()))
    );
    ConstructionCost::fixed(cost!(inspected.checked_add(released))).checked_add(payload)
}

/// One unit of construction of the tagged value in the context's slot, from
/// the context's node: the derived binding's `build_step`, the context its
/// session's. Without metadata the state is `INITIAL`, so construction
/// begins; a completed or released value is refused. `Done` carries the
/// value's record, minted once its untagged payload is done (`Complete`).
pub fn build<'b, T: Payload<A>, A: Allocator>(
    ctx: Context<'b, '_, '_, '_, T, State<T::Untagged, A::Permit>, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, T>, A> {
    let mut ctx = ctx;
    let index = ctx.index();
    let node = ctx.node();
    let assembly = ctx.assembly();
    let (mut slot, pending) = ctx.acquiring();
    let state = slot.custody();
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: the header is the whole metadata, every field written.
        unsafe {
            stable::install::<Meta<T::Untagged>, Meta<T::Untagged>, A>(
                const { contract::<T::Untagged, A::Permit>() },
                &mut state.meta,
                pending,
                &mut state.ticket,
                || Meta {
                    child: T::UNTAGGED,
                    phase: Phase::Inspect,
                },
                |meta| meta,
                a,
            )?
        };
        return Ok(Building::Progress);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            match node.map(|node| node.kind()) {
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
            meta.phase = Phase::Build;
            Ok(Building::Progress)
        }
        Phase::Build => {
            // The payload is the tag's child: the node after the context's,
            // recomputed here; the value keeps no index of its own. It is
            // built only in `Build`, which a refused or erroring payload
            // step leaves unchanged and only the payload's `Done` ends;
            // cleanup moves the value out of it with the payload's first
            // completed unit ([`reclaim`]), and every other phase is refused
            // below.
            let child = index.checked_add(1).ok_or(BoundedError::Overflow)?;
            // SAFETY: the tagged value's own place and its untagged payload's
            // state, held in the metadata this value's state owns, which
            // only the payload callback uses. The payload is built within
            // the tagged value's session, so it is a part, not a child
            // binding with a session of its own.
            let payload = unsafe {
                ctx.part(child, |slot| {
                    let (place, state) = slot.into_parts();
                    let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
                    Ok::<_, BoundedError<A::Refusal>>(Slot::new(place, &mut meta.child))
                })
            }?;
            if T::build_payload(payload, a)? == Built::Progress {
                return Ok(Building::Progress);
            }
            // The payload's `Done`: a newtype's field record verified and
            // consumed by its part entry in this step, or a unit payload's
            // own admitted write. `Complete` records it, set here alone.
            let mut slot = ctx.slot();
            let installed = slot
                .custody()
                .meta
                .as_mut()
                .ok_or(BoundedError::PlanMismatch)?;
            installed.get().phase = Phase::Complete;
            // SAFETY: the tag was inspected and the untagged payload, the
            // whole value at this place, is done in this step, `Complete`
            // recording it.
            Ok(Building::Done(unsafe { assembly.assemble() }))
        }
        _ => Err(BoundedError::PlanMismatch.into()),
    }
}

/// One unit of cleanup of the tagged value in `slot`. Releasing the metadata
/// leaves the state `INITIAL`.
pub fn reclaim<T: Payload<A>, A: Allocator>(
    mut slot: Slot<'_, T, State<T::Untagged, A::Permit>>,
    a: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        // The metadata's acquisition, if pending, had its credit settled at
        // the operation's cleanup entry: the ticket is forgotten.
        state.ticket = None;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            meta.phase = Phase::Release;
        }
        Phase::Build | Phase::Complete | Phase::Reclaim => {
            // SAFETY: the payload state tracks all partial initialization of
            // the payload at this place.
            let payload = unsafe { Slot::new(place, &mut meta.child) };
            // A refused unit returned above, the phase unchanged; one the
            // payload completed moves the value into cleanup, so no build
            // reaches the payload again.
            meta.phase = match T::reclaim_payload(payload, a)? {
                Reclaimed::Done => Phase::Release,
                _ => Phase::Reclaim,
            };
        }
        Phase::Release => {
            // SAFETY: the payload owns no resources now. The metadata's
            // release was paid for by its installation.
            unsafe { stable::uninstall(&mut state.meta) };
            state.ticket = None;
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
) -> Option<u64> {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return Some(1);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Inspect => Some(2),
        Phase::Build | Phase::Complete | Phase::Reclaim => {
            // SAFETY: the payload state tracks the payload at `place`.
            T::remaining_payload(unsafe { Slot::new(place, &mut meta.child) })?.checked_add(1)
        }
        Phase::Release => Some(1),
    }
}

/// The permits the tagged value in `slot` owns, reported inside the caller's
/// open group: its metadata block's, then its untagged payload's while the
/// payload is live ([`Payload::observe_payload`]); none without metadata.
pub fn observe_permits<T: Payload<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Untagged, A::Permit>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    sink.permit(installed.permit(), None);
    let meta = installed.get();
    if !matches!(meta.phase, Phase::Build | Phase::Complete | Phase::Reclaim) {
        return PermitsObserved::Complete;
    }
    // SAFETY: the payload state tracks the payload at `place`.
    T::observe_payload(unsafe { Slot::new(place, &mut meta.child) }, sink)
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
        let bare = cost::<Written, Reservation>(ConstructionCost::ZERO).unwrap();
        assert_eq!(bare.per_byte, ConstructionCost::ZERO.per_byte);
        assert_eq!(
            bare.fixed.values,
            contract::<Written, Reservation>().write().values
                + 2 * STEP_COST.values
                + stable::release_cost::<Reservation>().values,
            "the install, the inspection, cleanup's unit and the release"
        );
        let payload = ConstructionCost::fixed(unit(16))
            .checked_add(ConstructionCost::checked_per_byte(unit(3)).unwrap())
            .unwrap();
        let tagged = cost::<Written, Reservation>(payload).unwrap();
        assert_eq!(Some(tagged.fixed), bare.fixed.checked_add(payload.fixed));
        assert_eq!(tagged.per_byte, payload.per_byte);
        let widest = ConstructionCost::fixed(ResourceBound {
            values: u64::MAX,
            ..ResourceBound::default()
        });
        assert_eq!(
            cost::<Written, Reservation>(widest),
            None,
            "a payload whose cost leaves no room is refused, never wrapped"
        );
    }
}
