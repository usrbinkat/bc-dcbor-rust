//! Retained discriminant selection and tag-last enum construction.
use super::*;
use crate::bounded::boundary::{Predicate, boundary, position};
use crate::bounded::decode::construction::reclamation::Custody;
use crate::bounded::decode::construction::stable::{self, Installed, Ticket};
use crate::sync::{Atomics, Representation};

/// Representation-specific projections generated from explicit enum layouts.
///
/// Each callback receives a [`Slot`] of the enum's root place and the
/// selected variant's payload state, which names that variant: a caller
/// holding one has nothing to promise.
///
/// # Safety
/// An implementation keeps six obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *discriminants*: the descriptors select unique wire discriminants.
/// - *start*: [`Self::start`] returns, for each variant index below COUNT, a
///   [`Self::Payload`] naming that variant and holding its payload's initial
///   state, and neither allocates nor unwinds.
/// - *projection*: payload callbacks project the variant the state names
///   using its declared Rust representation, retaining the same payload
///   state through cleanup.
/// - *tag*: commit writes only that variant's native tag, into the tag's
///   own bytes, which no payload place covers.
/// - *reference*: no callback constructs an enum value by value or forms a
///   reference to a partially initialized enum.
/// - *order*: each callback is sound for every call, in any order, as its
///   payload's own methods are.
pub unsafe trait Variants<A: Allocator>: Sized {
    const COUNT: usize;
    const TAG: Option<u64>;
    const TAG_BYTES: usize;
    /// The construction state of one variant's payload, naming the variant:
    /// no payload state can be paired with another variant. Its observation
    /// names the variant and carries its payload's observation whole.
    type Payload: Custody;
    fn descriptor(variant: usize) -> (u64, u64);
    /// The initial payload state of variant `variant`, or `None` for an index
    /// past the last variant.
    fn start(variant: usize) -> Option<Self::Payload>;
    /// One unit of construction of the payload of the variant the context's
    /// state names, from the context's node, the payload's: a part of the
    /// enum, built within the enum's own construction.
    fn build_variant(
        ctx: Context<'_, '_, '_, '_, Self, Self::Payload, A>,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// One unit of cleanup of the payload of the variant the slot's state
    /// names.
    fn reclaim_variant(
        slot: Slot<'_, Self, Self::Payload>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_variant`] still takes from the slot's state:
    /// the [`Reclaim::remaining`] of the variant's payload it names, `None`
    /// when it does not fit in `u64`.
    fn remaining_variant(slot: PeekSlot<'_, Self, Self::Payload>) -> Option<u64>;
    /// The permits the payload of the variant the slot's state names owns,
    /// reported inside the caller's open group: its
    /// [`Reclaim::observe_permits`], projected as for
    /// [`Self::remaining_variant`].
    fn observe_variant(
        slot: PeekSlot<'_, Self, Self::Payload>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved;
    /// Write the native tag of the variant the slot's state names, the
    /// state, the enum place's custody while a variant is selected, borrowed
    /// exclusively for the write. The engine commits once the payload is
    /// built, its write admitted ([`Self::TAG_BYTES`]).
    fn commit(slot: Slot<'_, Self, Self::Payload>);
}

/// Where an enum's construction is, each phase holding exactly the data it
/// needs: the wire discriminant and length until a variant is selected, then
/// the selected payload's state, held from its selection until its cleanup.
/// The two never coexist, so the metadata block holds the larger of them.
enum Phase<V> {
    Tag,
    Shape,
    /// The array form's length read; its discriminant is next.
    Discriminant {
        length: u64,
    },
    /// The discriminant and length read, compared with each variant in turn.
    Select {
        discriminant: u64,
        length: u64,
    },
    Build(V),
    Commit(V),
    Complete(V),
    /// The selected payload's cleanup under way: entered by the first
    /// cleanup step the payload completes, so no build reaches a payload
    /// being cleaned up.
    Reclaim(V),
    Release,
}

/// Move the payload state `phase` holds into the phase `next` makes of it.
fn carry<V>(phase: &mut Phase<V>, next: fn(V) -> Phase<V>) {
    *phase = match core::mem::replace(phase, Phase::Release) {
        Phase::Build(child)
        | Phase::Commit(child)
        | Phase::Complete(child)
        | Phase::Reclaim(child) => next(child),
        other => other,
    };
}

/// Written whole with its permit in one admitted unit of at most a quantum
/// ([`contract`]). For a derived enum, `V` holds one variant's record state,
/// a field map's (`fields::State`, 24 bytes: its block and ticket handles,
/// the fields completed as `u32` and its phase) behind the derived payload
/// enum's tag, so at most 32; [`Phase`] holds `V` or the selection's two
/// words behind its own tag, at most 40; with the index, 48, and the 16-byte
/// permit, 64: one quantum for any variant count, with no niche assumed.
/// Checked where the type is used (`Contract::of`, E0080) and by
/// `a_two_variant_enums_metadata_fits_one_quantum`.
struct Meta<V> {
    /// The document index of the node the current phase reads: the enum's
    /// own progress through its node and that node's heads (the tag's
    /// content, the array's discriminant, the payload), set from the
    /// context's node at installation and advanced only by the inspection
    /// that read the node before it. The one record of which node the
    /// selected payload is built from.
    index: usize,
    phase: Phase<V>,
}

impl<V> Representation for Meta<V> {
    type In<F: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds, its whole value
/// written with the permit ([`stable::Contract`]): the one definition its
/// installation and the enum's cost read.
const fn contract<V, P>() -> stable::Contract<Meta<V>, Meta<V>, P> {
    stable::Contract::of()
}

/// The construction state of an enum whose payloads' states are `V`, with
/// permits of `P`: its metadata, once installed; the ticket of that
/// installation's acquisition while it is pending, whose credit
/// is the operation's; and the variant index the selection has reached. Only
/// the enum engine reads or changes it.
pub struct State<V, P> {
    meta: Option<Installed<Meta<V>, P>>,
    ticket: Option<Ticket>,
    variant: usize,
}

impl<V, P> State<V, P> {
    /// Nothing installed, no variant passed.
    pub const INITIAL: Self = Self {
        meta: None,
        ticket: None,
        variant: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// selected payload's state (a `V`), its permit and plain counters, as the
// auto traits would derive through `Installed`; stated once here so a nested
// enum's proof is one obligation per level.
unsafe impl<V: Send, P: Send> Send for State<V, P> {}

/// What an enum's construction holds: no metadata block; or the block, at a
/// document index, past `variant` variants in the selection, in a phase that
/// carries the selected payload's whole observation once a variant is
/// selected. Progress alone: an acquisition bound for the block is the root
/// pending's custody (`CustodySink::bound`), never this observation's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnumObservation<V> {
    Unallocated,
    Held {
        index: usize,
        variant: usize,
        phase: EnumPhase<V>,
    },
}

/// An enum's phase as observed, `V` the selected payload's observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnumPhase<V> {
    Tag,
    Shape,
    Discriminant { length: u64 },
    Select { discriminant: u64, length: u64 },
    Build(V),
    Commit(V),
    Complete(V),
    Reclaim(V),
    Release,
}

impl<V: Custody, P> Custody for State<V, P> {
    type Observation = EnumObservation<V::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return EnumObservation::Unallocated;
        };
        let meta = installed.get();
        let phase = match &mut meta.phase {
            Phase::Tag => EnumPhase::Tag,
            Phase::Shape => EnumPhase::Shape,
            Phase::Discriminant { length } => EnumPhase::Discriminant { length: *length },
            Phase::Select {
                discriminant,
                length,
            } => EnumPhase::Select {
                discriminant: *discriminant,
                length: *length,
            },
            Phase::Build(child) => EnumPhase::Build(child.observe()),
            Phase::Commit(child) => EnumPhase::Commit(child.observe()),
            Phase::Complete(child) => EnumPhase::Complete(child.observe()),
            Phase::Reclaim(child) => EnumPhase::Reclaim(child.observe()),
            Phase::Release => EnumPhase::Release,
        };
        EnumObservation::Held {
            index: meta.index,
            variant: self.variant,
            phase,
        }
    }
}

/// Committing a native tag of `tag_bytes` bytes after its payload: one value
/// and the tag's bytes, its write extent.
const fn commit(tag_bytes: usize) -> Unit<Caller> {
    Unit::new(Caller, 1, crate::bounded::write_extent(tag_bytes))
}

/// The selection's units over `count` variants: one per variant passed and
/// one more. A discriminant no variant has takes exactly this many: each
/// variant compared, then the rejection. None when a quantity does not fit
/// in `u64`.
pub const fn selection(count: usize) -> Option<ResourceBound> {
    STEP_COST.checked_mul(count as u64 + 1)
}

/// The cost of an enum of the `variants` payload costs, whose payloads'
/// states are `V`, its native tag of `tag_bytes`, with permits of type `P`:
/// the metadata block, held for the value's life; the tag, shape and
/// discriminant inspections; the [`selection`] over its variants; the native
/// tag's commit; cleanup's unit before any payload and the metadata's
/// release. Only one variant's payload is built, in the enum's own bytes:
/// the largest of their costs. None when a quantity does not fit in `u64`.
pub const fn cost<V, P>(
    tag_bytes: usize,
    variants: &[ConstructionCost],
) -> Option<ConstructionCost> {
    let meta = contract::<V, P>();
    let inspections = cost!(STEP_COST.checked_mul(3));
    let selection = cost!(selection(variants.len()));
    let read = cost!(meta.write().checked_add(inspections));
    let selected = cost!(selection.checked_add(commit(tag_bytes).bound()));
    let released = cost!(
        cost!(STEP_COST.checked_add(stable::release_cost::<P>())).checked_add(held(meta.block()))
    );
    let fixed = cost!(cost!(read.checked_add(selected)).checked_add(released));
    let mut payload = ConstructionCost::ZERO;
    let mut index = 0;
    while index < variants.len() {
        payload = payload.larger(variants[index]);
        index += 1;
    }
    ConstructionCost::fixed(fixed).checked_add(payload)
}

/// One unit of construction of the enum in the context's slot, from the
/// context's node. Without metadata the state is `INITIAL` (every cleanup
/// that releases the metadata restores it), so construction begins; a
/// completed or released enum is refused.
///
/// The selected payload is a part of the enum, built from `meta.index`,
/// which no step changes once a variant is selected: a refused or erroring
/// payload step leaves it, the phase and the payload's state unchanged. No
/// payload is built once cleanup began: cleanup ([`reclaim`]) steps a
/// selected payload only from its own state and moves every phase toward
/// `Release`, which this function refuses, nothing changed. Cleanup of a
/// payload under `Build` does not move the phase until the payload reports
/// `Done`; a build in that window would step a payload being cleaned up,
/// so only the enum's owner's phase (a parent's cleanup phase, or the root's
/// session once cleaning) keeps a build from reaching it. A enum reclaimed
/// to its end is `INITIAL` again, under the same owner's guard.
pub fn build<'b, T: Variants<A>, A: Allocator>(
    ctx: Context<'b, '_, '_, '_, T, State<T::Payload, A::Permit>, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, T>, A> {
    let mut ctx = ctx;
    let assembly = ctx.assembly();
    let index = ctx.index();
    let nodes = ctx.nodes();
    let (mut slot, pending) = ctx.acquiring();
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        if state.variant != 0 {
            return Err(BoundedError::PlanMismatch.into());
        }
        // SAFETY: the header is the whole metadata, every field written.
        unsafe {
            stable::install::<Meta<T::Payload>, Meta<T::Payload>, A>(
                const { contract::<T::Payload, A::Permit>() },
                &mut state.meta,
                pending,
                &mut state.ticket,
                || Meta {
                    index,
                    phase: Phase::Tag,
                },
                |meta| meta,
                a,
            )?
        };
        return Ok(Building::Progress);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Tag => {
            STEP.admit(a)?;
            if let Some(expected) = T::TAG {
                match nodes.node(meta.index).map(|n| n.kind()) {
                    Some(Kind::Tagged(found)) if found == expected => {}
                    Some(Kind::Tagged(found)) => {
                        return Err(crate::bounded::decode::DecodeError::Invalid(
                            crate::Error::WrongTag(
                                crate::Tag::with_value(expected),
                                crate::Tag::with_value(found),
                            ),
                        ));
                    }
                    _ => return Err(wrong_type()),
                }
                meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            }
            meta.phase = Phase::Shape;
        }
        Phase::Shape => {
            STEP.admit(a)?;
            match nodes.node(meta.index).map(|n| n.kind()) {
                Some(Kind::Unsigned(discriminant)) => {
                    meta.phase = Phase::Select {
                        discriminant,
                        length: 0,
                    };
                }
                Some(Kind::Array(length)) if length > 0 => {
                    meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
                    meta.phase = Phase::Discriminant { length };
                }
                _ => return Err(wrong_type()),
            }
        }
        Phase::Discriminant { length } => {
            STEP.admit(a)?;
            let discriminant = match nodes.node(meta.index).map(|n| n.kind()) {
                Some(Kind::Unsigned(discriminant)) => discriminant,
                Some(Kind::Negative(_)) => {
                    return Err(crate::bounded::decode::DecodeError::Invalid(
                        crate::Error::OutOfRange,
                    ));
                }
                _ => return Err(wrong_type()),
            };
            meta.index = meta.index.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.phase = Phase::Select {
                discriminant,
                length,
            };
        }
        Phase::Select {
            discriminant,
            length,
        } => {
            STEP.admit(a)?;
            if boundary!(a, Predicate::Field, state.variant, T::COUNT).is_eq() {
                return Err(wrong_type());
            }
            let (expected, expected_length) = T::descriptor(state.variant);
            if expected == discriminant {
                if expected_length != length {
                    return Err(wrong_type());
                }
                boundary!(a, Predicate::Field => position(state.variant, T::COUNT));
                // The payload's custody starts with its selection, before
                // any of its fields is built.
                let child = T::start(state.variant).ok_or(BoundedError::PlanMismatch)?;
                meta.phase = Phase::Build(child);
            } else {
                state.variant += 1;
            }
        }
        Phase::Build(_) => {
            let payload_index = meta.index;
            // SAFETY: the enum's root place, and the selected variant's
            // payload state in this enum's metadata, started for that
            // variant by `T::start`.
            let payload = unsafe {
                ctx.part(payload_index, |slot| {
                    let (place, state) = slot.into_parts();
                    let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
                    match meta.phase {
                        Phase::Build(ref mut child) => {
                            Ok::<_, BoundedError<A::Refusal>>(Slot::new(place, child))
                        }
                        _ => Err(BoundedError::PlanMismatch),
                    }
                })
            }?;
            if T::build_variant(payload, a)? == Built::Done {
                let mut slot = ctx.slot();
                let meta = slot
                    .custody()
                    .meta
                    .as_mut()
                    .ok_or(BoundedError::PlanMismatch)?
                    .get();
                carry(&mut meta.phase, Phase::Commit);
            }
        }
        Phase::Commit(ref mut child) => {
            // The native tag is committed in one unit, its extent checked
            // where the enum's type is used.
            const { commit(T::TAG_BYTES) }.admit(a)?;
            // SAFETY: the enum's root place, and the selected variant's
            // payload state.
            T::commit(unsafe { Slot::new(place, child) });
            carry(&mut meta.phase, Phase::Complete);
            // SAFETY: `Commit` is entered only from `Build` after
            // `build_variant` returned `Done`, a result whose record,
            // confined by its brand to the step that minted it, was verified
            // against the payload place this enum projected for the selected
            // variant (`fields::build_payload`); the native tag is written
            // above. So the selected variant's payload
            // and tag are initialized, and the slot is not reclaimed: cleanup
            // moves the phase toward `Release`, which this function refuses.
            return Ok(Building::Done(unsafe { assembly.assemble() }));
        }
        Phase::Complete(_) | Phase::Reclaim(_) | Phase::Release => {
            return Err(BoundedError::PlanMismatch.into());
        }
    }
    Ok(Building::Progress)
}

/// One unit of cleanup of the enum in `slot`. Releasing the metadata restores
/// `INITIAL`, so a later step reports `Done` and a later build begins anew.
pub fn reclaim<T: Variants<A>, A: Allocator>(
    mut slot: Slot<'_, T, State<T::Payload, A::Permit>>,
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
        Phase::Build(ref mut child)
        | Phase::Commit(ref mut child)
        | Phase::Complete(ref mut child)
        | Phase::Reclaim(ref mut child) => {
            // SAFETY: the enum's root place, and the selected variant's
            // payload state.
            let payload = unsafe { Slot::new(place, child) };
            match T::reclaim_variant(payload, a)? {
                // The reclaimed payload state owns nothing; it ends here.
                Reclaimed::Done => meta.phase = Phase::Release,
                // The payload's cleanup began: no build reaches it again.
                // A refused step returned above, the phase unchanged.
                _ => carry(&mut meta.phase, Phase::Reclaim),
            }
        }
        Phase::Release => {
            // SAFETY: payload reclamation finished, or no payload was
            // started. The metadata's release was paid for by its
            // installation.
            unsafe { stable::uninstall(&mut state.meta) };
            state.variant = 0;
            return Ok(Reclaimed::Done);
        }
        Phase::Tag | Phase::Shape | Phase::Discriminant { .. } | Phase::Select { .. } => {
            STEP.admit(a)?;
            meta.phase = Phase::Release;
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from the slot's state: no metadata, one;
/// before a variant is selected, one to `Release` and one to release; a
/// selected payload, its own calls, the last of which reaches `Release`, then
/// one; `Release`, one.
pub fn remaining<T: Variants<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Payload, A::Permit>>,
) -> Option<u64> {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return Some(1);
    };
    match installed.get().phase {
        Phase::Build(ref mut child)
        | Phase::Commit(ref mut child)
        | Phase::Complete(ref mut child)
        | Phase::Reclaim(ref mut child) => {
            // SAFETY: the state names the selected variant's payload.
            T::remaining_variant(unsafe { Slot::new(place, child) })?.checked_add(1)
        }
        Phase::Release => Some(1),
        Phase::Tag | Phase::Shape | Phase::Discriminant { .. } | Phase::Select { .. } => Some(2),
    }
}

/// The permits the enum in `slot` owns, reported inside the caller's open
/// group: its metadata block's, then the selected payload's while one is
/// selected ([`Variants::observe_variant`]); none without metadata.
pub fn observe_permits<T: Variants<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Payload, A::Permit>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    sink.permit(installed.permit(), None);
    match installed.get().phase {
        Phase::Build(ref mut child)
        | Phase::Commit(ref mut child)
        | Phase::Complete(ref mut child)
        | Phase::Reclaim(ref mut child) => {
            // SAFETY: the state names the selected variant's payload.
            T::observe_variant(unsafe { Slot::new(place, child) }, sink)
        }
        Phase::Tag
        | Phase::Shape
        | Phase::Discriminant { .. }
        | Phase::Select { .. }
        | Phase::Release => PermitsObserved::Complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Reservation;

    /// A derived enum's payload state for two dataful variants, each a field
    /// map's record state, as the derive's expansion holds them.
    #[expect(
        dead_code,
        reason = "a layout fixture: its variants are measured, not built"
    )]
    enum TwoVariants {
        First(super::super::fields::State<Written, Reservation>),
        Second(super::super::fields::State<Written, Reservation>),
    }

    /// The metadata of an enum of two field-map variants is written in one
    /// unit of at most a quantum: its contract evaluated in a constant here,
    /// which refuses an overrun to compile (E0080) in the crate's own tests;
    /// and the sizes [`Meta`]'s derivation rests on, measured.
    #[test]
    fn a_two_variant_enums_metadata_fits_one_quantum() {
        let contract = const { contract::<TwoVariants, Reservation>() };
        assert!(contract.write().bytes <= stable::QUANTUM as u64);
        assert_eq!(
            core::mem::size_of::<super::super::fields::State<Written, Reservation>>(),
            24,
            "a field map's record state"
        );
        assert!(core::mem::size_of::<TwoVariants>() <= 32);
        assert!(core::mem::size_of::<Phase<TwoVariants>>() <= 40);
        assert!(
            core::mem::size_of::<Meta<TwoVariants>>() + core::mem::size_of::<Reservation>()
                <= stable::QUANTUM
        );
    }

    /// An enum's cost, evaluated at run time as the derive evaluates it in
    /// constants: the native tag committed in one unit of its own bytes;
    /// one selection unit per variant and one more; and, one variant being
    /// built in the enum's own bytes, the largest variant's payload cost,
    /// never their sum.
    #[test]
    fn an_enums_cost_is_its_largest_variants_with_a_selection_per_variant() {
        assert_eq!(commit(1).bound(), unit(1));
        assert_eq!(commit(0).bound(), unit(0));
        let payload = |fixed: usize, per_byte: usize| {
            ConstructionCost::fixed(unit(fixed))
                .checked_add(ConstructionCost::checked_per_byte(unit(per_byte)).unwrap())
                .unwrap()
        };
        let (large, small) = (payload(40, 2), payload(8, 1));
        let selection = |count: usize| selection(count).unwrap();
        let enumeration = |tag_bytes, variants: &[ConstructionCost]| {
            cost::<Written, Reservation>(tag_bytes, variants).unwrap()
        };
        let alone = enumeration(1, &[large]);
        let both = enumeration(1, &[large, small]);
        let reversed = enumeration(1, &[small, large]);
        assert_eq!(both, reversed, "the order of variants changes no cost");
        assert_eq!(
            both.fixed.values - alone.fixed.values,
            STEP_COST.values,
            "a further variant is one more selection unit"
        );
        assert_eq!(
            both.fixed.bytes, alone.fixed.bytes,
            "and its payload, smaller, is not charged"
        );
        assert_eq!(both.per_byte, large.per_byte);
        assert_eq!(
            enumeration(4, &[large]).fixed.bytes - alone.fixed.bytes,
            3,
            "a native tag of four bytes commits three more"
        );
        assert_eq!(
            enumeration(1, &[]).fixed.values + selection(1).values - selection(0).values,
            enumeration(1, &[ConstructionCost::ZERO]).fixed.values
        );
        let widest = ConstructionCost::fixed(ResourceBound {
            values: u64::MAX,
            ..ResourceBound::default()
        });
        assert_eq!(
            cost::<Written, Reservation>(1, &[widest]),
            None,
            "a payload whose cost leaves no room is refused, never wrapped"
        );
    }
}
