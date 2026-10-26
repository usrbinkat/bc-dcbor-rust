//! Retained discriminant selection and tag-last enum construction.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody};
use crate::bounded::decode::construction::stable::{self, Installed};

/// Representation-specific projections generated from explicit enum layouts.
///
/// # Safety
/// Descriptors select unique wire discriminants. [`Self::start`] must return,
/// for each variant index below COUNT, a [`Self::Payload`] naming that
/// variant and holding its payload's initial state, and must neither
/// allocate nor unwind. Payload callbacks must project the variant the state
/// names using its declared Rust representation, retaining the same payload
/// state through cleanup. Commit writes only that variant's native tag, after
/// all its payload fields are initialized. No callback may construct an enum
/// value by value or form a reference to a partially initialized enum.
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
    /// # Safety
    /// The destination is stable and the payload state is unique.
    unsafe fn build_variant(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Payload,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The state and destination are the original selected payload pair.
    unsafe fn reclaim_variant(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Payload,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_variant`] still takes from `state`: the
    /// [`Reclaim::remaining`] of the variant's payload it names.
    ///
    /// # Safety
    /// As [`Self::reclaim_variant`].
    unsafe fn remaining_variant(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Payload,
    ) -> u64;
    /// # Safety
    /// All payload fields of the variant `state` names are initialized;
    /// TAG_BYTES was admitted.
    unsafe fn commit(state: &Self::Payload, place: NonNull<MaybeUninit<Self>>);
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
    Release,
}

/// Move the payload state `phase` holds into the phase `next` makes of it.
fn carry<V>(phase: &mut Phase<V>, next: fn(V) -> Phase<V>) {
    *phase = match core::mem::replace(phase, Phase::Release) {
        Phase::Build(child) | Phase::Commit(child) | Phase::Complete(child) => next(child),
        other => other,
    };
}

struct Meta<V> {
    /// The document index of the node the current phase reads.
    index: usize,
    phase: Phase<V>,
}

/// The construction state of an enum whose payloads' states are `V`, with
/// permits of `P`: its metadata, once installed; what that installation has
/// admitted; and the variant index the selection has reached. Only the enum
/// engine reads or changes it.
pub struct State<V, P> {
    meta: Option<Installed<Meta<V>, P>>,
    admitted: stable::Admitted,
    variant: usize,
}

impl<V, P> State<V, P> {
    /// Nothing installed, no variant passed.
    pub const INITIAL: Self = Self {
        meta: None,
        admitted: stable::Admitted::Nothing,
        variant: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// selected payload's state (a `V`), its permit and plain counters, as the
// auto traits would derive through `Installed`; stated once here so a nested
// enum's proof is one obligation per level.
unsafe impl<V: Send, P: Send> Send for State<V, P> {}

/// What an enum's construction holds: no metadata block, with the
/// admissions held toward it; or the block, at a document index, past
/// `variant` variants in the selection, in a phase that carries the
/// selected payload's whole observation once a variant is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnumObservation<V> {
    Unallocated(Admitted),
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
    Release,
}

impl<V: Custody, P> Custody for State<V, P> {
    type Observation = EnumObservation<V::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return EnumObservation::Unallocated(self.admitted);
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
/// variant compared, then the rejection.
pub const fn selection(count: usize) -> ResourceBound {
    times(STEP_COST, count as u64 + 1)
}

/// The cost of an enum of the `variants` payload costs, whose payloads'
/// states are `V`, its native tag of `tag_bytes`, with permits of type `P`:
/// the metadata block, held for the value's life; the tag, shape and
/// discriminant inspections; the [`selection`] over its variants; the native
/// tag's commit; cleanup's unit before any payload and the metadata's
/// release. Only one variant's payload is built, in the enum's own bytes:
/// the largest of their costs.
pub const fn cost<V, P>(tag_bytes: usize, variants: &[ConstructionCost]) -> ConstructionCost {
    let meta = stable::Metadata::whole::<Meta<V>, P>().bytes();
    let inspections = times(STEP_COST, 3);
    let selection = selection(variants.len());
    let fixed = plus(
        plus(
            plus(stable::install_cost::<Meta<V>, P>(), inspections),
            plus(selection, commit(tag_bytes).bound()),
        ),
        plus(plus(STEP_COST, stable::release_cost::<P>()), held(meta)),
    );
    let mut payload = ConstructionCost::ZERO;
    let mut index = 0;
    while index < variants.len() {
        payload = payload.larger(variants[index]);
        index += 1;
    }
    ConstructionCost::fixed(fixed).plus(payload)
}

/// # Safety
/// The destination and state satisfy InPlace's stable ownership contract.
pub unsafe fn build<T: Variants<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Payload, A::Permit>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: every metadata field is written.
        unsafe {
            stable::install::<Meta<T::Payload>, A>(
                &mut state.meta,
                &mut state.admitted,
                const { stable::Metadata::whole::<Meta<T::Payload>, A::Permit>() },
                |meta| {
                    meta.write(Meta {
                        index,
                        phase: Phase::Tag,
                    })
                },
                a,
            )?
        };
        return Ok(Built::Progress);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Tag => {
            STEP.admit(a)?;
            if let Some(expected) = T::TAG {
                match node_at(document, meta.index).map(|n| n.kind()) {
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
            match node_at(document, meta.index).map(|n| n.kind()) {
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
            let discriminant = match node_at(document, meta.index).map(|n| n.kind()) {
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
            if state.variant == T::COUNT {
                return Err(wrong_type());
            }
            let (expected, expected_length) = T::descriptor(state.variant);
            if expected == discriminant {
                if expected_length != length {
                    return Err(wrong_type());
                }
                // The payload's custody starts with its selection, before
                // any of its fields is built.
                let child = T::start(state.variant).ok_or(BoundedError::PlanMismatch)?;
                meta.phase = Phase::Build(child);
            } else {
                state.variant += 1;
            }
        }
        Phase::Build(ref mut child) => {
            if unsafe { T::build_variant(document, meta.index, place, child, a)? } == Built::Done {
                carry(&mut meta.phase, Phase::Commit);
            }
        }
        Phase::Commit(ref child) => {
            // The native tag is committed in one unit, its extent checked
            // where the enum's type is used.
            const { commit(T::TAG_BYTES) }.admit(a)?;
            unsafe { T::commit(child, place) };
            carry(&mut meta.phase, Phase::Complete);
            return Ok(Built::Done);
        }
        Phase::Complete(_) | Phase::Release => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// # Safety
/// The destination and state are the original construction pair.
pub unsafe fn reclaim<T: Variants<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Payload, A::Permit>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Build(ref mut child)
        | Phase::Commit(ref mut child)
        | Phase::Complete(ref mut child) => {
            if unsafe { T::reclaim_variant(place, child, a)? } == Reclaimed::Done {
                // The reclaimed payload state owns nothing; it ends here.
                meta.phase = Phase::Release;
            }
        }
        Phase::Release => {
            // SAFETY: payload reclamation finished, or no payload was
            // started. The metadata's release was paid for by its
            // installation.
            unsafe { stable::uninstall(&mut state.meta) };
            return Ok(Reclaimed::Done);
        }
        Phase::Tag | Phase::Shape | Phase::Discriminant { .. } | Phase::Select { .. } => {
            STEP.admit(a)?;
            meta.phase = Phase::Release;
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from `state`: no metadata, one; before
/// a variant is selected, one to `Release` and one to release; a selected
/// payload, its own calls, the last of which reaches `Release`, then one;
/// `Release`, one.
///
/// # Safety
/// As [`reclaim`].
pub unsafe fn remaining<T: Variants<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Payload, A::Permit>,
) -> u64 {
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    match installed.get().phase {
        Phase::Build(ref mut child)
        | Phase::Commit(ref mut child)
        | Phase::Complete(ref mut child) => {
            // SAFETY: the state names the selected variant's payload.
            unsafe { T::remaining_variant(place, child) }.saturating_add(1)
        }
        Phase::Release => 1,
        Phase::Tag | Phase::Shape | Phase::Discriminant { .. } | Phase::Select { .. } => 2,
    }
}
