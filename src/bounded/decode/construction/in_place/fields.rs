//! Retained required-field map construction for generated structs.
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody};
use crate::bounded::decode::construction::stable::{self, Installed, Stack};
use core::mem::MaybeUninit;
use core::ptr::NonNull;

/// Compiler-generated field projections, indexed by ascending integer wire key.
///
/// # Safety
/// Keys must be unique and strictly increasing. Every payload field must occur
/// exactly once; COUNT must equal the payload field count. Non-payload enum tags
/// are initialized separately by the enum engine. Projections must use the actual
/// aligned struct layout. [`Self::start`] must return, for each field index
/// below COUNT, a [`Self::Field`] naming that field and holding its type's
/// [`Reclaim::INITIAL`] state, and must neither allocate nor unwind. Each
/// field callback must delegate to the field its state names, with that
/// field's InPlace/Reclaim implementation, the same stable address and the
/// state it carries.
pub unsafe trait Fields<A: Allocator>: Sized {
    const COUNT: usize;
    const TAG: Option<u64> = None;
    const POSITIONAL: bool = false;
    /// One field's construction state, naming the field it belongs to: a
    /// value of it is the state of exactly one field, so no state can be
    /// paired with another field. Its observation names the field and
    /// carries that field's own observation whole.
    type Field: Custody;
    fn key(field: usize) -> u64;
    fn optional(field: usize) -> bool;
    /// The initial state of the field of dense index `field`, or `None` for
    /// an index past the last field.
    fn start(field: usize) -> Option<Self::Field>;
    /// # Safety
    /// Initializes only the field `state` names, which is omitted, and
    /// retains its cleanup state.
    unsafe fn missing_field(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Field,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The root destination and field state satisfy InPlace's preconditions.
    unsafe fn build_field(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Field,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// # Safety
    /// The state tracks exactly the initialized parts of the field it names.
    unsafe fn reclaim_field(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::Field,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_field`] still takes from `state`: the
    /// [`Reclaim::remaining`] of the field it names, at that field's place,
    /// with its own state.
    ///
    /// # Safety
    /// As [`Self::reclaim_field`].
    unsafe fn remaining_field(place: NonNull<MaybeUninit<Self>>, state: &mut Self::Field) -> u64;
}

/// Where a field map's construction or cleanup is: the tag and map
/// inspections, the search for each entry's field, a field's record
/// allocated and its value built or its absence written, the advance past
/// it, completion; then, reclaiming, each field's record newest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Inspect,
    Map,
    Find,
    Search,
    Allocate,
    Build,
    Missing,
    AdvanceMissing,
    Advance,
    Complete,
    Reclaim,
}
/// The metadata and its permit are written as one admitted unit of at most
/// [`stable::QUANTUM`] bytes, so field indices, bounded by the schema's field
/// count, are held as `u32`.
struct Meta<F, P> {
    next: usize,
    end: usize,
    low: u32,
    high: u32,
    /// One custody record per started field, holding its state.
    children: Stack<F, P>,
}

/// The construction state of a field map whose fields' states are `F`, with
/// permits of `P`: its metadata, once installed; what that installation has
/// admitted; its phase; and the fields completed, in key order. Only the field
/// engine reads or changes it; outside code can only start one.
pub struct State<F, P> {
    meta: Option<Installed<Meta<F, P>, P>>,
    admitted: stable::Admitted,
    // Control belongs to the continuation, including before installation and
    // after release. Keeping it here also avoids an aligned word in Meta's
    // single-quantum initialization; it shares padding with `admitted`.
    phase: Phase,
    position: usize,
}

impl<F, P> State<F, P> {
    /// Nothing installed, nothing completed.
    pub const INITIAL: Self = Self {
        meta: None,
        admitted: stable::Admitted::Nothing,
        phase: Phase::Inspect,
        position: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// field records (each an `F`), their permits and plain indices, as the auto
// traits would derive through `Installed` and `Stack`; stated once here so a
// nested record's proof is one obligation per level.
unsafe impl<F: Send, P: Send> Send for State<F, P> {}

/// What a field map's construction holds: no metadata block, with the
/// admissions held toward it; or the block, holding the field records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldsObservation<F> {
    Unallocated(Admitted),
    Held(FieldsCustody<F>),
}

/// A field map's custody once its metadata is held, `F` a field's
/// observation: the phase; the fields completed, in key order; the document
/// positions searched and the key range; the field records held and the
/// admissions held toward the next; and the newest record's field, the one
/// under construction or cleanup whenever one is, whole. Every record
/// before the newest holds a complete field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldsCustody<F> {
    pub phase: Phase,
    pub completed: usize,
    pub next: usize,
    pub end: usize,
    pub low: u32,
    pub high: u32,
    pub records: usize,
    pub admitted: Admitted,
    pub newest: Option<F>,
}

impl<F: Custody, P> Custody for State<F, P> {
    type Observation = FieldsObservation<F::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return FieldsObservation::Unallocated(self.admitted);
        };
        let meta = installed.get();
        FieldsObservation::Held(FieldsCustody {
            phase: self.phase,
            completed: self.position,
            next: meta.next,
            end: meta.end,
            low: meta.low,
            high: meta.high,
            records: meta.children.len(),
            admitted: meta.children.admitted(),
            newest: meta.children.top().map(|child| child.state.observe()),
        })
    }
}

/// A field index in the metadata's compact form.
fn field_index<R>(field: usize) -> Result<u32, BoundedError<R>> {
    u32::try_from(field).map_err(|_| BoundedError::Overflow)
}

/// The cost of a record of the `fields` given in key order, built by
/// [`build`] and reclaimed by [`reclaim`], whose fields' states are `F`,
/// with permits of type `P`.
///
/// Fixed: the metadata block, held for the value's life; the tag and map
/// inspections; the last find; cleanup's transition and the metadata's
/// release. Per field, present or omitted, at most once: its custody record,
/// held; its advance; its record's release; its own fixed cost, and one unit
/// of each quantity for the rounding of its per-byte part. The fields'
/// subtrees partition the record's bytes, so their per-byte parts together
/// are at most the largest of them. Positional fields are found by one unit
/// each. Keyed entries, the fields' and any unknown key's alike, are
/// [`entries`].
pub const fn cost<F, P>(positional: bool, fields: &[ConstructionCost]) -> ConstructionCost {
    let meta = stable::Metadata::whole::<Meta<F, P>, P>().bytes();
    let child = stable::Metadata::whole::<stable::Child<F, P>, P>().bytes();
    let release = stable::release_cost::<P>();
    // The metadata installed; the tag, map and last find steps; cleanup's
    // transition step; the metadata released.
    let mut fixed = plus(
        plus(stable::install_cost::<Meta<F, P>, P>(), times(STEP_COST, 4)),
        plus(release, held(meta)),
    );
    let mut per_byte = ConstructionCost::ZERO.per_byte;
    let mut index = 0;
    while index < fields.len() {
        // The custody record pushed, the advance step, the record popped.
        let each = plus(
            plus(
                plus(stable::install_cost::<stable::Child<F, P>, P>(), STEP_COST),
                release,
            ),
            plus(held(child), plus(fields[index].fixed, ROUNDING)),
        );
        fixed = plus(fixed, each);
        if positional {
            fixed = plus(fixed, STEP_COST);
        }
        per_byte = larger(per_byte, fields[index].per_byte);
        index += 1;
    }
    let mut cost = ConstructionCost { fixed, per_byte };
    if !positional {
        cost = cost.plus(entries(fields.len()));
    }
    cost
}

/// One keyed entry's units in a record of `count` fields: its find, at most
/// `floor(log2 count) + 1` search steps, and one to locate or skip its
/// value. An unknown key below every field's takes exactly this many: the
/// search halves toward the first field at every step.
pub const fn entry(count: usize) -> ResourceBound {
    let search = if count == 0 {
        0
    } else {
        count.ilog2() as u64 + 1
    };
    times(STEP_COST, search + 2)
}

/// The keyed entries of a record of `count` fields, by the record's bytes:
/// each entry has a key and a value of a byte at least, so one [`entry`]
/// per two bytes, half a unit of each per byte.
pub const fn entries(count: usize) -> ConstructionCost {
    ConstructionCost {
        fixed: ConstructionCost::ZERO.fixed,
        per_byte: times(entry(count), PER_BYTE_SCALE / 2),
    }
}

/// # Safety
/// Called with the stable root destination and its original state.
pub unsafe fn build<T: Fields<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Field, A::Permit>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let Some(installed) = state.meta.as_mut() else {
        // SAFETY: initialize only fixed-size metadata, never a schema-sized tuple.
        unsafe {
            stable::install::<Meta<T::Field, A::Permit>, A>(
                &mut state.meta,
                &mut state.admitted,
                const { stable::Metadata::whole::<Meta<T::Field, A::Permit>, A::Permit>() },
                |meta| {
                    meta.write(Meta {
                        next: index,
                        end: 0,
                        low: 0,
                        high: 0,
                        children: Stack::new(),
                    })
                },
                a,
            )?
        };
        return Ok(Built::Progress);
    };
    let meta = installed.get();
    match state.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            if let Some(expected) = T::TAG {
                let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
                match node.kind() {
                    Kind::Tagged(found) if found == expected => {
                        meta.next = meta.next.checked_add(1).ok_or(BoundedError::Overflow)?;
                    }
                    Kind::Tagged(found) => {
                        return Err(crate::bounded::decode::DecodeError::Invalid(
                            crate::Error::WrongTag(
                                crate::Tag::with_value(expected),
                                crate::Tag::with_value(found),
                            ),
                        ));
                    }
                    _ => return Err(wrong_type()),
                }
            }
            state.phase = Phase::Map;
        }
        Phase::Map => {
            STEP.admit(a)?;
            if T::POSITIONAL {
                state.phase = Phase::Find;
                return Ok(Built::Progress);
            }
            let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
            if !matches!(node.kind(), Kind::Map(_)) {
                return Err(wrong_type());
            }
            meta.next = meta.next.checked_add(1).ok_or(BoundedError::Overflow)?;
            meta.end = super::super::next_index(node);
            state.phase = Phase::Find;
        }
        Phase::Find => {
            STEP.admit(a)?;
            if T::POSITIONAL {
                if state.position == T::COUNT {
                    state.phase = Phase::Complete;
                    return Ok(Built::Done);
                }
                // The element is located in this admitted unit, so the build
                // of the field never inspects the document before admission.
                node_at(document, meta.next).ok_or_else(wrong_type)?;
                meta.low = field_index(state.position)?;
                state.phase = Phase::Allocate;
                return Ok(Built::Progress);
            }
            if meta.next == meta.end {
                if state.position != T::COUNT {
                    meta.low = field_index(T::COUNT)?;
                    state.phase = Phase::Allocate;
                    return Ok(Built::Progress);
                }
                state.phase = Phase::Complete;
                return Ok(Built::Done);
            }
            meta.low = 0;
            meta.high = field_index(T::COUNT)?;
            state.phase = Phase::Search;
        }
        Phase::Search => {
            STEP.admit(a)?;
            let node = node_at(document, meta.next).ok_or_else(wrong_type)?;
            if let Kind::Unsigned(key) = node.kind()
                && meta.low < meta.high
            {
                let mid = meta.low + (meta.high - meta.low) / 2;
                match key.cmp(&T::key(mid as usize)) {
                    core::cmp::Ordering::Less => meta.high = mid,
                    core::cmp::Ordering::Greater => meta.low = mid + 1,
                    core::cmp::Ordering::Equal => {
                        if (mid as usize) < state.position {
                            return Err(BoundedError::PlanMismatch.into());
                        }
                        meta.low = mid;
                        state.phase = Phase::Allocate;
                    }
                }
                return Ok(Built::Progress);
            }
            let value = node_at(document, super::super::next_index(node)).ok_or_else(wrong_type)?;
            meta.next = super::super::next_index(value);
            state.phase = Phase::Find;
        }
        Phase::Allocate => {
            let low = meta.low as usize;
            let missing = state.position < low;
            let field = if missing { state.position } else { low };
            if missing && !T::optional(field) {
                STEP.admit(a)?;
                return Err(crate::bounded::decode::DecodeError::Invalid(
                    crate::Error::MissingMapKey,
                ));
            }
            // Custody is registered, holding the field's initial state, before
            // any field constructor runs.
            let start = T::start(field).ok_or(BoundedError::PlanMismatch)?;
            meta.children.push(start, a)?;
            state.phase = if missing {
                Phase::Missing
            } else {
                Phase::Build
            };
        }
        Phase::Missing => {
            let child = meta.children.top().ok_or(BoundedError::PlanMismatch)?;
            if unsafe { T::missing_field(place, &mut child.state, a)? } == Built::Done {
                state.phase = Phase::AdvanceMissing;
            }
        }
        Phase::AdvanceMissing => {
            STEP.admit(a)?;
            state.position = state
                .position
                .checked_add(1)
                .ok_or(BoundedError::Overflow)?;
            state.phase = if state.position == T::COUNT {
                Phase::Find
            } else {
                Phase::Allocate
            };
        }
        Phase::Build => {
            // Find or Search located this node in an admitted unit.
            let key = node_at(document, meta.next).ok_or(BoundedError::PlanMismatch)?;
            // Allocate pushed the active child; its exact projection and
            // state remain unchanged throughout suspension and cleanup.
            let child = meta.children.top().ok_or(BoundedError::PlanMismatch)?;
            if unsafe {
                T::build_field(
                    document,
                    if T::POSITIONAL {
                        meta.next
                    } else {
                        super::super::next_index(key)
                    },
                    place,
                    &mut child.state,
                    a,
                )?
            } == Built::Done
            {
                state.phase = Phase::Advance;
            }
        }
        Phase::Advance => {
            STEP.admit(a)?;
            let key = node_at(document, meta.next).ok_or_else(wrong_type)?;
            let value = if T::POSITIONAL {
                key
            } else {
                node_at(document, super::super::next_index(key)).ok_or_else(wrong_type)?
            };
            meta.next = super::super::next_index(value);
            state.position = state
                .position
                .checked_add(1)
                .ok_or(BoundedError::Overflow)?;
            state.phase = Phase::Find;
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}

/// # Safety
/// Root and state must come from build, and all external value borrows must end.
pub unsafe fn reclaim<T: Fields<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Field, A::Permit>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
    match state.phase {
        Phase::Reclaim => {
            let Some(child) = meta.children.top() else {
                // SAFETY: every field record has completed cleanup and been
                // freed. The metadata's release was paid for by its
                // installation.
                unsafe { stable::uninstall(&mut state.meta) };
                return Ok(Reclaimed::Done);
            };
            // The top record retains either an initialized or a partial
            // field. Once it is reclaimed completely its record is freed in
            // the same step, a release its push paid for.
            if unsafe { T::reclaim_field(place, &mut child.state, a)? } == Reclaimed::Done {
                meta.children.pop();
            }
        }
        _ => {
            STEP.admit(a)?;
            state.phase = Phase::Reclaim;
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from `state`: no metadata, one; in
/// `Reclaim`, every field record's own calls, then the metadata's release;
/// before it, one more to enter `Reclaim`.
///
/// # Safety
/// As [`reclaim`].
pub unsafe fn remaining<T: Fields<A>, A: Allocator>(
    place: NonNull<MaybeUninit<T>>,
    state: &mut State<T::Field, A::Permit>,
) -> u64 {
    let Some(installed) = state.meta.as_mut() else {
        return 1;
    };
    let mut drain = 0u64;
    installed.get().children.for_each(|child| {
        // SAFETY: each record's state names its own field, which the
        // callback projects from the root.
        drain = drain.saturating_add(unsafe { T::remaining_field(place, child) });
    });
    let reclaiming = drain.saturating_add(1);
    match state.phase {
        Phase::Reclaim => reclaiming,
        _ => reclaiming.saturating_add(1),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::text::BufferState;
    use super::*;
    use crate::bounded::Reservation;
    use crate::bounded::decode::construction::Written;

    fn layouts<F, P>() {
        let _ = const { stable::Metadata::whole::<Meta<F, P>, P>() };
        let _ = const { stable::Metadata::whole::<stable::Child<State<F, P>, P>, P>() };
        let bound = const { cost::<F, P>(false, &[ConstructionCost::ZERO]) };
        assert!(bound.bound::<()>(1).is_ok());
    }

    #[test]
    fn metadata_and_nested_field_records_fit_at_the_permit_boundary() {
        layouts::<Written, Reservation>();
        layouts::<BufferState<Reservation>, Reservation>();
        layouts::<State<Written, Reservation>, Reservation>();
        layouts::<Written, [u8; 16]>();
        layouts::<Written, u128>();
        layouts::<State<Written, u128>, u128>();
    }
}
