//! Retained required-field map construction for generated structs.
use super::*;
use crate::bounded::boundary::{Predicate, boundary, position};
use crate::bounded::decode::construction::reclamation::Custody;
use crate::bounded::decode::construction::stable::{self, Installed, Stack, Ticket};
use crate::sync::{Atomics, Representation};

/// Compiler-generated field projections, indexed by ascending integer wire key.
///
/// Each callback receives a [`Slot`] of the record's root place and one
/// field's state, which names the field it belongs to, construction within a
/// [`Context`] of that slot projected from the record's: a caller holding
/// one has nothing to promise. Each field is a part of the record, stepped
/// through the engine's part entries ([`build_part`], [`build_part_present`],
/// [`build_part_absent`], [`reclaim_part`], [`remaining_part`]).
///
/// # Safety
/// An implementation keeps six obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation). Non-payload enum tags are initialized
/// separately by the enum engine.
///
/// - *keys*: keys are unique and strictly increasing.
/// - *count*: every payload field occurs exactly once; COUNT equals the
///   payload field count.
/// - *layout*: projections use the actual aligned struct layout.
/// - *start*: [`Self::start`] returns, for each field index below COUNT, a
///   [`Self::Field`] naming that field and holding its type's
///   [`Reclaim::INITIAL`] state, and neither allocates nor unwinds.
/// - *delegation*: each field callback delegates to the field its state
///   names, with that field's InPlace/Reclaim implementation, the state it
///   carries, and the field's place projected from the record's
///   ([`Slot::child`]) by one expression shared by construction, cleanup and
///   the count.
/// - *order*: each callback is sound for every call, in any order, as its
///   field's own methods are.
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
    /// Initializes only the field the context's state names, which is
    /// omitted, and retains its cleanup state; the context's node is the
    /// record's.
    fn missing_field(
        ctx: Context<'_, '_, '_, '_, Self, Self::Field, A>,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// One unit of construction of the field the context's state names,
    /// from the context's node, the field's value.
    fn build_field(
        ctx: Context<'_, '_, '_, '_, Self, Self::Field, A>,
        a: &mut A,
    ) -> ConstructResult<Built, A>;
    /// One unit of cleanup of the field the slot's state names, under the
    /// record's cleanup capability ([`Cleanup`]).
    fn reclaim_field(
        slot: Slot<'_, Self, Self::Field>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A>;
    /// The calls [`Self::reclaim_field`] still takes from the slot's state:
    /// the [`Reclaim::remaining`] of the field it names, at that field's
    /// place, with its own state; `None` when it does not fit in `u64`.
    fn remaining_field(slot: PeekSlot<'_, Self, Self::Field>) -> Option<u64>;
    /// The permits the field the slot's state names owns, reported inside
    /// the caller's open group: its [`Reclaim::observe_permits`]
    /// ([`observe_part`]), at that field's place, with its own state,
    /// projected as for [`Self::remaining_field`].
    fn observe_field(
        slot: PeekSlot<'_, Self, Self::Field>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved;
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

impl<F, P> Representation for Meta<F, P> {
    type In<S: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds, its whole value
/// written with the permit ([`stable::Contract`]): the one definition its
/// installation and the record's cost read.
const fn contract<F, P>() -> stable::Contract<Meta<F, P>, Meta<F, P>, P> {
    stable::Contract::of()
}

/// The construction state of a field map whose fields' states are `F`, with
/// permits of `P`: its metadata, once installed; the ticket of that
/// installation's acquisition while it is pending ([`Ticket`]), whose credit
/// is the operation's; its phase; and the fields completed, in key order.
/// Only the field engine reads or changes it; outside code can only start
/// one.
pub struct State<F, P> {
    meta: Option<Installed<Meta<F, P>, P>>,
    ticket: Option<Ticket>,
    // Control belongs to the continuation, including before installation and
    // after release. Keeping it here also avoids an aligned word in Meta's
    // single-quantum initialization.
    phase: Phase,
    /// The fields completed, at most the schema's field count, which the
    /// field indices already hold as `u32` ([`field_index`] refuses a count
    /// past it): a `u32` too. So the state is 24 bytes, two words, the
    /// count and the phase, and a derived enum's metadata, which holds one
    /// variant's field state beside its own phase, index and permit, stays
    /// within one quantum (`enumeration::Meta`).
    position: u32,
}

impl<F, P> State<F, P> {
    /// Nothing installed, nothing completed.
    pub const INITIAL: Self = Self {
        meta: None,
        ticket: None,
        phase: Phase::Inspect,
        position: 0,
    };
}

// SAFETY: the state exclusively owns its metadata block, which holds the
// field records (each an `F`), their permits and plain indices, as the auto
// traits would derive through `Installed` and `Stack`; stated once here so a
// nested record's proof is one obligation per level.
unsafe impl<F: Send, P: Send> Send for State<F, P> {}

/// What a field map's construction holds: no metadata block, or the block,
/// holding the field records. Progress alone: an acquisition bound for the
/// block or the next record is the root pending's custody, reported by its
/// observation (`CustodySink::bound`), never by this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldsObservation<F> {
    Unallocated,
    Held(FieldsCustody<F>),
}

/// A field map's custody once its metadata is held, `F` a field's
/// observation: the phase; the fields completed, in key order; the document
/// positions searched and the key range; the field records held; and the
/// newest record's field, the one under construction or cleanup whenever
/// one is, whole. Every record before the newest holds a complete field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldsCustody<F> {
    pub phase: Phase,
    pub completed: usize,
    pub next: usize,
    pub end: usize,
    pub low: u32,
    pub high: u32,
    pub records: usize,
    pub newest: Option<F>,
}

impl<F: Custody, P> Custody for State<F, P> {
    type Observation = FieldsObservation<F::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(installed) = self.meta.as_mut() else {
            return FieldsObservation::Unallocated;
        };
        let meta = installed.get();
        FieldsObservation::Held(FieldsCustody {
            phase: self.phase,
            completed: self.position as usize,
            next: meta.next,
            end: meta.end,
            low: meta.low,
            high: meta.high,
            records: meta.children.len(),
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
/// [`entries`]. None when a quantity does not fit in `u64`.
pub const fn cost<F, P>(positional: bool, fields: &[ConstructionCost]) -> Option<ConstructionCost> {
    let meta = contract::<F, P>();
    let child = Stack::<F, P>::RECORD;
    let release = stable::release_cost::<P>();
    // The metadata installed; the tag, map and last find steps; cleanup's
    // transition step; the metadata released.
    let installed = cost!(meta.write().checked_add(cost!(STEP_COST.checked_mul(4))));
    let mut fixed = cost!(installed.checked_add(cost!(release.checked_add(held(meta.block())))));
    let mut per_byte = ConstructionCost::ZERO.per_byte;
    let mut index = 0;
    while index < fields.len() {
        // The custody record pushed, the advance step, the record popped.
        let record = cost!(cost!(child.write().checked_add(STEP_COST)).checked_add(release));
        let own = cost!(fields[index].fixed.checked_add(ROUNDING));
        let each = cost!(record.checked_add(cost!(held(child.block()).checked_add(own))));
        fixed = cost!(fixed.checked_add(each));
        if positional {
            fixed = cost!(fixed.checked_add(STEP_COST));
        }
        per_byte = per_byte.larger(fields[index].per_byte);
        index += 1;
    }
    let cost = ConstructionCost { fixed, per_byte };
    if positional {
        Some(cost)
    } else {
        cost.checked_add(cost!(entries(fields.len())))
    }
}

/// One keyed entry's units in a record of `count` fields: its find, at most
/// `floor(log2 count) + 1` search steps, and one to locate or skip its
/// value. An unknown key below every field's takes exactly this many: the
/// search halves toward the first field at every step. None when a quantity
/// does not fit in `u64`.
pub const fn entry(count: usize) -> Option<ResourceBound> {
    let search = if count == 0 {
        0
    } else {
        count.ilog2() as u64 + 1
    };
    STEP_COST.checked_mul(search + 2)
}

/// The keyed entries of a record of `count` fields, by the record's bytes:
/// each entry has a key and a value of a byte at least, so one [`entry`]
/// per two bytes, half a unit of each per byte. None when a quantity does
/// not fit in `u64`.
pub const fn entries(count: usize) -> Option<ConstructionCost> {
    Some(ConstructionCost {
        fixed: ConstructionCost::ZERO.fixed,
        per_byte: cost!(cost!(entry(count)).checked_mul(PER_BYTE_SCALE / 2)),
    })
}

/// The newest field record's context, projected from the record's: the
/// record's own place and the state the record holds for its newest field,
/// in this record's metadata. Refused when no metadata or record is held.
///
/// # Safety
/// The newest record holds the state of the field being built or written,
/// started for it by [`Fields::start`]: the record's place and that state
/// are the field's slot as its callbacks project it.
unsafe fn newest<'b, 'c, 'x, 'a, T: Fields<A>, A: Allocator>(
    ctx: &'x mut Context<'b, 'c, '_, 'a, T, State<T::Field, A::Permit>, A>,
    index: usize,
) -> BoundedResult<Context<'b, 'c, 'x, 'a, T, T::Field, A>, A> {
    // SAFETY: forwarded from the caller.
    unsafe {
        ctx.part(index, |slot| {
            let (place, state) = slot.into_parts();
            let meta = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?.get();
            let child = meta.children.top().ok_or(BoundedError::PlanMismatch)?;
            Ok(Slot::new(place, &mut child.state))
        })
    }
}

/// One unit of construction of the record in the context's slot, from the
/// context's node. Without metadata the state is `INITIAL` (every cleanup
/// that releases the metadata restores it), so construction begins; any
/// phase past construction is refused.
///
/// Each field is a part of the record. Its node is recomputed from
/// `meta.next`, the record's one record of which entry it is at: set past
/// the tag and map heads, moved by `Search` only past an unknown key, and
/// past a field's value only in `Advance`, after the field reports `Done`; a
/// refused or erroring field leaves it, the phase and the field's record
/// unchanged. A field is built (`Build`, [`Fields::build_field`]) exactly
/// when `Allocate` found its key in the map (`low` reached by `Search`), and
/// written absent (`Missing`, [`Fields::missing_field`]) exactly when it did
/// not (`position < low`). No field is built once cleanup began: cleanup's
/// first unit moves the phase to `Reclaim` ([`reclaim`]), which this
/// function's last arm refuses, nothing changed. A record reclaimed to its
/// end is `INITIAL` again, which a build would restart: only its owner's
/// phase (a parent's cleanup phase, or the root's released session) keeps it
/// from being built again.
pub fn build<'b, T: Fields<A>, A: Allocator>(
    ctx: Context<'b, '_, '_, '_, T, State<T::Field, A::Permit>, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, T>, A> {
    let mut ctx = ctx;
    let assembly = ctx.assembly();
    let index = ctx.index();
    let nodes = ctx.nodes();
    let (mut slot, pending) = ctx.acquiring();
    let state = slot.custody();
    let Some(installed) = state.meta.as_mut() else {
        if state.phase != Phase::Inspect || state.position != 0 {
            return Err(BoundedError::PlanMismatch.into());
        }
        // SAFETY: the header is the whole fixed-size metadata, never a
        // schema-sized tuple, every field written.
        unsafe {
            stable::install::<Meta<T::Field, A::Permit>, Meta<T::Field, A::Permit>, A>(
                const { contract::<T::Field, A::Permit>() },
                &mut state.meta,
                pending,
                &mut state.ticket,
                || Meta {
                    next: index,
                    end: 0,
                    low: 0,
                    high: 0,
                    children: Stack::new(),
                },
                |meta| meta,
                a,
            )?
        };
        return Ok(Building::Progress);
    };
    let meta = installed.get();
    match state.phase {
        Phase::Inspect => {
            STEP.admit(a)?;
            if let Some(expected) = T::TAG {
                let node = nodes.node(meta.next).ok_or_else(wrong_type)?;
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
                return Ok(Building::Progress);
            }
            let node = nodes.node(meta.next).ok_or_else(wrong_type)?;
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
                if state.position as usize == T::COUNT {
                    state.phase = Phase::Complete;
                    // SAFETY: as for the keyed record below.
                    return Ok(Building::Done(unsafe { assembly.assemble() }));
                }
                // The element is located in this admitted unit, so the build
                // of the field never inspects the document before admission.
                nodes.node(meta.next).ok_or_else(wrong_type)?;
                meta.low = state.position;
                state.phase = Phase::Allocate;
                return Ok(Building::Progress);
            }
            if meta.next == meta.end {
                if state.position as usize != T::COUNT {
                    meta.low = field_index(T::COUNT)?;
                    state.phase = Phase::Allocate;
                    return Ok(Building::Progress);
                }
                state.phase = Phase::Complete;
                // SAFETY: `position` counts the fields completed in key
                // order, and it reaches `COUNT` only through `Advance` or
                // `AdvanceMissing`. Each of those follows a `Done` whose
                // record, confined by its brand to the step that minted it,
                // the engine's part entry verified against the field place
                // this record projected for that field (`build_field` and
                // `missing_field` delegate to `build_part`,
                // `build_part_present` or `build_part_absent`).
                // So every payload field is initialized, `Fields` lists each
                // exactly once, and the slot is not reclaimed: cleanup moves
                // the phase to `Reclaim`, which this function refuses.
                return Ok(Building::Done(unsafe { assembly.assemble() }));
            }
            meta.low = 0;
            meta.high = field_index(T::COUNT)?;
            state.phase = Phase::Search;
        }
        Phase::Search => {
            STEP.admit(a)?;
            let node = nodes.node(meta.next).ok_or_else(wrong_type)?;
            if let Kind::Unsigned(key) = node.kind()
                && boundary!(a, Predicate::Field, meta.low, meta.high).is_lt()
            {
                let mid = meta.low + (meta.high - meta.low) / 2;
                match key.cmp(&T::key(mid as usize)) {
                    core::cmp::Ordering::Less => meta.high = mid,
                    core::cmp::Ordering::Greater => meta.low = mid + 1,
                    core::cmp::Ordering::Equal => {
                        if boundary!(a, Predicate::Field, mid as usize, state.position as usize)
                            .is_lt()
                        {
                            return Err(BoundedError::PlanMismatch.into());
                        }
                        meta.low = mid;
                        state.phase = Phase::Allocate;
                    }
                }
                return Ok(Building::Progress);
            }
            let value = nodes
                .node(super::super::next_index(node))
                .ok_or_else(wrong_type)?;
            meta.next = super::super::next_index(value);
            state.phase = Phase::Find;
        }
        Phase::Allocate => {
            let low = meta.low as usize;
            let completed = state.position as usize;
            let missing = boundary!(a, Predicate::Field, completed, low).is_lt();
            let field = if missing { completed } else { low };
            boundary!(a, Predicate::Field => position(field, T::COUNT));
            if missing && !T::optional(field) {
                STEP.admit(a)?;
                return Err(crate::bounded::decode::DecodeError::Invalid(
                    crate::Error::MissingMapKey,
                ));
            }
            // Custody is registered, holding the field's initial state, before
            // any field constructor runs.
            let start = T::start(field).ok_or(BoundedError::PlanMismatch)?;
            meta.children.push(start, pending, a)?;
            state.phase = if missing {
                Phase::Missing
            } else {
                Phase::Build
            };
        }
        Phase::Missing => {
            // SAFETY: Allocate pushed the omitted field's record, started for
            // it by `T::start`, and it is the newest.
            let field = unsafe { newest::<T, A>(&mut ctx, index) }?;
            if T::missing_field(field, a)? == Built::Done {
                ctx.slot().custody().phase = Phase::AdvanceMissing;
            }
        }
        Phase::AdvanceMissing => {
            STEP.admit(a)?;
            state.position = state
                .position
                .checked_add(1)
                .ok_or(BoundedError::Overflow)?;
            state.phase = if state.position as usize == T::COUNT {
                Phase::Find
            } else {
                Phase::Allocate
            };
        }
        Phase::Build => {
            // Find or Search located this node in an admitted unit.
            let key = nodes.node(meta.next).ok_or(BoundedError::PlanMismatch)?;
            let value = if T::POSITIONAL {
                meta.next
            } else {
                super::super::next_index(key)
            };
            // SAFETY: Allocate pushed the active field's record, started for
            // it by `T::start`, and it is the newest; its exact projection
            // and state remain unchanged throughout suspension and cleanup.
            let field = unsafe { newest::<T, A>(&mut ctx, value) }?;
            if T::build_field(field, a)? == Built::Done {
                ctx.slot().custody().phase = Phase::Advance;
            }
        }
        Phase::Advance => {
            STEP.admit(a)?;
            let key = nodes.node(meta.next).ok_or_else(wrong_type)?;
            let value = if T::POSITIONAL {
                key
            } else {
                nodes
                    .node(super::super::next_index(key))
                    .ok_or_else(wrong_type)?
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
    Ok(Building::Progress)
}

/// One unit of construction of an enum's selected variant payload, `T` the
/// variant's field record, in the context the enum projected for that
/// payload ([`super::enumeration::Variants::build_variant`]): the record's
/// step ([`build`]), its `Done` record, confined by its brand to this step,
/// verified against the payload place this context holds and consumed here
/// (`verified`). The check runs here, inside the crate: the generated
/// callback that calls this serves every variant of its enum, so its
/// signature cannot carry a variant's record. The enum advances its phase
/// only on the `Built::Done` this returns.
pub fn build_payload<T: Fields<A>, A: Allocator>(
    ctx: Context<'_, '_, '_, '_, T, State<T::Field, A::Permit>, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let expected = ctx.assembly();
    Ok(super::verified::<T, A::Refusal>(build(ctx, a)?, expected)?)
}

/// One unit of cleanup of the record in `slot`. The slot's custody excludes
/// every borrow of the value. Releasing the metadata restores `INITIAL`, so
/// a later step reports `Done` and a later build begins anew.
pub fn reclaim<T: Fields<A>, A: Allocator>(
    mut slot: Slot<'_, T, State<T::Field, A::Permit>>,
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
    match state.phase {
        Phase::Reclaim => {
            let Some(child) = meta.children.top() else {
                // SAFETY: every field record has completed cleanup and been
                // freed. The metadata's release was paid for by its
                // installation.
                unsafe { stable::uninstall(&mut state.meta) };
                state.phase = Phase::Inspect;
                state.position = 0;
                return Ok(Reclaimed::Done);
            };
            // The top record retains either an initialized or a partial
            // field. Once it is reclaimed completely its record is freed in
            // the same step, a release its push paid for.
            // SAFETY: the record's root place, and the state of the field its
            // record names.
            let field = unsafe { Slot::new(place, &mut child.state) };
            if T::reclaim_field(field, a)? == Reclaimed::Done {
                meta.children.pop();
            }
        }
        _ => {
            STEP.admit(a)?;
            // A field record's acquisition, if pending, had its credit
            // settled at the operation's cleanup entry: the ticket is
            // forgotten.
            meta.children.abandon();
            state.phase = Phase::Reclaim;
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls [`reclaim`] still takes from the slot's state: no metadata, one;
/// in `Reclaim`, every field record's own calls, then the metadata's release;
/// before it, one more to enter `Reclaim`. `None` when the count does not
/// fit in `u64`.
pub fn remaining<T: Fields<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Field, A::Permit>>,
) -> Option<u64> {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return Some(1);
    };
    let mut drain = Some(0u64);
    installed.get().children.for_each(|child| {
        // SAFETY: each record's state names its own field, which the
        // callback projects from the root.
        let field = T::remaining_field(unsafe { Slot::new(place, child) });
        drain = drain.and_then(|drain| drain.checked_add(field?));
    });
    let reclaiming = drain?.checked_add(1)?;
    match state.phase {
        Phase::Reclaim => Some(reclaiming),
        _ => reclaiming.checked_add(1),
    }
}

/// The permits the record in `slot` owns, reported inside the caller's open
/// group: its metadata block's, then, newest first, each field record's
/// block and the field's own ([`Fields::observe_field`]); none without
/// metadata.
pub fn observe_permits<T: Fields<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, State<T::Field, A::Permit>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    let (place, state) = slot.parts();
    let Some(installed) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    sink.permit(installed.permit(), None);
    let mut whole = PermitsObserved::Complete;
    installed.get().children.for_each_record(|permit, child| {
        sink.permit(permit, None);
        // SAFETY: each record's state names its own field, which the
        // callback projects from the root.
        let field = T::observe_field(unsafe { Slot::new(place, child) }, sink);
        whole = observed_all([whole, field]);
    });
    whole
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::super::text::BufferState;
    use super::*;
    use crate::bounded::Reservation;
    use crate::bounded::decode::construction::Written;

    fn layouts<F, P>() {
        let _ = const { contract::<F, P>() };
        let _ = const { Stack::<State<F, P>, P>::RECORD };
        let bound = crate::const_cost!(cost::<F, P>(false, &[ConstructionCost::ZERO]));
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

    /// A record's cost, evaluated at run time as the derive evaluates it in
    /// constants: every field, present or omitted, adds the same fixed part
    /// (its custody record pushed, held and released, its advance, its own
    /// fixed cost and a rounding unit); positional fields are found by one
    /// step each where keyed ones are paid as entries per byte; and the
    /// fields' per-byte parts do not add, their subtrees partitioning the
    /// record's bytes, so the record takes the largest.
    #[test]
    fn a_records_cost_adds_each_fields_fixed_part_and_the_largest_per_byte_part() {
        let field = ConstructionCost::fixed(unit(4))
            .checked_add(ConstructionCost::checked_per_byte(unit(1)).unwrap())
            .unwrap();
        let entries = |count: usize| entries(count).unwrap();
        let keyed =
            |fields: &[ConstructionCost]| cost::<Written, Reservation>(false, fields).unwrap();
        let positional =
            |fields: &[ConstructionCost]| cost::<Written, Reservation>(true, fields).unwrap();
        let (none, one, two) = (keyed(&[]), keyed(&[field]), keyed(&[field, field]));
        let each = Stack::<Written, Reservation>::RECORD.write().values
            + STEP_COST.values
            + stable::release_cost::<Reservation>().values
            + field.fixed.values
            + ROUNDING.values;
        assert_eq!(one.fixed.values - none.fixed.values, each);
        assert_eq!(two.fixed.values - one.fixed.values, each);
        assert_eq!(none.per_byte, entries(0).per_byte);
        assert_eq!(
            Some(one.per_byte),
            field.per_byte.checked_add(entries(1).per_byte)
        );
        assert_eq!(
            Some(two.per_byte),
            field.per_byte.checked_add(entries(2).per_byte),
            "two fields' per-byte parts are the larger, not the sum"
        );
        assert_eq!(
            cost::<Written, Reservation>(
                false,
                &[ConstructionCost::fixed(ResourceBound {
                    values: u64::MAX,
                    ..ResourceBound::default()
                })]
            ),
            None,
            "a field whose cost leaves no room is refused, never wrapped"
        );
        let found = positional(&[field]);
        assert_eq!(
            found.fixed.values - one.fixed.values,
            STEP_COST.values,
            "a positional field is found by one step"
        );
        assert_eq!(found.per_byte, field.per_byte, "no entry is searched");
        assert_eq!(positional(&[]).per_byte, ConstructionCost::ZERO.per_byte);
    }
}
