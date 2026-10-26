//! The legal successor relations of the reducing bindings' custody
//! observations, each read from its binding's own construction and cleanup
//! steps: the byte buffer (`copy_buffer`, `reclaim_buffer`), a written
//! scalar or unit, the native option, the stable option and the tagged
//! value. A binding over a child composes its child's relations, so the
//! relation of `Option<String>` is the option's over the buffer's.
//! [`crate::legal`] checks every transition a construction and its cleanup
//! reach against them, and the cleanup that remains from every state.
//!
//! Containers (the sequence of `Vec` and arrays, the field map of derived
//! structs, the enum of derived enums, and, in its own binary, the B-tree)
//! have relations too, over what their observation carries: their own
//! phase, counts and arenas, and their newest record whole. An observation
//! that does not determine something reports `None` for it: a container
//! holding more than one record determines neither its remaining cleanup
//! nor its claims, since its older records' custody is only counted, which
//! is why containers declare no reduction.
//!
//! Every match ends in rejection: a transition is legal only by an arm that
//! names it. These limits are stated rather than hidden. A build relation
//! cannot tell a child's completing build step from its others, since no
//! measure of remaining build exists, so a parent checks those steps through
//! its child's relation alone. Transitions only a refusal reaches (an
//! acquisition's admissions advancing without its block) are legal here,
//! though [`crate::construction`] builds unrefused and never reaches them.
//! A generated field or payload state, whose initial states the schema
//! chooses per field or variant, is related only by [`opaque`]: a progress
//! step changes its observation, and nothing else is claimed of it.
use dcbor::bounded::decode::construction::in_place::enumeration::{EnumObservation, EnumPhase};
use dcbor::bounded::decode::construction::in_place::fields::{
    FieldsCustody, FieldsObservation, Phase as FieldsPhase,
};
use dcbor::bounded::decode::construction::in_place::tagged::{
    Phase as TaggedPhase, TaggedObservation,
};
use dcbor::bounded::decode::construction::in_place::{
    BufferCustody, BufferObservation, BufferPhase, ElementObservation, OptionalObservation,
    OptionalPhase, SequenceCustody, SequenceObservation, SequencePhase,
    StableOptionDecision as Decision, StableOptionObservation, StableOptionPhase,
};
use dcbor::bounded::decode::construction::reclamation::{Admitted, Written};
use dcbor::bounded::decode::storage::{StoragePosition, StorageStage};
use std::rc::Rc;

/// Whether one observation may follow another.
pub type Relation<O> = Rc<dyn Fn(&O, &O) -> bool>;

/// The admitted cleanup units that remain from a state, when its
/// observation determines them.
pub type Remaining<O> = Rc<dyn Fn(&O) -> Option<usize>>;

/// The allocations a state claims live, when its observation determines
/// them, each named by its acquisition's order among the construction's
/// granted allocation requests, 0 the first.
pub type Claims<O> = Rc<dyn Fn(&O) -> Option<Vec<usize>>>;

/// The claims of a binding over a child: its own `own` blocks, acquired
/// before anything of the child's, then the child's, each `own` later.
fn after_own<S>(own: usize, child: &Claims<S>, state: &S) -> Option<Vec<usize>> {
    Some(
        (0..own)
            .chain(child(state)?.into_iter().map(|claim| claim + own))
            .collect(),
    )
}

/// Whether a child's cleanup unit was not its last, so its parent keeps its
/// phase and record: true or false when the child's remaining units are
/// determined, either when they are not. Every container's relation, in
/// this module or a binary's own, reads its child's last unit this way.
pub fn not_last<S>(units: &Remaining<S>, child: &S, kept: bool) -> bool {
    units(child).is_none_or(|remaining| (remaining > 1) == kept)
}

/// Whether `child` is the child's initial observation, where the child's
/// relations name one.
pub fn initial<S: PartialEq>(first: &Option<S>, child: &S) -> bool {
    first.as_ref().is_none_or(|first| first == child)
}

/// One binding's relations over its observation `O`:
///
/// - `initial`: the observation of its state before anything is built, or
///   `None` for a generated state whose initial state its schema chooses;
/// - `build`: whether a build step that made progress may lead from one
///   observation to another. A step that rejects its input changes nothing,
///   which [`crate::legal`] requires separately, so no relation holds a
///   state's identity;
/// - `clean`: whether an admitted cleanup unit may lead from one
///   observation to another, the completing unit included;
/// - `remaining`: the admitted cleanup units that remain from a state, the
///   completing unit included, exact where the observation determines them,
///   since each unit's outcome is fixed by the state it starts from. A
///   parent reads its child's to tell the child's last unit, which moves the
///   parent on, from the others;
/// - `permits`: the permits a state claims live ([`Claims`]), where the
///   observation determines them: the policy's live bytes must be exactly
///   their granted bytes;
/// - `physical`: the physical allocations a state claims live, named as its
///   permits are: each is exactly its permit's bytes, so the heap
///   observer's live bytes must be exactly theirs. A freed buffer whose
///   permit is kept claims the permit but not the allocation.
///
/// A reducing binding determines all three on every state; a container
/// holding more than one record determines none.
pub struct Legality<O> {
    pub initial: Option<O>,
    pub build: Relation<O>,
    pub clean: Relation<O>,
    pub remaining: Remaining<O>,
    pub permits: Claims<O>,
    pub physical: Claims<O>,
}

/// The byte buffer of `String` and `ByteString`. Built: the metadata block
/// installed, its write and release admitted first (a refused or failed
/// allocation keeps them, so admissions only advance); the empty header
/// written; the payload's reservation and release admitted; the payload's
/// permit granted and its buffer reserved; then copies, each of at least one
/// byte, the last completing (an empty source completes copying nothing).
/// A payload permit granted whose buffer reservation then fails physically
/// leaves `AllocatePayload` holding the permit: a failed step, not progress,
/// so no build transition admits it. Cleaned: no block completes at once,
/// changing nothing; the empty or written buffer is freed, its payload
/// permit and copy count kept; the freed buffer's permit and block are
/// released, completing.
pub fn buffer() -> Legality<BufferObservation> {
    use BufferObservation::{Held, Unallocated};
    use BufferPhase::{
        AllocatePayload, BufferFreed, Complete, Copy, Empty, Initialized, ReleasePayload,
    };
    let at = |phase, held: BufferCustody| BufferCustody { phase, ..held };
    Legality {
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (Unallocated(_), after) => {
                after
                    == Held(BufferCustody {
                        phase: Empty,
                        payload: false,
                        copied: 0,
                    })
            }
            (Held(held), Held(next)) => match held.phase {
                Empty => next == at(Initialized, held),
                Initialized => next == at(ReleasePayload, held),
                ReleasePayload => next == at(AllocatePayload, held),
                AllocatePayload => {
                    !held.payload
                        && next
                            == BufferCustody {
                                phase: Copy,
                                payload: true,
                                ..held
                            }
                }
                Copy => {
                    held.payload
                        && next.payload
                        && match next.phase {
                            Copy => next.copied > held.copied,
                            Complete => next.copied >= held.copied,
                            _ => false,
                        }
                }
                Complete | BufferFreed => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (Held(held), Held(next)) => held.phase != BufferFreed && next == at(BufferFreed, held),
            (Held(held), Unallocated(next)) => {
                held.phase == BufferFreed && next == Admitted::Nothing
            }
            _ => false,
        }),
        remaining: Rc::new(|observation| {
            Some(match observation {
                Unallocated(_) => 1,
                Held(held) if held.phase == BufferFreed => 1,
                Held(_) => 2,
            })
        }),
        // The metadata block, then the payload's permit once granted.
        permits: Rc::new(|observation| {
            Some(match observation {
                Unallocated(_) => Vec::new(),
                Held(held) if held.payload => vec![0, 1],
                Held(_) => vec![0],
            })
        }),
        // The metadata block, then the payload's buffer from its reservation
        // until it is freed.
        physical: Rc::new(|observation| {
            Some(match observation {
                Unallocated(_) => Vec::new(),
                Held(held) if matches!(held.phase, Copy | Complete) => vec![0, 1],
                Held(_) => vec![0],
            })
        }),
    }
}

/// A resource-free value written in one step, a scalar or a unit: built from
/// empty to initialized; cleaned in one unit, to empty.
pub fn written() -> Legality<Written> {
    Legality {
        initial: Some(Written::Empty),
        build: Rc::new(|before, after| *before == Written::Empty && *after == Written::Initialized),
        clean: Rc::new(|_, after| *after == Written::Empty),
        remaining: Rc::new(|_| Some(1)),
        permits: Rc::new(|_| Some(Vec::new())),
        physical: Rc::new(|_| Some(Vec::new())),
    }
}

/// A native `Option` over `child`. Built: a present field marked before
/// anything else; the metadata installed, its admissions only advancing,
/// with the payload's state initial; null written as absent, or `Some`
/// written with its placeholder; the payload's own build steps, the last
/// completing the option. Cleaned: no metadata completes at once, the
/// marker and admissions reset; empty or absent reaches `Release`; the
/// payload's own cleanup units, the last reaching `Release`; the metadata's
/// release completes.
pub fn optional<S: Copy + PartialEq + 'static>(
    child: Legality<S>,
) -> Legality<OptionalObservation<S>> {
    use OptionalObservation::{Held, Unallocated};
    use OptionalPhase::{Absent, Child, Complete, Empty, Release};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    Legality {
        initial: Some(Unallocated {
            present: false,
            admitted: Admitted::Nothing,
        }),
        build: Rc::new(move |before, after| match (*before, *after) {
            (
                Unallocated {
                    present: false,
                    admitted,
                },
                Unallocated {
                    present: true,
                    admitted: next,
                },
            ) => next == admitted,
            (
                Unallocated { present, admitted },
                Unallocated {
                    present: marked,
                    admitted: next,
                },
            ) => marked == present && next > admitted,
            (
                Unallocated { present, .. },
                Held {
                    present: marked,
                    phase: Empty,
                    child,
                },
            ) => marked == present && initial(&first, &child),
            (
                Held {
                    present,
                    phase,
                    child,
                },
                Held {
                    present: marked,
                    phase: next,
                    child: grown,
                },
            ) => {
                marked == present
                    && match (phase, next) {
                        (Empty, Absent | Child) => grown == child,
                        (Child, Child | Complete) => grow(&child, &grown),
                        _ => false,
                    }
            }
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated { .. }, after) => {
                after
                    == Unallocated {
                        present: false,
                        admitted: Admitted::Nothing,
                    }
            }
            (
                Held {
                    present,
                    phase,
                    child,
                },
                Held {
                    present: marked,
                    phase: next,
                    child: reclaimed,
                },
            ) => {
                marked == present
                    && match (phase, next) {
                        (Empty | Absent, Release) => reclaimed == child,
                        // The payload's unit that is not its last keeps the
                        // phase; its last moves the option to `Release`.
                        (Child, Child) | (Complete, Complete) => {
                            not_last(&units, &child, true) && shrink(&child, &reclaimed)
                        }
                        (Child | Complete, Release) => {
                            not_last(&units, &child, false) && shrink(&child, &reclaimed)
                        }
                        _ => false,
                    }
            }
            (
                Held {
                    present,
                    phase: Release,
                    ..
                },
                after,
            ) => {
                after
                    == Unallocated {
                        present,
                        admitted: Admitted::Nothing,
                    }
            }
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(1),
            Held { phase, child, .. } => match phase {
                Empty | Absent => Some(2),
                Child | Complete => rest(child).map(|units| units + 1),
                Release => Some(1),
            },
        }),
        // The metadata block, then the payload's, which hold nothing until
        // its own construction acquires them and nothing once reclaimed.
        permits: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(Vec::new()),
            Held { child, .. } => after_own(1, &claims, child),
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(Vec::new()),
            Held { child, .. } => after_own(1, &allocations, child),
        }),
    }
}

/// A `StableOption` over `child`. Built: the null decision taken, or
/// presence; null written; the payload block installed for a present value,
/// its admissions only advancing, with the payload's state initial; the
/// payload's own build steps, the last reaching `Publish`; publication
/// writes the option. Cleaned: no block completes at once, the decision and
/// admissions reset; the payload's own cleanup units, in `Build` and
/// `Publish` alike, the last reaching `Clean`; the block's release
/// completes.
pub fn stable_option<S: Copy + PartialEq + 'static>(
    child: Legality<S>,
) -> Legality<StableOptionObservation<S>> {
    use StableOptionObservation::{Held, Unallocated};
    use StableOptionPhase::{Build, Clean, Publish};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    Legality {
        initial: Some(Unallocated {
            decision: Decision::Undecided,
            admitted: Admitted::Nothing,
        }),
        build: Rc::new(move |before, after| match (*before, *after) {
            (
                Unallocated { decision, admitted },
                Unallocated {
                    decision: next,
                    admitted: held,
                },
            ) => match (decision, next) {
                (Decision::Undecided, Decision::Present | Decision::Null)
                | (Decision::Null, Decision::Written) => held == admitted,
                (Decision::Present, Decision::Present) => held > admitted,
                _ => false,
            },
            (
                Unallocated {
                    decision: Decision::Present,
                    ..
                },
                Held {
                    decision: Decision::Present,
                    phase: Build,
                    child,
                },
            ) => initial(&first, &child),
            (
                Held {
                    decision,
                    phase,
                    child,
                },
                Held {
                    decision: next,
                    phase: reached,
                    child: grown,
                },
            ) => match (phase, reached) {
                (Build, Build | Publish) => next == decision && grow(&child, &grown),
                (Publish, Publish) => {
                    decision == Decision::Present && next == Decision::Written && grown == child
                }
                _ => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated { .. }, after) => {
                after
                    == Unallocated {
                        decision: Decision::Undecided,
                        admitted: Admitted::Nothing,
                    }
            }
            (
                Held {
                    decision,
                    phase,
                    child,
                },
                Held {
                    decision: next,
                    phase: reached,
                    child: reclaimed,
                },
            ) => {
                next == decision
                    && match (phase, reached) {
                        // The payload's unit that is not its last keeps the
                        // phase; its last moves the option to `Clean`.
                        (Build, Build) | (Publish, Publish) => {
                            not_last(&units, &child, true) && shrink(&child, &reclaimed)
                        }
                        (Build | Publish, Clean) => {
                            not_last(&units, &child, false) && shrink(&child, &reclaimed)
                        }
                        _ => false,
                    }
            }
            (
                Held {
                    decision,
                    phase: Clean,
                    ..
                },
                after,
            ) => {
                after
                    == Unallocated {
                        decision,
                        admitted: Admitted::Nothing,
                    }
            }
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(1),
            Held { phase, child, .. } => match phase {
                Build | Publish => rest(child).map(|units| units + 1),
                Clean => Some(1),
            },
        }),
        // The payload block, holding the payload in place, then the
        // payload's own allocations.
        permits: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(Vec::new()),
            Held { child, .. } => after_own(1, &claims, child),
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(Vec::new()),
            Held { child, .. } => after_own(1, &allocations, child),
        }),
    }
}

/// A tagged value over its untagged payload `child`. Built: the metadata
/// installed at the value's document index, its admissions only advancing,
/// with the payload's state initial; the tag inspected, moving to the
/// payload's index; the payload's own build steps, the last completing.
/// Cleaned: no metadata completes at once, changing nothing; an uninspected
/// tag reaches `Release`; the payload's own cleanup units, the last reaching
/// `Release`; the metadata's release completes.
pub fn tagged<U: Copy + PartialEq + 'static>(child: Legality<U>) -> Legality<TaggedObservation<U>> {
    use TaggedObservation::{Held, Unallocated};
    use TaggedPhase::{Build, Complete, Inspect, Release};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    Legality {
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (
                Unallocated(_),
                Held {
                    phase: Inspect,
                    child,
                    ..
                },
            ) => initial(&first, &child),
            (
                Held {
                    index,
                    phase,
                    child,
                },
                Held {
                    index: next,
                    phase: reached,
                    child: grown,
                },
            ) => match (phase, reached) {
                (Inspect, Build) => index.checked_add(1) == Some(next) && grown == child,
                (Build, Build | Complete) => next == index && grow(&child, &grown),
                _ => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (
                Held {
                    index,
                    phase,
                    child,
                },
                Held {
                    index: next,
                    phase: reached,
                    child: reclaimed,
                },
            ) => {
                next == index
                    && match (phase, reached) {
                        (Inspect, Release) => reclaimed == child,
                        // The payload's unit that is not its last keeps the
                        // phase; its last moves the value to `Release`.
                        (Build, Build) | (Complete, Complete) => {
                            not_last(&units, &child, true) && shrink(&child, &reclaimed)
                        }
                        (Build | Complete, Release) => {
                            not_last(&units, &child, false) && shrink(&child, &reclaimed)
                        }
                        _ => false,
                    }
            }
            (Held { phase: Release, .. }, Unallocated(next)) => next == Admitted::Nothing,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(1),
            Held { phase, child, .. } => match phase {
                Inspect => Some(2),
                Build | Complete => rest(child).map(|units| units + 1),
                Release => Some(1),
            },
        }),
        // The metadata block, then the untagged payload's allocations.
        permits: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held { child, .. } => after_own(1, &claims, child),
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held { child, .. } => after_own(1, &allocations, child),
        }),
    }
}

/// A generated field or payload state, related by its observation alone: a
/// build step that made progress changes it, and a cleanup unit is whatever
/// its own binding takes, the last one ending its record in the parent. No
/// initial observation, remaining cleanup or allocation is claimed, and no
/// cleanup transition is constrained: the relation is the weakest one the
/// observation supports, stated as such.
pub fn opaque<O: PartialEq + 'static>() -> Legality<O> {
    Legality {
        initial: None,
        build: Rc::new(|before, after| before != after),
        clean: Rc::new(|_, _| true),
        remaining: Rc::new(|_| None),
        permits: Rc::new(|_| None),
        physical: Rc::new(|_| None),
    }
}

/// Whether two arena positions hold the same elements, capacities, moves
/// remaining and permit: an arena whose stage alone changed.
fn same_arena(before: &StoragePosition, after: &StoragePosition) -> bool {
    after.initialized == before.initialized
        && after.reserved_capacity == before.reserved_capacity
        && after.physical_capacity == before.physical_capacity
        && after.relocating_remaining == before.relocating_remaining
        && after.has_current_permit == before.has_current_permit
}

/// One unit of an arena's growth, relocation or settled use
/// (`Storage::reserve_step`, `settle_step`, `Spare::push`), from `before`
/// to `after`: a free slot of a settled arena filled; admissions toward the
/// staging block only advancing, the block then staged; admissions toward
/// the grown allocation only advancing, the grown allocation then ready;
/// the relocation published, every element still in the old allocation, or
/// an empty arena settled on the grown one at once; one element relocated,
/// the last ending the relocation; the relocated arena settled, its block
/// vacated; the vacated block released. A grown allocation holds more than
/// every element and is reserved physically for at least its capacity.
pub fn storage_build(before: &StoragePosition, after: &StoragePosition) -> bool {
    use StorageStage::{Ready, Relocated, Relocating, Retired, Settled, Staged, Staging};
    let grown = after.reserved_capacity > before.initialized
        && after.physical_capacity >= after.reserved_capacity
        && after.has_current_permit
        && after.reserved_capacity > before.reserved_capacity;
    match (before.stage, after.stage) {
        (Settled, Settled) => {
            after.initialized == before.initialized + 1
                && after.initialized <= after.reserved_capacity
                && after.reserved_capacity == before.reserved_capacity
                && after.physical_capacity == before.physical_capacity
                && after.has_current_permit == before.has_current_permit
                && after.relocating_remaining == 0
        }
        (Settled, Staging(next)) => next != Admitted::Nothing && same_arena(before, after),
        (Staging(admitted), Staging(next)) => next > admitted && same_arena(before, after),
        (Settled | Staging(_), Staged(Admitted::Nothing)) => same_arena(before, after),
        (Staged(admitted), Staged(next)) => next > admitted && same_arena(before, after),
        (Staged(_), Ready) | (Relocated, Retired) | (Retired, Settled) => same_arena(before, after),
        (Ready, Relocating) => {
            before.initialized > 0
                && after.initialized == 0
                && after.relocating_remaining == before.initialized
                && grown
        }
        (Ready, Retired) => before.initialized == 0 && after.initialized == 0 && grown,
        (Relocating, Relocating) => {
            after.initialized == before.initialized + 1
                && after.relocating_remaining + 1 == before.relocating_remaining
                && after.relocating_remaining > 0
                && after.reserved_capacity == before.reserved_capacity
                && after.physical_capacity == before.physical_capacity
                && after.has_current_permit == before.has_current_permit
        }
        (Relocating, Relocated) => {
            after.initialized == before.initialized + 1
                && before.relocating_remaining == 1
                && after.relocating_remaining == 0
                && after.reserved_capacity == before.reserved_capacity
                && after.physical_capacity == before.physical_capacity
                && after.has_current_permit == before.has_current_permit
        }
        _ => false,
    }
}

/// One unit of an arena's cleanup (`Storage::reclaim_step`,
/// `reclaim_copy_step`, or a newest element popped from a settled arena),
/// from `before` to `after`: a settled element drained, or plain data
/// cleared at once; an empty settled arena's allocation and permit released;
/// a growth's admissions forfeited with the settled unit that follows; a
/// staged, ready or retired growth released; one element drained from an
/// interrupted relocation, from the grown allocation first, the last
/// ending it; one element drained from the relocated arena, and, empty,
/// the relocated arena released whole.
pub fn storage_clean(before: &StoragePosition, after: &StoragePosition) -> bool {
    use StorageStage::{Ready, Relocated, Relocating, Retired, Settled, Staged, Staging};
    let emptied = after.initialized == 0
        && after.reserved_capacity == 0
        && after.physical_capacity == 0
        && !after.has_current_permit
        && after.relocating_remaining == 0;
    let settled_unit = || {
        let drained = after.initialized + 1 == before.initialized
            && after.reserved_capacity == before.reserved_capacity
            && after.physical_capacity == before.physical_capacity
            && after.has_current_permit == before.has_current_permit;
        let cleared = before.initialized > 0
            && after.initialized == 0
            && after.reserved_capacity == before.reserved_capacity
            && after.physical_capacity == before.physical_capacity
            && after.has_current_permit == before.has_current_permit;
        // `Owned::release` releases exactly when the arena `holds()`: a
        // tracked capacity or a permit; it leaves `Owned::new()`.
        let released = before.initialized == 0
            && (before.reserved_capacity != 0 || before.has_current_permit)
            && emptied;
        drained || cleared || released
    };
    match (before.stage, after.stage) {
        (Settled, Settled) => settled_unit(),
        (Staging(_), Settled) => settled_unit() || same_arena(before, after),
        (Staged(_) | Ready | Retired, Settled) => same_arena(before, after),
        (Relocating, Relocating | Relocated) => {
            let from_grown = after.initialized + 1 == before.initialized
                && after.relocating_remaining == before.relocating_remaining;
            let from_old = before.initialized == 0
                && after.initialized == 0
                && after.relocating_remaining + 1 == before.relocating_remaining;
            (from_grown || from_old)
                && (after.stage == Relocated) == (after.relocating_remaining == 0)
                && after.reserved_capacity == before.reserved_capacity
                && after.has_current_permit == before.has_current_permit
        }
        (Relocated, Relocated) => {
            after.initialized + 1 == before.initialized
                && after.reserved_capacity == before.reserved_capacity
                && after.has_current_permit == before.has_current_permit
        }
        (Relocated, Settled) => before.initialized == 0 && emptied,
        _ => false,
    }
}

/// A sequence over its element `child`: a `Vec`'s, or, `inline`, a fixed
/// array's, whose elements are its own slots and which holds no payload.
/// Built: the metadata installed, its admissions only advancing; the array
/// inspected and the container initialized, past the array's head; for a
/// vector, the payload's reservation and release admitted, then its permit
/// granted and its buffer reserved; per element, its record pushed with the
/// element's initial state, the element's own build steps, its commit past
/// its subtree; completion once every record is committed. Cleaned: an
/// uninspected sequence is freed at once; otherwise its cleanup begins; the
/// newest element's own units, the last freeing its record and leaving the
/// prefix if it was committed, an older committed record becoming the
/// newest; the empty container released; the payload's permit and the
/// metadata released.
pub fn sequence<E: Copy + PartialEq + 'static>(
    child: Legality<E>,
    inline: bool,
) -> Legality<SequenceObservation<E>> {
    use SequenceObservation::{Held, Unallocated};
    use SequencePhase::{
        AllocatePayload, BufferFreed, Child, Commit, Complete, Empty, Initialized, Initializing,
        Next, Reclaim, ReleasePayload,
    };
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    let at = |phase, held: SequenceCustody<E>| SequenceCustody { phase, ..held };
    // The record block of the first element follows the metadata block and,
    // for a vector, the payload.
    let base = if inline { 1 } else { 2 };
    Legality {
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (Unallocated(_), Held(held)) => {
                held == SequenceCustody {
                    phase: Initializing,
                    position: 0,
                    committed: 0,
                    records: 0,
                    admitted: Admitted::Nothing,
                    payload: false,
                    newest: None,
                }
            }
            (Held(held), Held(next)) => match (held.phase, next.phase) {
                (Initializing, Empty) => next == at(Empty, held),
                (Empty, phase) => {
                    phase == if inline { Next } else { Initialized }
                        && next.position > held.position
                        && next
                            == SequenceCustody {
                                phase,
                                position: next.position,
                                ..held
                            }
                }
                (Initialized, ReleasePayload) | (ReleasePayload, AllocatePayload) => {
                    !inline && next == at(next.phase, held)
                }
                (AllocatePayload, Next) => {
                    !inline
                        && !held.payload
                        && next
                            == SequenceCustody {
                                phase: Next,
                                payload: true,
                                ..held
                            }
                }
                (Next, Complete) => held.records == held.committed && next == at(Complete, held),
                (Next, Next) => {
                    next.admitted > held.admitted
                        && next
                            == SequenceCustody {
                                admitted: next.admitted,
                                ..held
                            }
                }
                (Next, Child) => match next.newest {
                    Some(ElementObservation {
                        committed: false,
                        element,
                    }) => {
                        held.records == held.committed
                            && next.records == held.records + 1
                            && next.admitted == Admitted::Nothing
                            && initial(&first, &element)
                            && next
                                == SequenceCustody {
                                    phase: Child,
                                    records: next.records,
                                    admitted: Admitted::Nothing,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    _ => false,
                },
                (Child, Child | Commit) => match (held.newest, next.newest) {
                    (
                        Some(ElementObservation {
                            committed: false,
                            element,
                        }),
                        Some(ElementObservation {
                            committed: false,
                            element: grown,
                        }),
                    ) => {
                        grow(&element, &grown)
                            && next
                                == SequenceCustody {
                                    phase: next.phase,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    _ => false,
                },
                (Commit, Next) => match (held.newest, next.newest) {
                    (
                        Some(ElementObservation {
                            committed: false,
                            element,
                        }),
                        Some(ElementObservation {
                            committed: true,
                            element: kept,
                        }),
                    ) => {
                        kept == element
                            && next.committed == held.committed + 1
                            && next.position > held.position
                            && next
                                == SequenceCustody {
                                    phase: Next,
                                    position: next.position,
                                    committed: next.committed,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    _ => false,
                },
                _ => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (Held(held), Held(next)) => match (held.phase, next.phase) {
                (Empty, BufferFreed) => next == at(BufferFreed, held),
                (
                    Initialized | ReleasePayload | AllocatePayload | Next | Child | Commit
                    | Complete,
                    Reclaim,
                ) => next == at(Reclaim, held),
                (Reclaim, Reclaim) => match held.newest {
                    // The newest element's unit that is not its last.
                    Some(newest) if next.records == held.records => match next.newest {
                        Some(reclaimed) => {
                            reclaimed.committed == newest.committed
                                && not_last(&units, &newest.element, true)
                                && shrink(&newest.element, &reclaimed.element)
                                && next
                                    == SequenceCustody {
                                        newest: next.newest,
                                        ..held
                                    }
                        }
                        None => false,
                    },
                    // Its last: the record freed, the element leaving the
                    // prefix if committed, an older committed record newest.
                    Some(newest) if next.records + 1 == held.records => {
                        not_last(&units, &newest.element, false)
                            && next.committed + usize::from(newest.committed) == held.committed
                            && match next.newest {
                                Some(older) => older.committed && next.records > 0,
                                None => next.records == 0,
                            }
                            && next
                                == SequenceCustody {
                                    committed: next.committed,
                                    records: next.records,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    _ => false,
                },
                (Reclaim, BufferFreed) => {
                    held.records == 0 && held.committed == 0 && next == at(BufferFreed, held)
                }
                _ => false,
            },
            (Held(held), Unallocated(next)) => {
                matches!(held.phase, Initializing | BufferFreed) && next == Admitted::Nothing
            }
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(1),
            Held(held) => {
                // The transition into cleanup, before the records' units.
                let begin = usize::from(!matches!(held.phase, Reclaim | Empty | BufferFreed));
                match held.phase {
                    Initializing | BufferFreed => Some(1),
                    Empty => Some(2),
                    _ => match (held.records, held.newest) {
                        // The container's release, then its metadata's.
                        (0, _) => Some(begin + 2),
                        (1, Some(newest)) => rest(&newest.element).map(|units| begin + units + 2),
                        _ => None,
                    },
                }
            }
        }),
        // The metadata block; the payload's permit once granted; then, with
        // one record, its block and the element's own.
        permits: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held(held) => {
                let own = if held.payload { 2 } else { 1 };
                match (held.records, held.newest) {
                    (0, _) => Some((0..own).collect()),
                    (1, Some(newest)) => {
                        let mut held_claims: Vec<usize> = (0..own).collect();
                        held_claims.extend(
                            after_own(1, &claims, &newest.element)?
                                .into_iter()
                                .map(|claim| claim + base),
                        );
                        Some(held_claims)
                    }
                    _ => None,
                }
            }
        }),
        // The metadata block; a vector's buffer from its reservation until
        // the container is released; then, with one record, its block and
        // the element's own allocations.
        physical: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held(held) => {
                let buffer = held.payload && held.phase != BufferFreed;
                let own: Vec<usize> = if buffer { vec![0, 1] } else { vec![0] };
                match (held.records, held.newest) {
                    (0, _) => Some(own),
                    (1, Some(newest)) => {
                        let mut held_claims = own;
                        held_claims.extend(
                            after_own(1, &allocations, &newest.element)?
                                .into_iter()
                                .map(|claim| claim + base),
                        );
                        Some(held_claims)
                    }
                    _ => None,
                }
            }
        }),
    }
}

/// A derived struct's field map over its generated field state `child`.
/// Built: the metadata installed at the value's document index, its
/// admissions only advancing; the tag inspected, moving past it when one is
/// declared; the map inspected, moving into it and fixing its end, or, for
/// positional fields, nothing; then per entry a find, which completes, finds
/// a field, or begins a binary search, which narrows, lands on a field, or
/// skips an unknown key; a field's record pushed with its state; the field
/// built, or its absence written; the advance past it, one more field
/// completed. Cleaned: cleanup begins; the newest field's own units, the
/// last freeing its record, an older complete field becoming the newest;
/// with no record left, the metadata released.
pub fn fields<F: Copy + PartialEq + 'static>(child: Legality<F>) -> Legality<FieldsObservation<F>> {
    use FieldsObservation::{Held, Unallocated};
    use FieldsPhase::{
        Advance, AdvanceMissing, Allocate, Build, Complete, Find, Inspect, Map, Missing, Reclaim,
        Search,
    };
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    let at = |phase, held: FieldsCustody<F>| FieldsCustody { phase, ..held };
    Legality {
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (Unallocated(_), Held(held)) => {
                held == FieldsCustody {
                    phase: Inspect,
                    completed: 0,
                    next: held.next,
                    end: 0,
                    low: 0,
                    high: 0,
                    records: 0,
                    admitted: Admitted::Nothing,
                    newest: None,
                }
            }
            (Held(held), Held(next)) => match (held.phase, next.phase) {
                (Inspect, Map) => {
                    (next.next == held.next || held.next.checked_add(1) == Some(next.next))
                        && next
                            == FieldsCustody {
                                phase: Map,
                                next: next.next,
                                ..held
                            }
                }
                (Map, Find) => {
                    let positional = next == at(Find, held);
                    let keyed = held.next.checked_add(1) == Some(next.next)
                        && next.end >= next.next
                        && next
                            == FieldsCustody {
                                phase: Find,
                                next: next.next,
                                end: next.end,
                                ..held
                            };
                    positional || keyed
                }
                (Find, Complete) => next == at(Complete, held),
                (Find, Allocate) => {
                    next == FieldsCustody {
                        phase: Allocate,
                        low: next.low,
                        ..held
                    }
                }
                (Find, Search) => {
                    next.low == 0
                        && next
                            == FieldsCustody {
                                phase: Search,
                                low: 0,
                                high: next.high,
                                ..held
                            }
                }
                (Search, Search) => {
                    next.low >= held.low
                        && next.high <= held.high
                        && (next.low, next.high) != (held.low, held.high)
                        && next
                            == FieldsCustody {
                                low: next.low,
                                high: next.high,
                                ..held
                            }
                }
                (Search, Allocate) => {
                    next.low >= held.low
                        && next.low < held.high
                        && next
                            == FieldsCustody {
                                phase: Allocate,
                                low: next.low,
                                ..held
                            }
                }
                (Search, Find) => {
                    next.next > held.next
                        && next
                            == FieldsCustody {
                                phase: Find,
                                next: next.next,
                                ..held
                            }
                }
                (Allocate, Allocate) => {
                    next.admitted > held.admitted
                        && next
                            == FieldsCustody {
                                admitted: next.admitted,
                                ..held
                            }
                }
                (Allocate, Build | Missing) => match next.newest {
                    Some(field) => {
                        held.records == held.completed
                            && next.records == held.records + 1
                            && initial(&first, &field)
                            && next
                                == FieldsCustody {
                                    phase: next.phase,
                                    records: next.records,
                                    admitted: Admitted::Nothing,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    None => false,
                },
                (Missing, Missing | AdvanceMissing) | (Build, Build | Advance) => {
                    match (held.newest, next.newest) {
                        (Some(field), Some(grown)) => {
                            grow(&field, &grown)
                                && next
                                    == FieldsCustody {
                                        phase: next.phase,
                                        newest: next.newest,
                                        ..held
                                    }
                        }
                        _ => false,
                    }
                }
                (AdvanceMissing, Find | Allocate) => {
                    next == FieldsCustody {
                        phase: next.phase,
                        completed: held.completed + 1,
                        ..held
                    }
                }
                (Advance, Find) => {
                    next.next > held.next
                        && next
                            == FieldsCustody {
                                phase: Find,
                                completed: held.completed + 1,
                                next: next.next,
                                ..held
                            }
                }
                _ => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (Held(held), Held(next)) => match (held.phase, next.phase) {
                (Reclaim, Reclaim) => match held.newest {
                    // The newest field's unit that is not its last.
                    Some(field) if next.records == held.records => match next.newest {
                        Some(reclaimed) => {
                            not_last(&units, &field, true)
                                && shrink(&field, &reclaimed)
                                && next
                                    == FieldsCustody {
                                        newest: next.newest,
                                        ..held
                                    }
                        }
                        None => false,
                    },
                    // Its last: the record freed, an older complete field
                    // newest, or none left.
                    Some(field) if next.records + 1 == held.records => {
                        not_last(&units, &field, false)
                            && next.newest.is_some() == (next.records > 0)
                            && next
                                == FieldsCustody {
                                    records: next.records,
                                    newest: next.newest,
                                    ..held
                                }
                    }
                    _ => false,
                },
                (_, Reclaim) => next == at(Reclaim, held),
                _ => false,
            },
            (Held(held), Unallocated(next)) => {
                held.phase == Reclaim && held.records == 0 && next == Admitted::Nothing
            }
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(1),
            Held(held) => {
                let begin = usize::from(held.phase != Reclaim);
                match (held.records, held.newest) {
                    (0, _) => Some(begin + 1),
                    (1, Some(field)) => rest(&field).map(|units| begin + units + 1),
                    _ => None,
                }
            }
        }),
        // The metadata block, then, with one record, its block and the
        // field's own.
        permits: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held(held) => match (held.records, held.newest) {
                (0, _) => Some(vec![0]),
                (1, Some(field)) => after_own(2, &claims, &field),
                _ => None,
            },
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held(held) => match (held.records, held.newest) {
                (0, _) => Some(vec![0]),
                (1, Some(field)) => after_own(2, &allocations, &field),
                _ => None,
            },
        }),
    }
}

/// A derived enum over its generated payload state `child`. Built: the
/// metadata installed at the value's document index, its admissions only
/// advancing; the tag inspected, moving past it when one is declared; the
/// shape read, a bare discriminant at once, or an array's length, moving
/// into it; the array's discriminant read, moving past it; the selection
/// passing each variant whose descriptor differs, or selecting one with the
/// payload's initial state; the payload's own build steps, the last moving
/// to the commit; the native tag committed, completing. Cleaned: an
/// unselected enum reaches `Release`; the payload's own units, the last
/// reaching `Release`; the metadata released.
pub fn enumeration<V: Copy + PartialEq + 'static>(
    child: Legality<V>,
) -> Legality<EnumObservation<V>> {
    use EnumObservation::{Held, Unallocated};
    use EnumPhase::{Build, Commit, Complete, Discriminant, Release, Select, Shape, Tag};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    Legality {
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (Unallocated(_), Held { variant, phase, .. }) => variant == 0 && phase == Tag,
            (
                Held {
                    index,
                    variant,
                    phase,
                },
                Held {
                    index: next,
                    variant: passed,
                    phase: reached,
                },
            ) => {
                let past = index.checked_add(1) == Some(next);
                let kept = next == index && passed == variant;
                match (phase, reached) {
                    (Tag, Shape) => passed == variant && (next == index || past),
                    (Shape, Select { length: 0, .. }) => kept,
                    (Shape, Discriminant { length }) => length > 0 && passed == variant && past,
                    (Discriminant { length }, Select { length: read, .. }) => {
                        read == length && passed == variant && past
                    }
                    (
                        Select {
                            discriminant,
                            length,
                        },
                        Select {
                            discriminant: same,
                            length: read,
                        },
                    ) => {
                        same == discriminant
                            && read == length
                            && next == index
                            && variant.checked_add(1) == Some(passed)
                    }
                    (Select { .. }, Build(payload)) => kept && initial(&first, &payload),
                    (Build(payload), Build(grown) | Commit(grown)) => {
                        kept && grow(&payload, &grown)
                    }
                    (Commit(payload), Complete(written)) => kept && written == payload,
                    _ => false,
                }
            }
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (
                Held {
                    index,
                    variant,
                    phase,
                },
                Held {
                    index: next,
                    variant: passed,
                    phase: reached,
                },
            ) => {
                next == index
                    && passed == variant
                    && match (phase, reached) {
                        (Tag | Shape | Discriminant { .. } | Select { .. }, Release) => true,
                        // The payload's unit that is not its last keeps the
                        // phase; its last moves the enum to `Release`.
                        (Build(payload), Build(reclaimed))
                        | (Commit(payload), Commit(reclaimed))
                        | (Complete(payload), Complete(reclaimed)) => {
                            not_last(&units, &payload, true) && shrink(&payload, &reclaimed)
                        }
                        (Build(payload) | Commit(payload) | Complete(payload), Release) => {
                            not_last(&units, &payload, false)
                        }
                        _ => false,
                    }
            }
            (Held { phase: Release, .. }, Unallocated(next)) => next == Admitted::Nothing,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(1),
            Held { phase, .. } => match phase {
                Tag | Shape | Discriminant { .. } | Select { .. } => Some(2),
                Build(payload) | Commit(payload) | Complete(payload) => {
                    rest(payload).map(|units| units + 1)
                }
                Release => Some(1),
            },
        }),
        // The metadata block, then the selected payload's allocations.
        permits: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held { phase, .. } => match phase {
                Build(payload) | Commit(payload) | Complete(payload) => {
                    after_own(1, &claims, payload)
                }
                _ => Some(vec![0]),
            },
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Held { phase, .. } => match phase {
                Build(payload) | Commit(payload) | Complete(payload) => {
                    after_own(1, &allocations, payload)
                }
                _ => Some(vec![0]),
            },
        }),
    }
}
