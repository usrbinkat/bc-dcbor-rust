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
//! nor its claims here, since its older records' custody is only counted.
//!
//! Which bindings declare a reduction (`Reduction`) is a separate matter:
//! every scalar and unit (`Written`), the byte buffer (`String`,
//! `ByteString`), the fixed-length byte string (`FixedBytes`), the checked
//! texts (`StabilizedText`, `AsciiText`), the minimal big integer, both
//! options,
//! the tagged value, and the sequence (`Vec`, arrays) over elements of a
//! uniform complete class (`Uniform`), whose older, complete records then
//! all clean up alike, so their count is their custody
//! (`in_place/vector.rs`, `SequenceClass`; certified in
//! `owned_pipeline_matrix.rs`). The derived field map and enum, whose
//! fields differ in type, and the B-tree declare none.
//!
//! Every match ends in rejection: a transition is legal only by an arm that
//! names it. These limits are stated rather than hidden. A build relation
//! cannot tell a child's completing build step from its others, since no
//! measure of remaining build exists, so a parent checks those steps through
//! its child's relation alone. An acquisition's binding and its admitted
//! credit are the operation's custody (`stable::Pending`, reported by its
//! custody observation, `CustodySink::bound` and `held`), not the binding's
//! progress: a step that binds an acquisition and is then refused leaves the
//! observation unchanged, which [`crate::legal`] requires of every refused
//! step, so no relation here names a binding and none reads credit.
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
    BufferCustody, BufferObservation, BufferPhase, CheckedObservation, ElementObservation,
    FixedObservation, MinimalObservation, OptionalObservation, OptionalPhase, SequenceCustody,
    SequenceObservation, SequencePhase, SessionObservation, StableOptionDecision as Decision,
    StableOptionObservation, StableOptionPhase, Stage,
};
use dcbor::bounded::decode::construction::reclamation::Written;
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

/// A binding's relations at the root, under its root session
/// (`in_place::Session`): what the owned root and the standalone driver
/// build and clean up. Built: an unbound session binds its node in one unit,
/// the binding unchanged; a bound one steps its binding by the binding's own
/// relation, the node and entry kept, its last step completing the session.
/// Cleaned: an unbound session is released in one unit, the binding
/// unchanged; a bound one begins cleanup in one unit, the binding unchanged;
/// a cleaning one steps its binding by the binding's own relation, the
/// binding's last unit releasing the session. Remaining: one unbound or
/// released; the begin unit and the binding's own while bound; the binding's
/// own while cleaning. The session holds nothing, so the claims are the
/// binding's. Children are parts, related by their parents' relations, so
/// this wraps the root alone.
pub fn root<O: Copy + PartialEq + 'static>(
    binding: &Legality<O>,
) -> Legality<SessionObservation<O>> {
    let (initial, build, clean, remaining, permits, physical) = (
        binding.initial,
        Rc::clone(&binding.build),
        Rc::clone(&binding.clean),
        Rc::clone(&binding.remaining),
        Rc::clone(&binding.permits),
        Rc::clone(&binding.physical),
    );
    let units = Rc::clone(&remaining);
    Legality {
        initial: initial.map(|inner| SessionObservation {
            stage: Stage::Unbound,
            inner,
        }),
        build: Rc::new(move |before, after| match (before.stage, after.stage) {
            (Stage::Unbound, Stage::Building { .. }) => before.inner == after.inner,
            (
                Stage::Building { node, entry },
                Stage::Building {
                    node: next,
                    entry: entered,
                }
                | Stage::Built {
                    node: next,
                    entry: entered,
                },
            ) => node == next && entry == entered && build(&before.inner, &after.inner),
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (before.stage, after.stage) {
            (Stage::Unbound, Stage::Released)
            | (Stage::Building { .. } | Stage::Built { .. }, Stage::Cleaning) => {
                before.inner == after.inner
            }
            (Stage::Cleaning, Stage::Cleaning) => {
                clean(&before.inner, &after.inner) && not_last(&units, &before.inner, true)
            }
            (Stage::Cleaning, Stage::Released) => {
                clean(&before.inner, &after.inner) && not_last(&units, &before.inner, false)
            }
            _ => false,
        }),
        remaining: Rc::new(move |state| match state.stage {
            Stage::Unbound | Stage::Released => Some(1),
            Stage::Building { .. } | Stage::Built { .. } => remaining(&state.inner)?.checked_add(1),
            Stage::Cleaning => remaining(&state.inner),
        }),
        permits: Rc::new(move |state| permits(&state.inner)),
        physical: Rc::new(move |state| physical(&state.inner)),
    }
}

/// The byte buffer of `String` and `ByteString` (`in_place/text.rs`). Its
/// acquisitions' bindings and credit are the operation's custody
/// (`stable::Pending`), never its progress. Built: the metadata block
/// installed in one step, its acquisition bound, granted and ended within it
/// (a refusal after the bind leaves the progress unchanged, which its retry
/// continues). The empty header written; the payload's reservation step; the
/// payload's release admitted; the payload's permit granted and its buffer
/// reserved, the acquisition ended; then copies, each of at least one byte,
/// the last completing (an empty source completes copying nothing). A
/// payload permit granted whose buffer reservation then fails physically
/// leaves `AllocatePayload` holding the permit: a failed step, not progress,
/// so no build transition admits it. Cleaned: no block completes at once
/// (the credit settled at the operation's cleanup entry) and no other state
/// reset; the empty or written buffer is freed, its payload permit and copy
/// count kept; the freed buffer's permit and block are released,
/// completing.
pub fn buffer() -> Legality<BufferObservation> {
    use BufferObservation::{Held, Unallocated};
    use BufferPhase::{
        AllocatePayload, BufferFreed, Complete, Copy, Empty, Initialized, ReleasePayload,
    };
    let at = |phase, held: BufferCustody| BufferCustody { phase, ..held };
    Legality {
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated, after) => {
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
                // The payload's release admitted.
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
            (Unallocated, Unallocated) => true,
            (Held(held), Held(next)) => held.phase != BufferFreed && next == at(BufferFreed, held),
            (Held(held), Unallocated) => held.phase == BufferFreed,
            _ => false,
        }),
        remaining: Rc::new(|observation| {
            Some(match observation {
                Unallocated => 1,
                Held(held) if held.phase == BufferFreed => 1,
                Held(_) => 2,
            })
        }),
        // The metadata block, then the payload's permit once granted.
        permits: Rc::new(|observation| {
            Some(match observation {
                Unallocated => Vec::new(),
                Held(held) if held.payload => vec![0, 1],
                Held(_) => vec![0],
            })
        }),
        // The metadata block, then the payload's buffer from its reservation
        // until it is freed.
        physical: Rc::new(|observation| {
            Some(match observation {
                Unallocated => Vec::new(),
                Held(held) if matches!(held.phase, Copy | Complete) => vec![0, 1],
                Held(_) => vec![0],
            })
        }),
    }
}

/// A checked text (`StabilizedText`, `AsciiText`, one engine): its check,
/// then its text, a byte buffer ([`buffer`]).
/// Built: each window checked advances the bytes checked, the text's state
/// still initial; then the text's own build steps, the bytes checked fixed.
/// Cleaned: the text's own units, the bytes checked fixed. Its remaining
/// cleanup and its claims are the text's: the check holds nothing. The
/// observation does not carry the text's length, so a text step taken before
/// every byte is checked is not refused here; the binding's charge witness
/// (`reclamation_owner.rs`, `checked_text_checks_every_byte_once`) holds
/// that.
pub fn checked() -> Legality<CheckedObservation> {
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = buffer();
    let text = first.expect("a byte buffer names its initial observation");
    Legality {
        initial: Some(CheckedObservation { checked: 0, text }),
        build: Rc::new(move |before, after| {
            if before.text == text && after.text == text {
                after.checked > before.checked
            } else {
                after.checked == before.checked && grow(&before.text, &after.text)
            }
        }),
        clean: Rc::new(move |before, after| {
            after.checked == before.checked && shrink(&before.text, &after.text)
        }),
        remaining: Rc::new(move |observation| rest(&observation.text)),
        permits: Rc::new(move |observation| claims(&observation.text)),
        physical: Rc::new(move |observation| allocations(&observation.text)),
    }
}

/// A `MinimalBigInt`: its sign, then its magnitude, a byte buffer
/// ([`buffer`]). Built: the sign written, from empty to initialized, the
/// magnitude still initial; then the magnitude's own build steps, the sign
/// fixed. Cleaned: the magnitude's own units, the sign fixed (it holds
/// nothing). Its remaining cleanup and its claims are the magnitude's.
pub fn minimal_bigint() -> Legality<MinimalObservation> {
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = buffer();
    let magnitude = first.expect("a byte buffer names its initial observation");
    Legality {
        initial: Some(MinimalObservation {
            sign: Written::Empty,
            magnitude,
        }),
        build: Rc::new(move |before, after| match (before.sign, after.sign) {
            (Written::Empty, Written::Initialized) => {
                before.magnitude == magnitude && after.magnitude == magnitude
            }
            (Written::Initialized, Written::Initialized) => {
                grow(&before.magnitude, &after.magnitude)
            }
            _ => false,
        }),
        clean: Rc::new(move |before, after| {
            after.sign == before.sign && shrink(&before.magnitude, &after.magnitude)
        }),
        remaining: Rc::new(move |observation| rest(&observation.magnitude)),
        permits: Rc::new(move |observation| claims(&observation.magnitude)),
        physical: Rc::new(move |observation| allocations(&observation.magnitude)),
    }
}

/// A `FixedBytes` (`in_place/fixed_bytes.rs`): its bytes copied inline,
/// nothing acquired. Built: each copy advances the bytes copied, by at least
/// one byte unless it completes (the empty type completes copying nothing),
/// the last copy completing; nothing follows completion. Cleaned: one unit,
/// from any state, to the initial one. It holds no permit and no
/// allocation.
pub fn fixed() -> Legality<FixedObservation> {
    let initial = FixedObservation {
        copied: 0,
        complete: false,
    };
    Legality {
        initial: Some(initial),
        build: Rc::new(|before, after| {
            !before.complete
                && if after.complete {
                    after.copied >= before.copied
                } else {
                    after.copied > before.copied
                }
        }),
        clean: Rc::new(move |_, after| *after == initial),
        remaining: Rc::new(|_| Some(1)),
        permits: Rc::new(|_| Some(Vec::new())),
        physical: Rc::new(|_| Some(Vec::new())),
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
/// anything else; the metadata installed in one step, its acquisition bound,
/// granted and ended within it (a refusal after the bind leaves the progress
/// unchanged, nothing installed), with the payload's state initial; null
/// written as absent, or `Some` written with its placeholder; the payload's
/// own build steps, the last completing the option. Cleaned: no metadata
/// completes at once, the marker reset (the credit settled at the
/// operation's cleanup entry); empty or absent reaches
/// `Release`; the payload's own cleanup units, the last reaching `Release`;
/// the metadata's release completes, the marker reset with it. Every
/// completing unit leaves the initial state, so a later build starts from
/// it.
pub fn optional<S: Copy + PartialEq + 'static>(
    child: Legality<S>,
) -> Legality<OptionalObservation<S>> {
    use OptionalObservation::{Held, Unallocated};
    use OptionalPhase::{Absent, Child, Complete, Empty, Reclaim, Release};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    let unallocated = Unallocated { present: false };
    Legality {
        initial: Some(unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated { present: false }, Unallocated { present: true }) => true,
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
            (Unallocated { .. }, after) => after == unallocated,
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
                        // The payload's unit that is not its last moves the
                        // option to, or keeps it in, `Reclaim`; its last
                        // moves the option to `Release`.
                        (Child | Complete | Reclaim, Reclaim) => {
                            not_last(&units, &child, true) && shrink(&child, &reclaimed)
                        }
                        (Child | Complete | Reclaim, Release) => {
                            not_last(&units, &child, false) && shrink(&child, &reclaimed)
                        }
                        _ => false,
                    }
            }
            (Held { phase: Release, .. }, after) => after == unallocated,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(1),
            Held { phase, child, .. } => match phase {
                Empty | Absent => Some(2),
                Child | Complete | Reclaim => rest(child)?.checked_add(1),
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
/// presence; null written; the payload block installed for a present value
/// in one step, its acquisition bound, granted and ended within it (a
/// refusal after the bind leaves the progress unchanged), with the payload's
/// state initial; the payload's own build steps, the last reaching
/// `Publish`; publication writes the option. Cleaned: no block completes at
/// once, the decision reset (the credit settled at the operation's cleanup
/// entry); the payload's own cleanup units, in
/// `Build` and `Publish` alike, the last reaching `Clean`; the block's
/// release completes, the decision reset with it. Every completing unit
/// leaves the initial state, so a later build starts from it.
pub fn stable_option<S: Copy + PartialEq + 'static>(
    child: Legality<S>,
) -> Legality<StableOptionObservation<S>> {
    use StableOptionObservation::{Held, Unallocated};
    use StableOptionPhase::{Build, Clean, Publish, Reclaim};
    let Legality {
        initial: first,
        build: grow,
        clean: shrink,
        remaining: rest,
        permits: claims,
        physical: allocations,
    } = child;
    let units = Rc::clone(&rest);
    let unallocated = Unallocated {
        decision: Decision::Undecided,
    };
    Legality {
        initial: Some(unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated { decision }, Unallocated { decision: next }) => matches!(
                (decision, next),
                (Decision::Undecided, Decision::Present | Decision::Null)
                    | (Decision::Null, Decision::Written)
            ),
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
            (Unallocated { .. }, after) => after == unallocated,
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
                        // The payload's unit that is not its last moves the
                        // option to, or keeps it in, `Reclaim`; its last
                        // moves the option to `Clean`.
                        (Build | Publish | Reclaim, Reclaim) => {
                            not_last(&units, &child, true) && shrink(&child, &reclaimed)
                        }
                        (Build | Publish | Reclaim, Clean) => {
                            not_last(&units, &child, false) && shrink(&child, &reclaimed)
                        }
                        _ => false,
                    }
            }
            (Held { phase: Clean, .. }, after) => after == unallocated,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated { .. } => Some(1),
            Held { phase, child, .. } => match phase {
                Build | Publish | Reclaim => rest(child)?.checked_add(1),
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
/// installed in one step, its acquisition bound, granted and ended within
/// it (a refusal after the bind leaves the progress unchanged), with the
/// payload's state initial; the tag inspected; the payload's own build
/// steps, the last completing. The payload's node is the tag's content,
/// recomputed from the value's context at every step, so the observation
/// carries no index. Cleaned: no metadata completes at once (the credit
/// settled at the operation's cleanup entry); an
/// uninspected tag reaches `Release`; the payload's own cleanup units, the
/// last reaching `Release`; the metadata's release completes.
pub fn tagged<U: Copy + PartialEq + 'static>(child: Legality<U>) -> Legality<TaggedObservation<U>> {
    use TaggedObservation::{Held, Unallocated};
    use TaggedPhase::{Build, Complete, Inspect, Reclaim, Release};
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
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (
                Unallocated,
                Held {
                    phase: Inspect,
                    child,
                    ..
                },
            ) => initial(&first, &child),
            (
                Held { phase, child },
                Held {
                    phase: reached,
                    child: grown,
                },
            ) => match (phase, reached) {
                (Inspect, Build) => grown == child,
                (Build, Build | Complete) => grow(&child, &grown),
                _ => false,
            },
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            // The credit was settled at the operation's cleanup entry.
            (Unallocated, Unallocated) => true,
            (
                Held { phase, child },
                Held {
                    phase: reached,
                    child: reclaimed,
                },
            ) => match (phase, reached) {
                (Inspect, Release) => reclaimed == child,
                // The payload's unit that is not its last moves the value
                // to, or keeps it in, `Reclaim`; its last moves the value to
                // `Release`.
                (Build | Complete | Reclaim, Reclaim) => {
                    not_last(&units, &child, true) && shrink(&child, &reclaimed)
                }
                (Build | Complete | Reclaim, Release) => {
                    not_last(&units, &child, false) && shrink(&child, &reclaimed)
                }
                _ => false,
            },
            (Held { phase: Release, .. }, Unallocated) => true,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated => Some(1),
            Held { phase, child, .. } => match phase {
                Inspect => Some(2),
                Build | Complete | Reclaim => rest(child)?.checked_add(1),
                Release => Some(1),
            },
        }),
        // The metadata block, then the untagged payload's allocations.
        permits: Rc::new(move |observation| match observation {
            Unallocated => Some(Vec::new()),
            Held { child, .. } => after_own(1, &claims, child),
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated => Some(Vec::new()),
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

/// Whether `after` is exactly `before` with `change` applied to its counts:
/// the whole position compared, so every field `change` leaves alone must
/// be equal. The stage is taken from `after`, which the caller's match on
/// both stages has already fixed.
fn becomes(
    before: &StoragePosition,
    after: &StoragePosition,
    change: impl FnOnce(&mut StoragePosition),
) -> bool {
    let mut expected = *before;
    change(&mut expected);
    expected.stage = after.stage;
    expected == *after
}

/// One unit of an arena's growth, relocation or settled use
/// (`Storage::reserve_step`, `settle_step`, `Spare::push`), from `before`
/// to `after`, over its execution observation ([`StoragePosition`]), each
/// transition naming every field it changes and every other held equal
/// (`becomes`):
///
/// - a free slot of a settled arena filled: one more element, within the
///   reserved capacity;
/// - the staging block staged (`Settled` to `Staged`), or the vacated block
///   released (`Retired` to `Settled`), or the relocated arena settled in
///   place, its block vacated (`Relocated` to `Retired`): nothing physical
///   the snapshot counts changes;
/// - the grown allocation requested into the staged block (`Staged` to
///   `Ready`): its capacity, more than every element and reserved
///   physically for at least itself, and its permit;
/// - the relocation published (`Ready` to `Relocating`): the grown
///   allocation becomes the arena's, empty, every element still in the old
///   allocation, whose permit is now the relocating one;
/// - an empty arena settled on the grown allocation at once (`Ready` to
///   `Retired`), the old allocation released;
/// - one element relocated, the last ending the relocation and releasing
///   the old allocation's permit.
///
/// The admissions a growth holds toward its block or grown allocation are
/// its acquisition custody, which no position shows: a unit that only
/// admits leaves the position unchanged, and is no transition here; its
/// acquisition advance is the custody's to verify.
pub fn storage_build(before: &StoragePosition, after: &StoragePosition) -> bool {
    use StorageStage::{Ready, Relocated, Relocating, Retired, Settled, Staged};
    let (from, to) = (before, after);
    match (before.stage, after.stage) {
        (Settled, Settled) => {
            to.initialized <= from.reserved_capacity
                && becomes(before, after, |p| p.initialized += 1)
        }
        (Settled, Staged) | (Relocated, Retired) | (Retired, Settled) => {
            becomes(before, after, |_| {})
        }
        (Staged, Ready) => {
            to.staged_reserved_capacity > from.initialized
                && to.staged_physical_capacity >= to.staged_reserved_capacity
                && becomes(before, after, |p| {
                    p.staged_reserved_capacity = to.staged_reserved_capacity;
                    p.staged_physical_capacity = to.staged_physical_capacity;
                    p.has_staged_permit = true;
                })
        }
        (Ready, Relocating) => {
            from.initialized > 0
                && becomes(before, after, |p| {
                    p.initialized = 0;
                    p.relocating_remaining = from.initialized;
                    p.reserved_capacity = from.staged_reserved_capacity;
                    p.physical_capacity = from.staged_physical_capacity;
                    p.has_current_permit = from.has_staged_permit;
                    p.has_relocating_permit = from.has_current_permit;
                    p.staged_reserved_capacity = 0;
                    p.staged_physical_capacity = 0;
                    p.has_staged_permit = false;
                })
        }
        (Ready, Retired) => {
            from.initialized == 0
                && becomes(before, after, |p| {
                    p.reserved_capacity = from.staged_reserved_capacity;
                    p.physical_capacity = from.staged_physical_capacity;
                    p.has_current_permit = from.has_staged_permit;
                    p.staged_reserved_capacity = 0;
                    p.staged_physical_capacity = 0;
                    p.has_staged_permit = false;
                })
        }
        (Relocating, Relocating) => {
            from.relocating_remaining > 1
                && becomes(before, after, |p| {
                    p.initialized += 1;
                    p.relocating_remaining -= 1;
                })
        }
        (Relocating, Relocated) => {
            from.relocating_remaining == 1
                && becomes(before, after, |p| {
                    p.initialized += 1;
                    p.relocating_remaining = 0;
                    p.has_relocating_permit = false;
                })
        }
        _ => false,
    }
}

/// One unit of an arena's cleanup (`Storage::reclaim_step`,
/// `reclaim_copy_step`, or a newest element popped from a settled arena),
/// from `before` to `after`, over its execution observation
/// ([`StoragePosition`]), each transition naming every field it changes and
/// every other held equal (`becomes`):
///
/// - a settled element drained, or plain data cleared at once;
/// - an empty settled arena's allocation and permit released, which
///   `Owned::release` does exactly when the arena holds a tracked capacity
///   or a permit, leaving `Owned::new()`;
/// - a staged or ready growth's block released, the staged fields cleared;
///   a retired growth's vacated block released, nothing the snapshot
///   counts changing;
/// - one element drained from an interrupted relocation, from the grown
///   allocation while it holds any, otherwise from the old one, the old
///   allocation released as its last element goes;
/// - one element drained from the relocated arena, and, empty, the
///   relocated arena released whole.
///
/// A growth's held admissions settled at the cleanup's entry are its
/// acquisition custody's settlement, which no position shows.
pub fn storage_clean(before: &StoragePosition, after: &StoragePosition) -> bool {
    use StorageStage::{Ready, Relocated, Relocating, Retired, Settled, Staged};
    let from = before;
    let released = |p: &mut StoragePosition| {
        p.reserved_capacity = 0;
        p.physical_capacity = 0;
        p.has_current_permit = false;
    };
    match (before.stage, after.stage) {
        (Settled, Settled) => {
            let drained = from.initialized > 0 && becomes(before, after, |p| p.initialized -= 1);
            let cleared = from.initialized > 1 && becomes(before, after, |p| p.initialized = 0);
            let emptied = from.initialized == 0
                && (from.reserved_capacity != 0 || from.has_current_permit)
                && becomes(before, after, released);
            drained || cleared || emptied
        }
        (Staged | Ready, Settled) => becomes(before, after, |p| {
            p.staged_reserved_capacity = 0;
            p.staged_physical_capacity = 0;
            p.has_staged_permit = false;
        }),
        (Retired, Settled) => becomes(before, after, |_| {}),
        (Relocating, Relocating) => {
            let from_grown = from.initialized > 0 && becomes(before, after, |p| p.initialized -= 1);
            let from_old = from.initialized == 0
                && from.relocating_remaining > 1
                && becomes(before, after, |p| p.relocating_remaining -= 1);
            from_grown || from_old
        }
        (Relocating, Relocated) => {
            from.initialized == 0
                && from.relocating_remaining == 1
                && becomes(before, after, |p| {
                    p.relocating_remaining = 0;
                    p.has_relocating_permit = false;
                })
        }
        (Relocated, Relocated) => {
            from.initialized > 0 && becomes(before, after, |p| p.initialized -= 1)
        }
        (Relocated, Settled) => from.initialized == 0 && becomes(before, after, released),
        _ => false,
    }
}

/// A sequence over its element `child`: a `Vec`'s, or, `inline`, a fixed
/// array's, whose elements are its own slots and which holds no payload.
/// Every acquisition's binding and credit are the operation's custody,
/// never the sequence's progress. Built: the metadata installed in one step,
/// its acquisition bound, granted and ended within it (a refusal after the
/// bind leaves the progress unchanged, nothing installed); the array
/// inspected and the container initialized, past the array's head; for a
/// vector, the payload's reservation step, its release admitted, then its
/// permit granted and its buffer reserved, the acquisition ended; per
/// element, its record pushed in one step with the element's initial state
/// (a refusal after the bind leaves the progress unchanged in `Next`), the
/// element's own build steps, its commit past its subtree; completion once
/// every record is committed. Cleaned: no metadata completes at once (the
/// credit settled at the operation's cleanup entry); an uninspected sequence
/// is freed at once; otherwise its cleanup begins; the newest
/// element's own units, the last freeing its record and leaving the prefix
/// if it was committed, an older committed record becoming the newest; the
/// empty container released; the payload's permit and the metadata
/// released.
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
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated, Held(held)) => {
                held == SequenceCustody {
                    phase: Initializing,
                    position: 0,
                    committed: 0,
                    records: 0,
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
                (Initialized, ReleasePayload) => !inline && next == at(ReleasePayload, held),
                // The payload's release admitted.
                (ReleasePayload, AllocatePayload) => !inline && next == at(AllocatePayload, held),
                // The payload granted, its acquisition ended.
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
                // The record granted, its acquisition ended.
                (Next, Child) => match next.newest {
                    Some(ElementObservation {
                        committed: false,
                        element,
                    }) => {
                        held.records == held.committed
                            && next.records == held.records + 1
                            && initial(&first, &element)
                            && next
                                == SequenceCustody {
                                    phase: Child,
                                    records: next.records,
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
            // The credit was settled at the operation's cleanup entry.
            (Unallocated, Unallocated) => true,
            (Held(held), Held(next)) => match (held.phase, next.phase) {
                (Empty, BufferFreed) => next == at(BufferFreed, held),
                // Cleanup begins.
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
            (Held(held), Unallocated) => matches!(held.phase, Initializing | BufferFreed),
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated => Some(1),
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
            Unallocated => Some(Vec::new()),
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
            Unallocated => Some(Vec::new()),
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
/// Every acquisition's binding and credit are the operation's custody, never
/// the map's progress. Built: the metadata installed at the value's document
/// index in one step, its acquisition bound, granted and ended within it (a
/// refusal after the bind leaves the progress unchanged, nothing installed);
/// the tag inspected, moving past it when one is
/// declared; the map inspected, moving into it and fixing its end, or, for
/// positional fields, nothing; then per entry a find, which completes, finds
/// a field, or begins a binary search, which narrows, lands on a field, or
/// skips an unknown key; a field's record pushed in one step with its state
/// (a refusal after the bind leaves the progress unchanged in `Allocate`);
/// the field built, or its absence written; the advance past it, one more
/// field completed. Cleaned: no metadata completes at once (the credit
/// settled at the operation's cleanup entry); otherwise cleanup begins; the
/// newest
/// field's own units, the last freeing its record, an older complete field
/// becoming the newest; with no record left, the metadata released.
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
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated, Held(held)) => {
                held == FieldsCustody {
                    phase: Inspect,
                    completed: 0,
                    next: held.next,
                    end: 0,
                    low: 0,
                    high: 0,
                    records: 0,
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
                // The record granted, its acquisition ended.
                (Allocate, Build | Missing) => match next.newest {
                    Some(field) => {
                        held.records == held.completed
                            && next.records == held.records + 1
                            && initial(&first, &field)
                            && next
                                == FieldsCustody {
                                    phase: next.phase,
                                    records: next.records,
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
            // The credit was settled at the operation's cleanup entry.
            (Unallocated, Unallocated) => true,
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
                // Cleanup begins.
                (_, Reclaim) => next == at(Reclaim, held),
                _ => false,
            },
            (Held(held), Unallocated) => held.phase == Reclaim && held.records == 0,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated => Some(1),
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
            Unallocated => Some(Vec::new()),
            Held(held) => match (held.records, held.newest) {
                (0, _) => Some(vec![0]),
                (1, Some(field)) => after_own(2, &claims, &field),
                _ => None,
            },
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated => Some(Vec::new()),
            Held(held) => match (held.records, held.newest) {
                (0, _) => Some(vec![0]),
                (1, Some(field)) => after_own(2, &allocations, &field),
                _ => None,
            },
        }),
    }
}

/// A derived enum over its generated payload state `child`. Built: the
/// metadata installed at the value's document index in one step, its
/// acquisition bound, granted and ended within it (a refusal after the bind
/// leaves the progress unchanged, nothing installed); the tag inspected,
/// moving past it when one is declared; the shape read, a bare discriminant
/// at once, or an array's length, moving into it; the array's discriminant
/// read, moving past it; the selection passing each variant whose
/// descriptor differs, or selecting one with the payload's initial state;
/// the payload's own build steps, the last moving to the commit; the native
/// tag committed, completing. Cleaned: no metadata completes at once (the
/// credit settled at the operation's cleanup entry);
/// an unselected enum reaches `Release`; the payload's own units, the first
/// that is not its last moving the selected phase to `Reclaim` (so no build
/// reaches a payload being cleaned up), the others keeping `Reclaim`, the
/// last reaching `Release`; the metadata released.
pub fn enumeration<V: Copy + PartialEq + 'static>(
    child: Legality<V>,
) -> Legality<EnumObservation<V>> {
    use EnumObservation::{Held, Unallocated};
    use EnumPhase::{Build, Commit, Complete, Discriminant, Reclaim, Release, Select, Shape, Tag};
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
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated, Held { variant, phase, .. }) => variant == 0 && phase == Tag,
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
            // The credit was settled at the operation's cleanup entry.
            (Unallocated, Unallocated) => true,
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
                        // The payload's unit that is not its last moves the
                        // enum to, or keeps it in, `Reclaim`; its last moves
                        // the enum to `Release`.
                        (
                            Build(payload) | Commit(payload) | Complete(payload) | Reclaim(payload),
                            Reclaim(reclaimed),
                        ) => not_last(&units, &payload, true) && shrink(&payload, &reclaimed),
                        (
                            Build(payload) | Commit(payload) | Complete(payload) | Reclaim(payload),
                            Release,
                        ) => not_last(&units, &payload, false),
                        _ => false,
                    }
            }
            (Held { phase: Release, .. }, Unallocated) => true,
            _ => false,
        }),
        remaining: Rc::new(move |observation| match observation {
            Unallocated => Some(1),
            Held { phase, .. } => match phase {
                Tag | Shape | Discriminant { .. } | Select { .. } => Some(2),
                Build(payload) | Commit(payload) | Complete(payload) | Reclaim(payload) => {
                    rest(payload)?.checked_add(1)
                }
                Release => Some(1),
            },
        }),
        // The metadata block, then the selected payload's allocations.
        permits: Rc::new(move |observation| match observation {
            Unallocated => Some(Vec::new()),
            Held { phase, .. } => match phase {
                Build(payload) | Commit(payload) | Complete(payload) | Reclaim(payload) => {
                    after_own(1, &claims, payload)
                }
                _ => Some(vec![0]),
            },
        }),
        physical: Rc::new(move |observation| match observation {
            Unallocated => Some(Vec::new()),
            Held { phase, .. } => match phase {
                Build(payload) | Commit(payload) | Complete(payload) | Reclaim(payload) => {
                    after_own(1, &allocations, payload)
                }
                _ => Some(vec![0]),
            },
        }),
    }
}
