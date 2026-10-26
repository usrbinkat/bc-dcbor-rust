//! The shared public-boundary driver for deterministic tests and lifecycle
//! fuzzing. Every retained operation is driven through [`Resumable`], and
//! every step is checked against its contract: admission before work, no
//! refund, at most one quantum per turn, no progress without an admission, a
//! refused unit that alone leaves the position unchanged, and nothing after
//! publication. Scope setup, input handles, retirement and drain build on it.
//! Unsafe code here implements an instrumented input resource, never a
//! decoder. Compiled once as the `dcbor-test-support` crate and shared by
//! every integration test and fuzz target; [`heap`] is the physical heap
//! observer, and [`legality`] holds the bindings' successor relations.
pub mod classes;
pub mod heap;
pub mod legality;
pub mod rigor;

use core::fmt::Debug;
use core::{
    mem::{MaybeUninit, size_of},
    ptr::NonNull,
};
use dcbor::ByteString;
use dcbor::bounded::decode::construction::in_place::{BufferObservation, InPlace, Transferable};
use dcbor::bounded::decode::construction::reclamation::{Custody, Reclaim, Reclaimed};
use dcbor::bounded::decode::construction::{
    Acquisition, Borrowed, Construction, DecodeInput, DecodeOwner, DocumentDecoder, InputDetail,
    OwnedDocument, OwnedInitialized, Position, TypedDecoder, TypedPosition, TypedValue,
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::encoding::{OwnedEmitStep, OwnedWriter};
use dcbor::bounded::{
    Admission, Allocator, BoundedError, BoundedResult, Budget, Call, Class, Failure, LimitRefusal,
    Limits, Resumable, Step, TURN, WriteWork,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Emergency bound for generic external `Resumable` bindings and a scope's
/// whole drain, whose public contracts expose no total bound: a `Reclaim`
/// record declares its own cleanup count, which the scope enforces, but no
/// public method sums a scope's records. Concrete engine
/// helpers below use their production bounds; callers with a known bound
/// must use the corresponding `*_within` entry point.
pub const TURNS: usize = 1 << 16;

/// Logged calls a policy reserves before any heap observation, so logging
/// never allocates while the observer is armed.
pub const LOG: usize = 1 << 16;

/// A logged, strict policy reporting each admitted allocation to the heap
/// observer, its call log reserved first. A pipeline applies its schedule's
/// refusals when its measured part begins.
pub fn observed() -> Limits {
    observed_with_capacity(u64::MAX)
}

/// The shared observed policy with a fixture-supplied live-storage limit.
/// Admission and release observation, strict refusals, and reserved logs are
/// configured together before any reservation or shared policy can escape.
pub fn observed_with_capacity(capacity: u64) -> Limits {
    let mut limits = heap::observe_releases(Limits::new(u64::MAX, u64::MAX, capacity))
        .logged()
        .strict()
        .observe(heap::admitted);
    limits.reserve_log(LOG);
    limits
}

/// The steps an operation of `bound` can take, by the crate's one step rule
/// ([`dcbor::bounded::ResourceBound::steps`]), as a loop count.
pub fn turns(bound: dcbor::bounded::ResourceBound) -> usize {
    let steps = bound
        .steps::<()>()
        .expect("an operation's steps fit in u64");
    usize::try_from(steps).expect("an operation's steps fit in usize")
}

/// Options admitting any nesting an input of `len` bytes can hold, so a
/// bound under them holds under every depth limit.
fn any_depth(len: usize) -> Options {
    Options::normalizing(len)
}

/// The turn bound for a retained parse of arbitrary input of `len` bytes, or
/// its cleanup after a failure, under any depth limit
/// (`decode::cursor::retained_decode_bound`). Nested map keys are compared
/// again at every level that contains them, so it is quadratic in the input
/// length.
pub fn decode_turns(len: usize) -> usize {
    turns(
        dcbor::bounded::decode::cursor::retained_decode_bound::<dcbor::bounded::Reservation, ()>(
            len as u64,
            any_depth(len),
        )
        .expect("the parse bound of an input held in memory fits in u64"),
    )
}

/// The turn bound for an owned typed decode of `T` from arbitrary input of
/// `len` bytes, or its cleanup, under any depth limit
/// (`decode::construction::typed_decode_bound`), or a construction alone.
pub fn typed_turns<T: InPlace<Limits>>(len: usize) -> usize {
    turns(
        dcbor::bounded::decode::construction::typed_decode_bound::<ByteString, T, Limits, ()>(
            len as u64,
            any_depth(len),
        )
        .expect("the typed decode bound of an input held in memory fits in u64"),
    )
}

/// The turn bound for a string decode of arbitrary input of `len` bytes
/// (`decode::string_cursor::string_bound`).
pub fn string_turns(len: usize) -> usize {
    turns(
        dcbor::bounded::decode::string_cursor::string_bound::<dcbor::bounded::Reservation, ()>(
            len as u64,
            any_depth(len),
        )
        .expect("the string decode bound of an input held in memory fits in u64"),
    )
}

/// The turn bound for emitting `len` prepared bytes: every emission step
/// admits exactly one value, so the values of the emission's resource bound
/// (`encoding::emit_bound`) bound its steps.
pub fn emit_turns(len: usize) -> usize {
    let bound = dcbor::bounded::encoding::emit_bound::<()>(len as u64)
        .expect("the emission bound of a plan held in memory fits in u64");
    usize::try_from(bound.values).expect("the emission bound fits in usize")
}

/// The turn bound for writing `len` bytes of prepared text: every step
/// admits exactly one value (`text_cursor::pipeline::writer_bound`).
pub fn text_emit_turns(len: usize) -> usize {
    let bound = dcbor::bounded::text_cursor::pipeline::writer_bound::<()>(len as u64)
        .expect("the writer bound of a text held in memory fits in u64");
    usize::try_from(bound.values).expect("the writer bound fits in usize")
}

/// The turn bound for normalizing and encoding `source`, or preparing it
/// (`text_cursor::pipeline::TextPreparation`, which stops earlier): every
/// step of the encoder admits at least one value, so the values of its
/// resource bound (`text_cursor::encode_bound`) of `source`'s own shape
/// bound its steps. Its ordering term is linear in the combining marks, two
/// stable radix passes over their classes; no comparison sort satisfies it.
pub fn normalize_turns(source: &str) -> usize {
    let bound = dcbor::bounded::text_cursor::encode_bound::<dcbor::bounded::Reservation, ()>(
        dcbor::bounded::text_cursor::TextShape::of(source),
    )
    .expect("the encoding bound of a text held in memory fits in u64");
    usize::try_from(bound.values).expect("the encoding bound fits in usize")
}

/// The turn bound for preparing a source of `shape` (`encoding::Shape::of`):
/// every step admits at least one value or makes an allocation request of
/// at least one byte alone, so the values and requested bytes of its
/// resource bound (`encoding::prepare_bound`) bound its steps.
pub fn prepare_turns(shape: dcbor::bounded::encoding::Shape) -> usize {
    turns(
        dcbor::bounded::encoding::prepare_bound::<dcbor::bounded::Reservation, ()>(shape)
            .expect("the preparation bound of a source held in memory fits in u64"),
    )
}

/// The shape of `source`, walked unmetered.
pub fn shape(source: &dyn dcbor::bounded::encoding::Schema) -> dcbor::bounded::encoding::Shape {
    dcbor::bounded::encoding::Shape::of(source, &mut Limits::unlimited())
        .expect("the source is within the engine's limits")
}

/// The custody observation of `T`'s construction state.
pub type Observation<T> = <<T as Reclaim<Limits>>::State as Custody>::Observation;

/// One observation a construction took, and the two independent witnesses
/// of what was held then: the policy's live bytes, the sum of the live
/// permits, and the heap observer's live bytes, the sum of the live physical
/// allocations the construction made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot<O> {
    pub observation: O,
    pub live: u64,
    pub physical: u64,
}

/// One cleanup unit of a construction: whether it completed the cleanup,
/// the live bytes it released (a cleanup unit never acquires), the calls it
/// admitted, and the observation it left. The bytes, not merely whether any
/// were released, so two units that release different permits differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupUnit<O> {
    pub done: bool,
    pub released: u64,
    pub admitted: Vec<Call>,
    pub after: O,
}

/// What constructing `T` in place from `wire`'s root, and then its
/// mandatory cleanup, did under a policy of its own, observed: the work,
/// requests and storage it measured; how many build steps it took, whether
/// the value was built, and whether its last step rejected the input; the
/// observation and live bytes where the build ended or was cancelled; each
/// cleanup unit; every transition between observations, by build steps and
/// by cleanup units; the bytes of every allocation request it was granted,
/// in order; and every observation with its witnesses ([`Snapshot`]): the
/// initial state, after each build step, after each admitted cleanup unit.
#[derive(Debug, Clone)]
pub struct Constructed<O> {
    pub used: dcbor::bounded::WriteWork,
    pub requested: u64,
    pub peak: u64,
    /// What the built value held, or zero when construction failed or was
    /// cancelled.
    pub retained: u64,
    pub built: bool,
    /// The last build step rejected the input as invalid.
    pub rejected: bool,
    pub steps: usize,
    pub reached: O,
    pub held: u64,
    pub cleanup: Vec<CleanupUnit<O>>,
    pub building: Vec<(O, O)>,
    pub cleaning: Vec<(O, O)>,
    pub allocations: Vec<u64>,
    pub snapshots: Vec<Snapshot<O>>,
}

impl<O> Constructed<O> {
    /// The same construction with every observation projected by
    /// `project`, everything measured kept: how a planted observer that
    /// loses custody is put through the checks the real one passes.
    pub fn project<P>(self, project: impl Fn(&O) -> P) -> Constructed<P> {
        Constructed {
            used: self.used,
            requested: self.requested,
            peak: self.peak,
            retained: self.retained,
            built: self.built,
            rejected: self.rejected,
            steps: self.steps,
            reached: project(&self.reached),
            held: self.held,
            cleanup: self
                .cleanup
                .into_iter()
                .map(|unit| CleanupUnit {
                    done: unit.done,
                    released: unit.released,
                    admitted: unit.admitted,
                    after: project(&unit.after),
                })
                .collect(),
            building: self
                .building
                .iter()
                .map(|(before, after)| (project(before), project(after)))
                .collect(),
            cleaning: self
                .cleaning
                .iter()
                .map(|(before, after)| (project(before), project(after)))
                .collect(),
            allocations: self.allocations,
            snapshots: self
                .snapshots
                .iter()
                .map(|snapshot| Snapshot {
                    observation: project(&snapshot.observation),
                    live: snapshot.live,
                    physical: snapshot.physical,
                })
                .collect(),
        }
    }
}

/// `state`'s custody observation, taken twice: the two are equal, and
/// observing admits nothing and changes no live byte.
fn observe_custody<S: Custody>(
    state: &mut S,
    m: &Limits,
    heap: &heap::Observation,
    at: &str,
) -> S::Observation {
    let (attempts, live) = (m.attempts(), m.live_bytes());
    let physical = heap.snapshot();
    let first = heap.window(|| state.observe());
    let second = heap.window(|| state.observe());
    assert_eq!(
        heap.snapshot(),
        physical,
        "{at}: observing changed physical storage"
    );
    assert_eq!(first, second, "{at}: observing twice disagreed");
    assert_eq!(m.attempts(), attempts, "{at}: observing admitted work");
    assert_eq!(m.live_bytes(), live, "{at}: observing changed what is held");
    first
}

/// Construct `T` in place from the root of canonical `wire`, one quantum per
/// step, to completion or to its terminal error, or, when `cancel` names a
/// build step, until that step and no further; `inspect` a built value;
/// then reclaim it to `Done`, every cleanup unit refused once before it is
/// admitted. Both run under one policy of their own: the document's parse
/// is not measured, and no scope record is involved; the work, requests and
/// storage measured are exactly what `InPlace::COST` bounds, which refusals
/// do not change. The state is observed after every build step and every
/// cleanup unit ([`Custody`]); a cleanup unit whose only attempt was refused
/// must leave the observation unchanged, and no refusal may change what is
/// held. Steps are bounded by `T`'s cost. The heap observer is armed around
/// every build step and cleanup unit, and only there, so it sees exactly
/// the engine's physical allocations: each must have been admitted, and
/// cleanup must free every one. The binary must install [`heap::Heap`].
pub fn construction<T: InPlace<Limits>>(
    wire: &[u8],
    cancel: Option<usize>,
    inspect: impl FnOnce(&T),
) -> Constructed<Observation<T>> {
    construction_requests::<T>(wire, cancel, 0, inspect).0
}

/// The same observed binding driver with the first `requests` allocation
/// requests refused. Returns construction accounting before cleanup so a
/// fixture can compare retained admissions against its unobstructed run.
pub fn construction_requests<T: InPlace<Limits>>(
    wire: &[u8],
    cancel: Option<usize>,
    requests: usize,
    inspect: impl FnOnce(&T),
) -> (Constructed<Observation<T>>, RefusalRun) {
    use dcbor::bounded::decode::construction::in_place::Built;
    let mut parser = Limits::unlimited();
    let document =
        dcbor::bounded::decode::decode(wire, 64, &mut parser).expect("the fixture parses");
    let bound = turns(
        T::COST
            .bound::<()>(wire.len() as u64)
            .expect("the cost of a fixture fits in u64"),
    );
    assert!(
        heap::installed(),
        "the observed construction witnesses physical storage: install heap::Heap as the \
         binary's global allocator"
    );
    let mut m = observed().refusing_requests(requests);
    let observer = heap::Observation::begin(None);
    observer.stop();
    let physical = || observer.snapshot().live as u64;
    let mut slot = MaybeUninit::<T>::uninit();
    let place = NonNull::from(&mut slot);
    let mut state = T::INITIAL;
    let mut previous = observe_custody(&mut state, &m, &observer, "the initial state");
    let mut snapshots = vec![Snapshot {
        observation: previous,
        live: m.live_bytes(),
        physical: physical(),
    }];
    let mut building = Vec::new();
    let mut built = false;
    let mut rejected = false;
    let mut ended = false;
    let mut steps = 0;
    let build_bound = bound
        .checked_add(requests)
        .expect("request retry bound fits");
    while steps < build_bound && cancel != Some(steps) {
        // Logging is harness storage, never an allocation of the binding.
        // Keep room outside observation for a quantum's work admissions,
        // one allocation request and the refusal that ends a turn.
        m.reserve_log(TURN.values as usize + 2);
        let attempts = m.attempts();
        let live = m.live_bytes();
        // SAFETY: the slot is this construction's unique, stable destination,
        // paired with one state from its first step to its last cleanup.
        let result = observer.window(|| {
            checked(&mut m, |m| unsafe {
                T::build_step(&document, 0, place, &mut state, m)
            })
        });
        steps += 1;
        let next = observe_custody(
            &mut state,
            &m,
            &observer,
            &format!("after build step {steps}"),
        );
        snapshots.push(Snapshot {
            observation: next,
            live: m.live_bytes(),
            physical: physical(),
        });
        building.push((previous, next));
        previous = next;
        match result {
            Ok(Built::Progress) => {}
            Ok(Built::Done) => {
                built = true;
                ended = true;
                break;
            }
            Err(error) if error.refused() => {
                assert!(
                    ordinary_exhaustion(&m, &error)
                        || matches!(
                            m.refused_calls().last(),
                            Some(&(index, LimitRefusal::Scheduled(selected), true))
                                if index + 1 == m.attempts()
                                    && selected == index
                                    && matches!(m.calls()[index], Call::Allocate(_))
                                    && error.class() == Class::Refused(&LimitRefusal::Scheduled(index))
                        ),
                    "unexpected construction refusal: {error:?}"
                );
                if m.attempts() == attempts + 1 {
                    assert_eq!(m.live_bytes(), live, "refusal changed live storage");
                    assert_eq!(
                        next,
                        building.last().unwrap().0,
                        "a construction unit whose only attempt was refused moved"
                    );
                }
            }
            // Only an input rejected as invalid is an outcome a run may
            // measure; a defect, a refusal or a physical failure never is.
            Err(error) => {
                assert!(
                    matches!(error.class(), dcbor::bounded::Class::Invalid),
                    "{error:?}, of class {:?}",
                    error.class()
                );
                rejected = true;
                ended = true;
                break;
            }
        }
    }
    assert!(
        ended || cancel == Some(steps),
        "construction exceeded its cost's bound of {bound} steps"
    );
    let reached = previous;
    let accounting = RefusalRun::of(&m);
    let held = m.live_bytes();
    let retained = if built { held } else { 0 };
    if built {
        // SAFETY: construction reported the destination fully initialized;
        // the borrow ends before cleanup begins.
        inspect(unsafe { place.as_ref().assume_init_ref() });
    }
    let mut cleanup = Vec::new();
    let mut cleaning = Vec::new();
    // The binding's declared cleanup count, read as an observation is: it
    // admits nothing and changes nothing, and the cleanup that follows takes
    // no more successful calls than it declares.
    let (attempts, live) = (m.attempts(), m.live_bytes());
    // SAFETY: the same destination and state, no reference into the value.
    let declared = unsafe { <T as Reclaim<Limits>>::remaining(place, &mut state) };
    assert_eq!(
        (m.attempts(), m.live_bytes()),
        (attempts, live),
        "declaring the cleanup count admitted work or changed what is held"
    );
    refuse(&mut m, pipeline::Refusal::Each);
    // Every cleanup unit refused once, then admitted.
    for unit in 0..allowed(&m, bound) {
        m.reserve_log(TURN.values as usize + 2);
        let at = format!("after {steps} build steps, cleanup unit {unit}");
        let before = observe_custody(&mut state, &m, &observer, &at);
        let (attempts, live, admitted) = (m.attempts(), m.live_bytes(), m.admitted().len());
        // SAFETY: the same destination and state; no reference into the
        // value remains.
        match observer
            .window(|| checked(&mut m, |m| unsafe { T::reclaim_step(place, &mut state, m) }))
        {
            Err(error) if error.refused() => {
                if m.attempts() - attempts == 1 {
                    assert_eq!(
                        observe_custody(&mut state, &m, &observer, &at),
                        before,
                        "{at}: a cleanup unit whose only attempt was refused moved"
                    );
                }
                assert_eq!(m.live_bytes(), live, "{at}: a refusal changed what is held");
            }
            Ok(outcome) => {
                let after = observe_custody(&mut state, &m, &observer, &at);
                snapshots.push(Snapshot {
                    observation: after,
                    live: m.live_bytes(),
                    physical: physical(),
                });
                cleaning.push((before, after));
                let done = outcome == Reclaimed::Done;
                assert!(m.live_bytes() <= live, "{at}: cleanup acquired storage");
                cleanup.push(CleanupUnit {
                    done,
                    released: live - m.live_bytes(),
                    admitted: m.admitted()[admitted..].to_vec(),
                    after,
                });
                if done {
                    assert!(
                        cleanup.len() as u64 <= declared,
                        "{at}: cleanup took {} calls, beyond the {declared} its state declared",
                        cleanup.len()
                    );
                    assert_eq!(m.live_bytes(), 0, "{at}: cleanup left storage held");
                    let stats = observer.snapshot();
                    assert_eq!(stats.live, 0, "{at}: cleanup left physical storage");
                    assert_eq!(
                        stats.unadmitted, 0,
                        "{at}: a physical allocation unadmitted"
                    );
                    assert_eq!(stats.denied, 0, "{at}: a physical allocation was denied");
                    assert!(!stats.overflow, "{at}: heap observation incomplete");
                    let allocations = m
                        .admitted()
                        .iter()
                        .filter_map(|call| match call {
                            Call::Allocate(bytes) => Some(*bytes),
                            Call::Work { .. } => None,
                        })
                        .collect();
                    return (
                        Constructed {
                            used: m.used(),
                            requested: m.requested_bytes(),
                            peak: m.peak_bytes(),
                            retained,
                            built,
                            rejected,
                            steps,
                            reached,
                            held,
                            cleanup,
                            building,
                            cleaning,
                            allocations,
                            snapshots,
                        },
                        accounting,
                    );
                }
            }
            Err(error) => panic!("{at}: cleanup failed: {error:?}"),
        }
    }
    panic!("cleanup exceeded its bound after {steps} build steps");
}

/// Every state construction of `T` from `wire` reaches, from nothing built
/// to its end, each cancelled there and cleaned up ([`construction`]): the
/// evidence a binding's observation and reduction are checked against.
pub fn reached<T: InPlace<Limits>>(name: &str, wire: &[u8]) -> Vec<Constructed<Observation<T>>> {
    let total = construction::<T>(wire, None, |_| {}).steps;
    let mut progress = rigor::Progress::new(format!(
        "{name}: {} from {wire:02x?}",
        core::any::type_name::<T>()
    ));
    progress.stage("reached states", total + 1, total + 1);
    (0..=total)
        .map(|steps| {
            progress.case(format!("cancelled after {steps} build steps"));
            construction::<T>(wire, Some(steps), |_| {})
        })
        .collect()
}

/// Members of one class must clean up alike: every member named, keyed by
/// its class, with what its cleanup did. The first member of each class is
/// its representative; any other whose cleanup differs fails, naming both,
/// because the class merges states of different custody. The one check of
/// every class claim: the matrix's stop classes, a binding's observation
/// (its class is the observation itself) and a binding's declared
/// reduction.
pub fn agree<K: Ord + Debug, V: PartialEq + Debug>(
    name: &str,
    members: impl IntoIterator<Item = (String, K, V)>,
) {
    let mut first: std::collections::BTreeMap<K, (String, V)> = std::collections::BTreeMap::new();
    for (member, class, cleanup) in members {
        match first.get(&class) {
            Some((representative, expected)) => assert!(
                &cleanup == expected,
                "{name}: {member} and {representative} share class {class:?} but clean up \
                 differently ({cleanup:?} against {expected:?}): the class merges states of \
                 different custody"
            ),
            None => {
                first.insert(class, (member, cleanup));
            }
        }
    }
}

/// The observation of `T`'s states, projected by `project`, is complete for
/// custody on every state reached building `T` from `wire`: two states whose
/// projections are equal hold equal live bytes and clean up identically,
/// unit by unit. The production check projects by identity; a planted
/// projection that drops custody must fail it. Returns the reached states,
/// whose transitions the binding's successor relation checks ([`legal`]).
pub fn observation<T: InPlace<Limits>, P: Ord + Debug>(
    name: &str,
    wire: &[u8],
    project: impl Fn(&Observation<T>) -> P,
) -> Vec<Constructed<Observation<T>>> {
    let states = reached::<T>(name, wire);
    rigor::classes(
        &format!(
            "{name}: {} observation from {wire:02x?}",
            core::any::type_name::<T>()
        ),
        states.iter().flat_map(|state| {
            core::iter::once(format!("{:?}", project(&state.reached))).chain(
                state
                    .cleanup
                    .iter()
                    .map(|unit| format!("{:?}", project(&unit.after))),
            )
        }),
    );
    agree(
        &format!("{name}: observation"),
        states.iter().map(|state| {
            (
                format!("the state after {} build steps", state.steps),
                project(&state.reached),
                (state.held, state.cleanup.clone()),
            )
        }),
    );
    states
}

/// `class` is a simulation of cleanup on the states reached building `T`
/// from `wire`: from two states of one class, each admitted cleanup unit
/// reaches the same outcome, admits the same calls and releases the same
/// bytes, into states again of one class; a unit refused first leaves its
/// state unchanged in every member alike, which [`construction`] requires
/// of each. The same calls are what the pipeline matrix requires of a
/// class's members. The observation is checked complete first. The
/// production check classes by the state's declared
/// [`Reduction`](dcbor::bounded::decode::construction::reclamation::Reduction);
/// a planted class that merges states of different custody must fail it.
/// Returns the reached states, for the binding's successor relations
/// ([`legal`]).
pub fn simulation<T: InPlace<Limits>, C: Ord + Debug>(
    name: &str,
    wire: &[u8],
    class: impl Fn(&Observation<T>) -> C,
) -> Vec<Constructed<Observation<T>>> {
    let states = observation::<T, Observation<T>>(name, wire, |observation| *observation);
    rigor::classes(
        &format!(
            "{name}: {} reduction from {wire:02x?}",
            core::any::type_name::<T>()
        ),
        states.iter().flat_map(|state| {
            core::iter::once(format!("{:?}", class(&state.reached))).chain(
                state
                    .cleanup
                    .iter()
                    .map(|unit| format!("{:?}", class(&unit.after))),
            )
        }),
    );
    agree(
        &format!("{name}: reduction"),
        states.iter().map(|state| {
            (
                format!("the state after {} build steps", state.steps),
                class(&state.reached),
                state
                    .cleanup
                    .iter()
                    .map(|unit| {
                        (
                            unit.done,
                            unit.released,
                            unit.admitted.clone(),
                            class(&unit.after),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        }),
    );
    states
}

/// `T`'s declared cleanup reduction is a simulation of cleanup on the states
/// reached building `T` from `wire` ([`simulation`]). Returns the reached
/// states, for the binding's successor relations ([`legal`]).
pub fn certified<T>(name: &str, wire: &[u8]) -> Vec<Constructed<Observation<T>>>
where
    T: InPlace<Limits>,
    T::State: dcbor::bounded::decode::construction::reclamation::Reduction,
{
    use dcbor::bounded::decode::construction::reclamation::Reduction;
    simulation::<T, <T::State as Reduction>::Class>(name, wire, |observation| {
        <T::State as Reduction>::class(observation)
    })
}

/// Every transition the reached `states` took is in the binding's successor
/// relations ([`legality::Legality`]), and its cleanup is exactly as long as
/// they say: each construction starts from the binding's initial
/// observation; every build step takes a build transition, except a last
/// step that rejected the input, which must leave the observation
/// unchanged; every admitted cleanup unit takes a cleanup transition; and
/// the units remaining from the state each construction reached, and from
/// each state its cleanup passed through before completing, are exactly the
/// units that followed. Every observation is witnessed: the policy's live
/// bytes are exactly the granted bytes of the permits it claims, and the
/// heap observer's live bytes exactly those of the physical allocations it
/// claims ([`Snapshot`]). The first violation is named.
pub fn legal<O: Copy + Eq + Debug>(
    name: &str,
    states: &[Constructed<O>],
    legality: &legality::Legality<O>,
) {
    for state in states {
        let at = format!("{name}, after {} build steps", state.steps);
        let start = state
            .building
            .first()
            .map_or(state.reached, |(before, _)| *before);
        if let Some(initial) = legality.initial {
            assert_eq!(
                start, initial,
                "{at}: construction did not start from the binding's initial observation"
            );
        }
        let last = state.building.len().checked_sub(1);
        for (step, (before, after)) in state.building.iter().enumerate() {
            if state.rejected && Some(step) == last {
                assert_eq!(
                    after, before,
                    "{at}: build step {step}, which rejected the input, changed the observation"
                );
            } else {
                assert!(
                    (legality.build)(before, after),
                    "{at}: the build transition {before:?} to {after:?} at step {step} is not \
                     in the binding's successor relation"
                );
            }
        }
        for (unit, (before, after)) in state.cleaning.iter().enumerate() {
            assert!(
                (legality.clean)(before, after),
                "{at}: the cleanup transition {before:?} to {after:?} at unit {unit} is not in \
                 the binding's successor relation"
            );
        }
        if let Some(units) = (legality.remaining)(&state.reached) {
            assert_eq!(
                units,
                state.cleanup.len(),
                "{at}: the cleanup units remaining from {:?}",
                state.reached
            );
        }
        for (unit, (_, after)) in state.cleaning.iter().enumerate() {
            let left = state.cleanup.len() - unit - 1;
            if left > 0
                && let Some(units) = (legality.remaining)(after)
            {
                assert_eq!(
                    units, left,
                    "{at}: the cleanup units remaining after unit {unit}, from {after:?}"
                );
            }
        }
        for snapshot in &state.snapshots {
            let observation = snapshot.observation;
            let granted = |claims: Vec<usize>| -> u64 {
                claims
                    .into_iter()
                    .map(|claim| {
                        *state.allocations.get(claim).unwrap_or_else(|| {
                            panic!(
                                "{at}: {observation:?} claims allocation {claim}, of {} granted",
                                state.allocations.len()
                            )
                        })
                    })
                    .sum()
            };
            if let Some(claims) = (legality.permits)(&observation) {
                assert_eq!(
                    snapshot.live,
                    granted(claims),
                    "{at}: the live permits witnessed differ from those {observation:?} claims"
                );
            }
            if let Some(claims) = (legality.physical)(&observation) {
                assert_eq!(
                    snapshot.physical,
                    granted(claims),
                    "{at}: the live physical allocations witnessed differ from those \
                     {observation:?} claims"
                );
            }
        }
    }
}

/// Require that `T`'s construction cost covers `measured`, from `wire`.
#[track_caller]
fn within_cost<T: InPlace<Limits>>(wire: &[u8], measured: Constructed<Observation<T>>) {
    let bound = T::COST
        .bound::<()>(wire.len() as u64)
        .expect("the cost of a fixture fits in u64");
    assert!(
        bound.covers(
            measured.used,
            measured.requested,
            measured.peak,
            measured.retained
        ),
        "{} from {wire:02x?}: used {:?}, requested {}, peak {}, retained {}, beyond {bound:?}",
        core::any::type_name::<T>(),
        measured.used,
        measured.requested,
        measured.peak,
        measured.retained
    );
}

/// Require that `T` is built from `wire`, satisfies `inspect`, and that its
/// construction and cleanup are within its cost.
#[track_caller]
pub fn builds_within_cost<T: InPlace<Limits>>(wire: &[u8], inspect: impl FnOnce(&T)) {
    let measured = construction::<T>(wire, None, inspect);
    assert!(
        measured.built,
        "{} was not built from {wire:02x?}",
        core::any::type_name::<T>()
    );
    within_cost::<T>(wire, measured);
}

/// Require that `T` is rejected from `wire`, and that its construction to
/// the rejection and the cleanup after it are within its cost.
#[track_caller]
pub fn rejects_within_cost<T: InPlace<Limits>>(wire: &[u8]) {
    let measured = construction::<T>(wire, None, |_| {});
    assert!(
        !measured.built,
        "{} was built from {wire:02x?}",
        core::any::type_name::<T>()
    );
    within_cost::<T>(wire, measured);
}

/// A borrowed input handle in a scope over the borrowed bytes.
pub type Input<'s> = OwnedInitialized<'s, Borrowed<'s>, Limits>;

/// A production step result that reports whether the step made progress.
pub trait Outcome {
    fn progressed(&self) -> bool;
}

impl<O> Outcome for Step<O> {
    fn progressed(&self) -> bool {
        matches!(self, Step::Progress)
    }
}

/// A single-step operation's success is its completion, never progress.
impl Outcome for () {
    fn progressed(&self) -> bool {
        false
    }
}

impl Outcome for Reclaimed {
    fn progressed(&self) -> bool {
        matches!(self, Reclaimed::Progress)
    }
}

impl Outcome for dcbor::bounded::decode::construction::in_place::Built {
    fn progressed(&self) -> bool {
        matches!(self, Self::Progress)
    }
}

/// A chunk is progress: emitting it must have been admitted.
impl Outcome for OwnedEmitStep<'_> {
    fn progressed(&self) -> bool {
        matches!(self, OwnedEmitStep::Progress | OwnedEmitStep::Chunk(_))
    }
}

impl<T: Outcome, E> Outcome for Result<T, E> {
    fn progressed(&self) -> bool {
        matches!(self, Ok(outcome) if outcome.progressed())
    }
}

/// A step result named without requiring the output to be printable.
pub fn label<O, E: Debug>(result: &Result<Step<O>, E>) -> String {
    match result {
        Ok(Step::Progress) => "Progress".into(),
        Ok(Step::Complete(_)) => "Complete".into(),
        Ok(Step::Finished) => "Finished".into(),
        Err(error) => format!("Err({error:?})"),
    }
}

/// Require that one step reported `Progress`, naming what it reported
/// otherwise. Outputs need not be comparable or printable.
#[track_caller]
pub fn expect_progress<O, E: Debug>(result: Result<Step<O>, E>) {
    assert!(
        matches!(result, Ok(Step::Progress)),
        "expected Progress, got {}",
        label(&result)
    );
}

/// Local release evidence for observed pools; a private pool's live total
/// remains the witness for callers using an uninstrumented policy. Never
/// fall back to a shared total when a release observer is installed.
struct ReleaseWitness {
    observed: bool,
    before: u64,
}

impl ReleaseWitness {
    fn capture(m: &Limits) -> Self {
        let observed = m.observes_releases();
        Self {
            observed,
            before: if observed {
                heap::reservation_releases()
            } else {
                m.live_bytes()
            },
        }
    }

    fn released(&self, m: &Limits) -> bool {
        if self.observed {
            heap::reservation_releases() != self.before
        } else {
            m.live_bytes() < self.before
        }
    }

    fn unchanged(&self, m: &Limits) -> bool {
        if self.observed {
            heap::reservation_releases() == self.before
        } else {
            m.live_bytes() == self.before
        }
    }
}

/// One fresh scheduler turn of `step`. Admitted work is never refunded, the
/// turn admits at most one quantum, and a result that reports progress made
/// at least one admission or released an allocation prepaid at acquisition.
pub fn checked<R: Outcome>(m: &mut Limits, step: impl FnOnce(&mut Limits) -> R) -> R {
    m.turn();
    let (before, attempts) = (m.used(), m.attempts());
    let releases = ReleaseWitness::capture(m);
    let result = step(m);
    let after = m.used();
    assert!(
        after.values >= before.values && after.bytes >= before.bytes,
        "admitted work refunded: {before:?} -> {after:?}"
    );
    assert!(
        after.values - before.values <= TURN.values && after.bytes - before.bytes <= TURN.bytes,
        "turn exceeded its quantum: {before:?} -> {after:?}"
    );
    if result.progressed() {
        assert!(
            m.attempts() > attempts || releases.released(m),
            "reported progress without an admission or a prepaid release"
        );
    }
    result
}

/// One step of `operation` under the policy's current allowance, checked
/// against the [`Resumable`] contract: progress made an admission, and a
/// step whose only admission attempt was refused left the position
/// unchanged.
pub fn contracted<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
) -> Result<Step<O::Output>, O::Error>
where
    O::Error: Debug,
{
    let position = operation.position();
    let attempts = m.attempts();
    let releases = ReleaseWitness::capture(m);
    let result = operation.step(m);
    let attempted = m.attempts() - attempts;
    match &result {
        Ok(Step::Progress) => assert!(
            attempted > 0 || releases.released(m),
            "progress without an admission or a prepaid release: from {position:?} to {:?}",
            operation.position()
        ),
        Err(error) if error.refused() && attempted == 1 => assert_eq!(
            operation.position(),
            position,
            "a step whose only admission was refused moved the operation"
        ),
        _ => {}
    }
    result
}

/// After publication or completed cleanup: the next step returns `Finished`,
/// admits nothing and leaves the position unchanged.
pub fn exhausted<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O)
where
    O::Error: Debug,
{
    ended(m, operation, true);
}

/// [`exhausted`], reading the position only when `observed`: unobserved, the
/// operation is stepped without its position read at all, as the no-effect
/// check runs it.
fn ended<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O, observed: bool)
where
    O::Error: Debug,
{
    let attempts = m.attempts();
    let position = observed.then(|| operation.position());
    let result = operation.step(m);
    assert!(
        matches!(result, Ok(Step::Finished)),
        "a finished operation stepped to {}",
        label(&result)
    );
    assert_eq!(m.attempts(), attempts, "a finished operation admitted work");
    if let Some(position) = position {
        assert_eq!(operation.position(), position, "a finished operation moved");
    }
}

/// One fresh checked turn of `operation` ([`checked`]): its contract checked
/// through its position when `observed` ([`contracted`]), or, unobserved,
/// stepped without its position read at all, as the no-effect check runs
/// it.
fn turn<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    observed: bool,
) -> Result<Step<O::Output>, O::Error>
where
    O::Error: Debug,
{
    checked(m, |m| {
        if observed {
            contracted(m, operation)
        } else {
            operation.step(m)
        }
    })
}

/// After a refusal: when the refused call is a unit of work wider than a
/// turn's quantum, no turn can ever admit it and the operation is stalled.
/// Fail at once, naming the call, the quantum and the operation's position,
/// rather than after every turn of the bound is spent retrying it.
fn refused<O: Resumable<Limits>>(m: &Limits, operation: &mut O) {
    if let Some(Admission {
        index,
        call: Call::Work { values, bytes },
        result: Err(LimitRefusal::Work),
        ..
    }) = m.trace().last()
        && (values > TURN.values || bytes > TURN.bytes)
    {
        panic!(
            "call {index}: an indivisible unit of {values} values and {bytes} bytes exceeds a \
             turn's quantum {TURN:?}, so no turn admits it; the operation is stalled at {:?}",
            operation.position()
        );
    }
}

/// Positively identify a non-injected work refusal that a fresh quantum can
/// satisfy. Step-level fixtures use this predicate without treating arbitrary
/// resource failures as retryable progress.
pub fn ordinary_exhaustion<E: Failure<Refusal = LimitRefusal>>(m: &Limits, error: &E) -> bool {
    if error.class() != Class::Refused(&LimitRefusal::Work) {
        return false;
    }
    let Some(&(index, LimitRefusal::Work, false)) = m.refused_calls().last() else {
        return false;
    };
    assert_eq!(index + 1, m.attempts(), "refusal witness is stale");
    let Call::Work { values, bytes } = m.calls()[index] else {
        panic!("ordinary work refusal did not concern work");
    };
    let requested = WriteWork::new(values, bytes);
    assert!(TURN.covers(&requested), "unit exceeds a fresh quantum");
    assert!(
        !m.remaining().covers(&requested),
        "ordinary refusal had enough allowance"
    );
    true
}

/// [`drive_within`] the general bound of [`TURNS`].
pub fn drive<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O) -> Result<O::Output, O::Error>
where
    O::Error: Debug,
{
    drive_within(m, operation, TURNS)
}

/// Drive `operation` through at most `turns` fresh checked turns until it
/// publishes or fails terminally. Refusals resume in the next turn.
/// `Finished` without publication, and exceeding the bound, are defects.
pub fn drive_within<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    turns: usize,
) -> Result<O::Output, O::Error>
where
    O::Error: Debug,
{
    match drive_faulted(m, operation, turns, false)? {
        Some(output) => Ok(output),
        None => unreachable!("an operation that resumes every refusal is never cancelled"),
    }
}

/// Drive `operation` through at most `turns` fresh checked turns under the
/// refusals `m` schedules: to its publication (`Some`), to its terminal
/// error (`Err`), or, when `cancel` is set, to its first injected refusal, where the
/// consumer stops stepping it (`None`). Ordinary turn exhaustion resumes in the next
/// turn. `Finished` without publication, and exceeding the bound, are
/// defects. Every step is checked ([`checked`], [`contracted`]), and a
/// published operation is checked [`exhausted`].
pub fn drive_faulted<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    turns: usize,
    cancel: bool,
) -> Result<Option<O::Output>, O::Error>
where
    O::Error: Debug,
{
    drive_faulted_observed(m, operation, turns, cancel, |_, _, _| {})
}

/// The same driver with a callback after each turn, outside the operation,
/// for fixture-specific resource and semantic witnesses. The callback borrows
/// the operation and outcome immutably; scheduling and cancellation stay here.
pub fn drive_faulted_observed<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    turns: usize,
    cancel: bool,
    mut after_turn: impl FnMut(&Limits, &O, &Result<Step<O::Output>, O::Error>),
) -> Result<Option<O::Output>, O::Error>
where
    O::Error: Debug,
{
    let injected_before = m.injected_refusals();
    for _ in 0..turns {
        let result = checked(m, |m| contracted(m, operation));
        after_turn(m, operation, &result);
        match result {
            Ok(Step::Complete(output)) => {
                exhausted(m, operation);
                return Ok(Some(output));
            }
            Ok(Step::Progress) => {}
            Ok(Step::Finished) => panic!("operation finished without publication"),
            Err(error) if error.refused() => {
                if cancel && m.injected_refusals() > injected_before {
                    return Ok(None);
                }
                refused(m, operation);
            }
            Err(error) => return Err(error),
        }
    }
    panic!(
        "operation exceeded its bound of {turns} turns; trace={:?}",
        m.calls()
    );
}

/// [`finish_within`] the general bound of [`TURNS`].
pub fn finish<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O)
where
    O::Error: Debug,
{
    finish_within(m, operation, TURNS);
}

/// Drive a cancelled or failed `operation` through its own cleanup to
/// `Finished`, in at most `turns` fresh checked turns.
pub fn finish_within<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O, turns: usize)
where
    O::Error: Debug,
{
    wound(m, operation, turns, true);
}

/// [`finish_within`], each turn observed or not ([`turn`]).
fn wound<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O, turns: usize, observed: bool)
where
    O::Error: Debug,
{
    for _ in 0..turns {
        let result = turn(m, operation, observed);
        match result {
            Ok(Step::Finished) => {
                ended(m, operation, observed);
                return;
            }
            Ok(Step::Progress) => {}
            Ok(Step::Complete(_)) => panic!("a cancelled or failed operation published"),
            Err(error) if error.refused() => refused(m, operation),
            Err(error) => panic!("cleanup failed: {error:?}"),
        }
    }
    panic!("cleanup exceeded its bound of {turns} turns");
}

/// [`fail_within`] the general bound of [`TURNS`].
pub fn fail<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O) -> O::Error
where
    O::Error: Debug,
{
    fail_within(m, operation, TURNS)
}

/// Drive `operation` in at most `turns` fresh checked turns until it fails
/// terminally, without publishing. Returns the terminal error; the operation
/// is then in its own cleanup, which [`finish`] performs under whichever
/// policy the caller chooses, so a measured trace can end at the failure.
pub fn fail_within<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    turns: usize,
) -> O::Error
where
    O::Error: Debug,
{
    for _ in 0..turns {
        match checked(m, |m| contracted(m, operation)) {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(_)) => panic!("an operation expected to fail published"),
            Ok(Step::Finished) => panic!("an operation expected to fail finished"),
            Err(error) if error.refused() => refused(m, operation),
            Err(error) => return error,
        }
    }
    panic!(
        "operation exceeded its bound of {turns} turns without failing; trace={:?}",
        m.calls()
    );
}

/// Step `operation` under the policy's current allowance, without new
/// turns, until it reports the injected refusal `reason`. Every earlier step
/// made progress. Returns the refused call's index.
pub fn suspend<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    reason: LimitRefusal,
) -> usize
where
    O::Error: Debug,
{
    suspend_within(m, operation, reason, TURNS, TurnSchedule::Retained)
}

/// Whether a suspension fixture keeps an externally imposed allowance or
/// renews the standard quantum before every step.
#[derive(Clone, Copy)]
pub enum TurnSchedule {
    Retained,
    Fresh,
}

/// Suspend within the operation's supplied bound and explicit turn policy.
pub fn suspend_within<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    reason: LimitRefusal,
    turns: usize,
    schedule: TurnSchedule,
) -> usize
where
    O::Error: Debug,
{
    for _ in 0..turns {
        let result = match schedule {
            TurnSchedule::Retained => contracted(m, operation),
            TurnSchedule::Fresh => checked(m, |m| contracted(m, operation)),
        };
        match &result {
            Ok(Step::Progress) => {}
            Err(error) if error.refused() => {
                if matches!(schedule, TurnSchedule::Fresh)
                    && error.class() == Class::Refused(&LimitRefusal::Work)
                    && reason != LimitRefusal::Work
                    && m.injected_refusals() == 0
                {
                    refused(m, operation);
                    continue;
                }
                assert_eq!(error.class(), Class::Refused(&reason));
                let (index, observed) = m.first_refusal().expect("injection never fired");
                assert_eq!(observed, reason);
                return index;
            }
            _ => panic!(
                "target refusal {reason:?} was not reached: {}",
                label(&result)
            ),
        }
    }
    panic!("target refusal {reason:?} never fired within {turns} steps");
}

/// The turns an operation bounded by `turns` may take under `m`'s refusals,
/// by the crate's one refusal allowance ([`Limits::allowed`]), as a loop
/// count.
pub fn allowed(m: &Limits, turns: usize) -> usize {
    let turns = u64::try_from(turns).expect("a turn bound fits in u64");
    let allowed = m
        .allowed::<()>(turns)
        .expect("a doubled turn bound fits in u64");
    usize::try_from(allowed).expect("a doubled turn bound fits in usize")
}

/// Apply `refusal` to `m` from its next attempt on: no refusal, every
/// admission refused once, or the attempted call of one index refused. The
/// one way a driver applies a schedule's refusals.
pub fn refuse(m: &mut Limits, refusal: pipeline::Refusal) {
    match refusal {
        pipeline::Refusal::None => {}
        pipeline::Refusal::At(index) => m.fail_call(Some((index, LimitRefusal::Scheduled(index)))),
        pipeline::Refusal::For(index, reason) => m.fail_call(Some((index, reason))),
        pipeline::Refusal::Each => m.fail_each(),
    }
}

/// Repeated refusals at one reached semantic boundary. This is a local
/// contract check, not a whole-run replay: each attempt must report the
/// injected reason, preserve the observation, retain all custody and charge
/// nothing. The caller supplies its ordinary production step and snapshot.
pub fn repeated_refusal<P: PartialEq + Debug, E: Failure<Refusal = LimitRefusal> + Debug>(
    name: &str,
    m: &mut Limits,
    position: P,
    repeats: usize,
    mut step: impl FnMut(&mut Limits) -> (P, Result<(), E>),
) {
    assert!(repeats > 0, "{name}: no repeated refusal selected");
    for repeat in 0..repeats {
        m.clear_refusal();
        let index = m.attempts();
        let work = m.used();
        let releases = ReleaseWitness::capture(m);
        refuse(m, pipeline::Refusal::For(index, LimitRefusal::Work));
        let (after, result) = step(m);
        let error = result.expect_err("a targeted admission was not refused");
        assert_eq!(
            error.class(),
            Class::Refused(&LimitRefusal::Work),
            "{name}, repeat {repeat}"
        );
        assert_eq!(
            m.first_refusal(),
            Some((index, LimitRefusal::Work)),
            "{name}"
        );
        assert_eq!(m.attempts(), index + 1, "{name}: continued after refusal");
        assert_eq!(after, position, "{name}: refusal changed custody");
        assert_eq!(m.used(), work, "{name}: refusal charged or refunded work");
        assert!(releases.unchanged(m), "{name}: refusal released storage");
        m.fail_call(None);
        m.clear_refusal();
    }
}

/// Take one real turn, first refusing its next admission repeatedly. A
/// prepaid release has no admission to refuse: witness that release and
/// return its progress rather than stepping past it or claiming a refusal.
pub fn repeated_turn<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    repeats: usize,
) -> Result<Step<O::Output>, O::Error>
where
    O::Error: Debug,
{
    assert!(repeats > 0);
    m.turn();
    let index = m.attempts();
    let work = m.used();
    let releases = ReleaseWitness::capture(m);
    let position = operation.position();
    refuse(m, pipeline::Refusal::For(index, LimitRefusal::Work));
    let result = contracted(m, operation);
    m.fail_call(None);
    if m.attempts() == index {
        assert!(
            matches!(result, Ok(Step::Progress)),
            "non-admitting step was not release progress"
        );
        assert_eq!(m.used(), work);
        assert!(
            releases.released(m),
            "non-admitting step released no storage"
        );
        return result;
    }
    assert!(matches!(&result, Err(error) if error.class() == Class::Refused(&LimitRefusal::Work)));
    assert_eq!(m.first_refusal(), Some((index, LimitRefusal::Work)));
    assert_eq!(m.attempts(), index + 1);
    assert_eq!(operation.position(), position);
    assert_eq!(m.used(), work);
    assert!(releases.unchanged(m), "refusal released storage");
    if repeats > 1 {
        repeated_refusal("retained operation turn", m, position, repeats - 1, |m| {
            m.turn();
            let result = contracted(m, operation).map(|_| ());
            (operation.position(), result)
        });
    }
    checked(m, |m| contracted(m, operation))
}

/// What one run of a single resumable operation injects: its refusals, and
/// whether the consumer cancels at the refused call, dropping the operation
/// there instead of resuming it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub refusal: pipeline::Refusal,
    pub cancel: bool,
}

/// A complete policy-backed run. Attempt indices and refusal provenance remain
/// authoritative even when an injection changes subsequent turn boundaries.
#[derive(Debug, PartialEq, Eq)]
pub struct RefusalRun {
    calls: Vec<Call>,
    admitted: Vec<Call>,
    refusals: Vec<(usize, LimitRefusal, bool)>,
}

impl RefusalRun {
    /// Require exactly the selected initial allocation-request refusals,
    /// retaining ordinary quantum exhaustion as a separate event kind.
    pub fn request_refusals(&self, count: usize) {
        let events = self.events();
        let requests: Vec<_> = events
            .iter()
            .filter(|(call, _)| matches!(call, Call::Allocate(_)))
            .collect();
        assert!(
            requests.len() > count,
            "no allocation succeeded after refusal"
        );
        for (at, (_, injected)) in requests.iter().enumerate() {
            assert_eq!(*injected, at < count, "allocation request {at}");
        }
        let injected: Vec<_> = self.refusals.iter().filter(|r| r.2).collect();
        assert_eq!(injected.len(), count, "request injection count");
        for &(index, reason, _) in injected {
            assert_eq!(reason, LimitRefusal::Scheduled(index));
            assert!(matches!(self.calls[index], Call::Allocate(_)));
        }
    }

    /// Every successful admission is refused once before succeeding, within
    /// one retained operation. Ordinary exhaustion is separately witnessed.
    pub fn each(&self, baseline: &Self) {
        assert!(baseline.refusals.iter().all(|r| !r.2));
        baseline.events();
        let expected: Vec<_> = baseline
            .admitted
            .iter()
            .flat_map(|call| [(*call, true), (*call, false)])
            .collect();
        assert_eq!(
            self.events(),
            expected,
            "a refusal replayed or skipped work"
        );
    }

    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    pub fn admitted(&self) -> &[Call] {
        &self.admitted
    }

    pub fn into_admitted(self) -> Vec<Call> {
        self.admitted
    }

    /// Compare useful work and the selected injection, retaining the exact
    /// pre-injection attempt prefix. Later quantum boundaries may differ.
    pub fn resumed(&self, baseline: &Self, index: usize, reason: LimitRefusal) {
        self.injected_at(index, reason);
        assert_eq!(&self.calls[..=index], &baseline.calls[..=index]);
        assert!(baseline.refusals.iter().all(|r| !r.2));
        let mut expected = baseline.events();
        let before = index - baseline.refusals.iter().filter(|r| r.0 < index).count();
        expected.insert(before, (baseline.calls[index], true));
        assert_eq!(
            self.events(),
            expected,
            "resumption replayed or skipped admitted work"
        );
    }

    pub fn of(m: &Limits) -> Self {
        assert_eq!(m.calls().len(), m.attempts(), "attempt logging incomplete");
        assert_eq!(
            m.refused_calls().len(),
            m.refusals(),
            "refusal logging incomplete"
        );
        assert_eq!(m.attempts(), m.admitted().len() + m.refusals());
        assert_eq!(
            m.injected_refusals(),
            m.refused_calls().iter().filter(|r| r.2).count()
        );
        m.assert_units(TURN);
        Self {
            calls: m.calls().to_vec(),
            admitted: m.admitted().to_vec(),
            refusals: m.refused_calls().to_vec(),
        }
    }

    fn events(&self) -> Vec<(Call, bool)> {
        let mut refusals = self.refusals.iter().peekable();
        let mut events = Vec::new();
        let mut admitted = Vec::new();
        for (index, &call) in self.calls.iter().enumerate() {
            if refusals.peek().is_some_and(|r| r.0 == index) {
                let &(_, reason, injected) = refusals.next().unwrap();
                if injected {
                    events.push((call, true));
                } else {
                    assert_eq!(reason, LimitRefusal::Work, "unexpected ordinary refusal");
                    assert!(matches!(call, Call::Work { .. }));
                }
            } else {
                admitted.push(call);
                events.push((call, false));
            }
        }
        assert!(refusals.next().is_none(), "invalid refusal index");
        assert_eq!(
            admitted, self.admitted,
            "attempt/admission witnesses disagree"
        );
        events
    }

    fn injected_at(&self, index: usize, reason: LimitRefusal) {
        assert_eq!(
            self.refusals
                .iter()
                .filter(|r| r.2)
                .copied()
                .collect::<Vec<_>>(),
            vec![(index, reason, true)],
            "injection did not fire exactly as selected"
        );
    }
}

impl Fault {
    /// Nothing injected.
    pub const NONE: Self = Self {
        refusal: pipeline::Refusal::None,
        cancel: false,
    };
}

/// The fault matrix of a single resumable operation that `run` drives under
/// a [`Fault`], returning a policy-backed [`RefusalRun`]; `run` carries the
/// operation's own oracles (its output, its storage, its guards), and steps
/// it through [`checked`] and [`contracted`], so every refused step is
/// checked to leave the position unchanged and refund nothing. The
/// unobstructed run's calls are the baseline:
///
/// - every admission refused once, in one run that suspends at each from the
///   state the unrefused run reaches there: it must attempt exactly each
///   successful baseline admission twice, refused then admitted, so no completed
///   work is replayed or skipped. A second refusal of the same unit is not
///   scheduled: the refused step left the operation's position and paid work
///   unchanged, so refusing it again repeats the same transition;
/// - in the exhaustive layer, each admission also refused in a run of its
///   own, preserving the exact attempt prefix through the injection and the
///   complete successful admission sequence after resumption;
/// - a cancellation at every call: the operation dropped at its refusal, the
///   calls attempted then exactly the baseline's up to and including it. No
///   cleanup class is certified for a single operation's states, so every
///   cancellation runs in both layers.
///
/// Every stage and case is reported as it runs. Returns the baseline.
/// Ordinary Work refusals are witnessed separately and excluded only from
/// event comparison; they remain in the attempt log and cancellation domain.
pub fn refusal_matrix(
    name: &str,
    rigor: rigor::Rigor,
    run: impl Fn(Fault) -> RefusalRun,
) -> RefusalRun {
    let mut progress = rigor::Progress::new(name);
    let baseline = run(Fault::NONE);
    let ordinary = baseline.events();
    assert!(baseline.refusals.iter().all(|r| !r.2));
    progress.dimension("attempts", baseline.calls.len());
    progress.dimension("admitted calls", baseline.admitted.len());
    progress.dimension("ordinary refusals", baseline.refusals.len());
    assert!(
        !baseline.admitted.is_empty(),
        "{name}: the operation admitted nothing"
    );
    progress.stage("every admission refused in one pass", 1, 1);
    progress.case(format!("{} admissions", baseline.admitted.len()));
    run(Fault {
        refusal: pipeline::Refusal::Each,
        cancel: false,
    })
    .each(&baseline);
    if rigor == rigor::Rigor::Exhaustive {
        progress.stage(
            "each admission refused in a run of its own",
            baseline.calls.len(),
            baseline.calls.len(),
        );
        for (index, call) in baseline.calls.iter().enumerate() {
            progress.case(format!("call {index}: {call:?}"));
            let resumed = run(Fault {
                refusal: pipeline::Refusal::At(index),
                cancel: false,
            });
            resumed.resumed(&baseline, index, LimitRefusal::Scheduled(index));
        }
    }
    progress.stage(
        "a cancellation at each admission",
        baseline.calls.len(),
        baseline.calls.len(),
    );
    for (index, call) in baseline.calls.iter().enumerate() {
        progress.case(format!("call {index}: {call:?}"));
        let stopped = run(Fault {
            refusal: pipeline::Refusal::At(index),
            cancel: true,
        });
        stopped.injected_at(index, LimitRefusal::Scheduled(index));
        assert_eq!(stopped.calls, baseline.calls[..=index]);
        let before = index - baseline.refusals.iter().filter(|r| r.0 < index).count();
        let mut expected = ordinary[..before].to_vec();
        expected.push((*call, true));
        assert_eq!(
            stopped.events(),
            expected,
            "{name}: cancellation at call {index}, {call:?}, did not end the trace there"
        );
    }
    baseline
}

/// Classification stage shared by resumable refusal matrices. The retained
/// engine resumes every refusal through the same path; only the policy's
/// reported reason differs. Fast checks each reason at the final admission,
/// after all preceding work has been paid. Exhaustive checks that assumption
/// at every admission. Callers must positively observe the exact reason and
/// compare the resulting trace and outcome with the ordinary refusal run.
pub fn reason_matrix(
    name: &str,
    rigor: rigor::Rigor,
    baseline: &[Call],
    reasons: &[LimitRefusal],
    mut run: impl FnMut(usize, LimitRefusal),
) {
    assert!(!baseline.is_empty(), "{name}: no admission to refuse");
    let start = match rigor {
        rigor::Rigor::Fast => baseline.len() - 1,
        rigor::Rigor::Exhaustive => 0,
    };
    let mut progress = rigor::Progress::new(format!("{name}: refusal classification"));
    progress.stage(
        "refusal classification",
        (baseline.len() - start) * reasons.len(),
        baseline.len() * reasons.len(),
    );
    for (index, call) in baseline.iter().enumerate().skip(start) {
        for &reason in reasons {
            progress.case(format!("{reason:?} at call {index}: {call:?}"));
            run(index, reason);
        }
    }
}

/// Every physical request of an operation `run` performs, failed in a run
/// of its own: `run` is given the request to fail, or none, carries the
/// operation's own oracles for a failed run (the failure observed,
/// classified as physical, everything released), and returns the physical
/// requests the run made. Every request is failed in both layers: a
/// physical failure ends the run, and no class of the states it can end in
/// is certified. Returns the unobstructed run's requests.
pub fn physical_matrix(name: &str, run: impl Fn(Option<usize>) -> usize) -> usize {
    let mut progress = rigor::Progress::new(format!("{name}: physical failures"));
    let requests = run(None);
    progress.dimension("physical requests", requests);
    assert!(
        requests > 0,
        "{name}: the operation made no physical request"
    );
    physical_stage(&mut progress, requests, |index| {
        run(Some(index));
    });
    requests
}

/// The physical stage of a matrix: each of `requests` failed in a run of
/// its own by `run`, reported as it runs.
fn physical_stage(progress: &mut rigor::Progress, requests: usize, run: impl Fn(usize)) {
    whole_stage(
        progress,
        "each physical request failed",
        "request",
        requests,
        run,
    );
}

/// A stage no reduction covers: each of `count` cases, the `case` of its
/// index, run in a run of its own by `run` in both layers, reported as it
/// runs.
fn whole_stage(
    progress: &mut rigor::Progress,
    stage: &'static str,
    case: &str,
    count: usize,
    mut run: impl FnMut(usize),
) {
    progress.stage(stage, count, count);
    for index in 0..count {
        progress.case(format!("{case} {index}"));
        run(index);
    }
}

/// The refusal matrix of a synchronous operation, one that ends at its first
/// refusal rather than suspending: each of the unobstructed run's
/// `attempts` admissions refused in a run of its own by `run`, which carries
/// the operation's own oracles for a refused run (the refusal reported at
/// that call, nothing attempted after it, nothing held, every physical
/// request admitted). One-pass refusal does not apply, since a refused
/// synchronous operation does not resume; and no cleanup class is certified
/// for the state a synchronous call ends in, so every admission is refused
/// in both layers.
pub fn synchronous_matrix(name: &str, attempts: usize, run: impl FnMut(usize)) {
    let mut progress = rigor::Progress::new(name);
    assert!(attempts > 0, "{name}: the operation admitted nothing");
    whole_stage(
        &mut progress,
        "each admission refused, ending the operation",
        "admission",
        attempts,
        run,
    );
}

/// The stop stage of a single operation whose unobstructed run publishes
/// after `boundaries` turns: a stop after each number of turns from none
/// through publication, in a run of its own by `run`, which carries the
/// operation's own oracles for the stopped run and its cleanup. No cleanup
/// class is certified for a single operation's states, so every boundary is
/// stopped at in both layers.
pub fn stop_matrix(name: &str, boundaries: usize, run: impl FnMut(usize)) {
    let mut progress = rigor::Progress::new(name);
    whole_stage(
        &mut progress,
        "a stop after each number of turns, through publication",
        "turns",
        boundaries + 1,
        run,
    );
}

/// [`resume_within`] the general bound of [`TURNS`].
pub fn resume<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    reason: LimitRefusal,
) -> (usize, O::Output)
where
    O::Error: Debug,
{
    resume_within(m, operation, reason, TURNS)
}

/// Suspend `operation` at the injected refusal `reason`, then resume the
/// same operation to publication within `turns` fresh turns. Paid work is
/// never refunded. Returns the refused call's index and the output.
pub fn resume_within<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    reason: LimitRefusal,
    turns: usize,
) -> (usize, O::Output)
where
    O::Error: Debug,
{
    let index = suspend_within(m, operation, reason, turns, TurnSchedule::Retained);
    let paid = m.used();
    m.fail_call(None);
    let output = drive_within(m, operation, turns).expect("resumed operation failed");
    let after = m.used();
    assert!(
        after.values >= paid.values && after.bytes >= paid.bytes,
        "resumption refunded paid work"
    );
    (index, output)
}

/// One fresh checked turn of `writer`. Its chunk borrows the writer.
pub fn emit_turn<'w, I: DecodeInput<Limits>, T: InPlace<Limits>>(
    m: &mut Limits,
    writer: &'w mut OwnedWriter<'_, I, T, Limits>,
) -> BoundedResult<OwnedEmitStep<'w>, Limits> {
    // Moving the borrow into the closure lets the chunk outlive its call.
    checked(m, move |m| {
        let writer = writer;
        writer.step(m)
    })
}

/// After completion: the next step returns `Finished` and admits nothing.
pub fn emitted<I: DecodeInput<Limits>, T: InPlace<Limits>>(
    m: &mut Limits,
    writer: &mut OwnedWriter<'_, I, T, Limits>,
) {
    let attempts = m.attempts();
    assert!(
        matches!(writer.step(m), Ok(OwnedEmitStep::Finished)),
        "a completed emission stepped again"
    );
    assert_eq!(m.attempts(), attempts, "a completed emission admitted work");
}

/// Emit `writer`'s plan of `len` bytes under fresh checked turns within
/// [`emit_turns`], refusals retried: every chunk at most 64 bytes, then
/// completion. Returns the emitted bytes.
pub fn emit<I: DecodeInput<Limits>, T: InPlace<Limits>>(
    m: &mut Limits,
    writer: &mut OwnedWriter<'_, I, T, Limits>,
    len: usize,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let bound = allowed(m, emit_turns(len));
    for _ in 0..bound {
        match emit_turn(m, writer) {
            Ok(OwnedEmitStep::Progress) => {}
            Ok(OwnedEmitStep::Chunk(chunk)) => {
                assert!(chunk.len() <= 64, "chunk of {} bytes", chunk.len());
                bytes.extend_from_slice(chunk);
            }
            Ok(OwnedEmitStep::Complete) => {
                emitted(m, writer);
                assert_eq!(bytes.len(), len, "emission ended early");
                return bytes;
            }
            Ok(OwnedEmitStep::Finished) => panic!("emission finished without completing"),
            Err(error) if error.refused() => {}
            Err(error) => panic!("emission failed: {error:?}"),
        }
    }
    panic!("emission exceeded its bound of {bound} turns");
}

/// A typed operation whose lifecycle position becomes the admission trace's
/// context before each step, so a trace names where every call was made.
pub struct Traced<O>(pub O);

impl<P, O> Resumable<Limits> for Traced<O>
where
    P: Clone + PartialEq + Debug,
    O: Resumable<Limits, Position = TypedPosition<P>>,
{
    type Output = O::Output;
    type Error = O::Error;
    type Position = TypedPosition<P>;

    fn step(&mut self, m: &mut Limits) -> Result<Step<O::Output>, O::Error> {
        m.trace_mut().context(self.0.position());
        self.0.step(m)
    }

    fn position(&mut self) -> TypedPosition<P> {
        self.0.position()
    }
}

/// Drive `operation` to its output, then retire it. Retiring a retained
/// operation releases no storage synchronously, whatever the outcome.
pub fn settle<O: Resumable<Limits>>(m: &mut Limits, operation: O) -> Result<O::Output, O::Error>
where
    O::Error: Debug,
{
    settle_within(m, operation, TURNS)
}

/// Bound-aware owned counterpart of `drive_within`, including the retirement
/// oracle. Used by every concrete owned-operation convenience function.
pub fn settle_within<O: Resumable<Limits>>(
    m: &mut Limits,
    mut operation: O,
    bound: usize,
) -> Result<O::Output, O::Error>
where
    O::Error: Debug,
{
    let output = drive_within(m, &mut operation, allowed(m, bound));
    let releases = ReleaseWitness::capture(m);
    drop(operation);
    assert!(
        releases.unchanged(m),
        "retiring an operation released storage synchronously"
    );
    output
}

/// Initialize `owner` under fresh checked turns, refusals retried. A failed
/// physical allocation is the only error returned; the owner then holds no
/// scope. Any other error is a defect.
pub fn initialize(
    owner: &mut DecodeOwner<'_, Limits>,
    m: &mut Limits,
) -> Result<(), BoundedError<LimitRefusal>> {
    let bound = allowed(
        m,
        turns(
            dcbor::bounded::decode::construction::scope_bound::<Limits, ()>()
                .expect("scope bound fits in u64"),
        ),
    );
    for _ in 0..bound {
        match checked(m, |m| owner.initialize_step(m)) {
            Ok(()) => return Ok(()),
            Err(error) => match error.class() {
                Class::Refused(_) => {}
                Class::Allocation => return Err(error),
                Class::Invalid | Class::Defect => {
                    panic!("scope initialization failed: {error:?}")
                }
            },
        }
    }
    panic!("scope initialization exceeded {bound} turns");
}

/// An initialized scope; refusals retried.
pub fn scope<'s>(m: &mut Limits) -> DecodeOwner<'s, Limits> {
    let mut owner = DecodeOwner::new();
    initialize(&mut owner, m).expect("scope allocation failed");
    owner
}

/// The units one record's acquisition admits (`stable::acquire`, through
/// `DecodeOwner::allocate_step`): its metadata's write, its release, then its
/// allocation, each within a quantum and kept across a refusal, so each
/// needs at most one fresh turn.
const ACQUISITION_UNITS: usize = 3;

/// A record of `T` acquired in `owner`'s scope under fresh turns, refusals
/// retried, `acquisition` keeping what each refused attempt admitted.
pub fn acquire<'s, T>(
    owner: &DecodeOwner<'s, Limits>,
    m: &mut Limits,
    acquisition: &mut Acquisition<'s, T, Limits>,
) -> dcbor::bounded::decode::construction::OwnedRecord<'s, T, Limits>
where
    T: Reclaim<Limits> + Send + 's,
    T::State: Send,
{
    for _ in 0..allowed(m, ACQUISITION_UNITS) {
        m.turn();
        match owner.allocate_step(m, acquisition) {
            Ok(record) => return record,
            Err(BoundedError::Refused(_)) => {}
            Err(error) => panic!("record acquisition failed: {error:?}"),
        }
    }
    panic!("record acquisition exceeded its {ACQUISITION_UNITS} units");
}

/// An initialized scope over `wire` and its borrowed input handle.
pub fn open<'s>(m: &mut Limits, wire: &'s [u8]) -> (DecodeOwner<'s, Limits>, Input<'s>) {
    let owner = scope(m);
    let bound = turns(
        dcbor::bounded::decode::construction::borrow_bound::<Limits, ()>()
            .expect("borrow bound fits in u64"),
    );
    let input = settle_within(m, owner.borrow_input(wire), bound).expect("borrowed input failed");
    (owner, input)
}

/// A copied input handle in `owner`'s scope.
pub fn copy<'s>(
    owner: &DecodeOwner<'s, Limits>,
    m: &mut Limits,
    bytes: &[u8],
) -> OwnedInitialized<'s, ByteString, Limits> {
    let bound = turns(
        dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(bytes.len() as u64)
            .expect("copy bound fits in u64"),
    );
    settle_within(m, owner.copy_input(bytes), bound).expect("copied input failed")
}

/// The parsed document of `input`.
pub fn parse<'s, I: DecodeInput<Limits> + 's>(
    m: &mut Limits,
    input: OwnedInitialized<'s, I, Limits>,
    options: Options,
) -> Result<OwnedDocument<'s, I, Limits>, DecodeError<LimitRefusal>> {
    let bound = turns(
        dcbor::bounded::decode::construction::parse_bound::<I, Limits, ()>(
            input.value().bytes().len() as u64,
            options,
        )
        .expect("parse bound fits in u64"),
    );
    settle_within(m, DocumentDecoder::parse(input, options), bound)
}

/// An initialized scope over `wire` and its parsed document.
pub fn document<'s>(
    m: &mut Limits,
    wire: &'s [u8],
    options: Options,
) -> (
    DecodeOwner<'s, Limits>,
    OwnedDocument<'s, Borrowed<'s>, Limits>,
) {
    let (owner, input) = open(m, wire);
    let document = parse(m, input, options).expect("literal document failed to parse");
    (owner, document)
}

/// `T` constructed from `document`.
pub fn construct<'s, I: DecodeInput<Limits> + 's, T: Transferable<Limits> + 's>(
    m: &mut Limits,
    document: OwnedDocument<'s, I, Limits>,
) -> Result<TypedValue<'s, I, T, Limits>, DecodeError<LimitRefusal>> {
    let bound = turns(
        dcbor::bounded::decode::construction::construction_bound::<I, T, Limits, ()>(
            document.bytes().len() as u64,
        )
        .expect("construction bound fits in u64"),
    );
    settle_within(m, Construction::construct(document), bound)
}

/// `T` decoded from `input`.
pub fn decode<'s, I: DecodeInput<Limits> + 's, T: Transferable<Limits> + 's>(
    m: &mut Limits,
    input: OwnedInitialized<'s, I, Limits>,
    options: Options,
) -> Result<TypedValue<'s, I, T, Limits>, DecodeError<LimitRefusal>> {
    let bound = turns(
        dcbor::bounded::decode::construction::typed_decode_bound::<I, T, Limits, ()>(
            input.value().bytes().len() as u64,
            options,
        )
        .expect("typed decode bound fits in u64"),
    );
    settle_within(m, TypedDecoder::new(input, options), bound)
}

/// Shut the scope down under fresh turns, refusals retried, and require that
/// every reservation it ever made was released.
/// A scope may contain arbitrary external Reclaim records, whose contract
/// declares no total cleanup bound. This generic helper consequently retains
/// the emergency bound; individual operation cleanup uses its own bound.
pub fn drain(owner: &mut DecodeOwner<'_, Limits>, m: &mut Limits) {
    for _ in 0..TURNS {
        match checked(m, |m| owner.shutdown_step(m)) {
            Ok(Reclaimed::Done) => return,
            Ok(Reclaimed::Progress) | Ok(Reclaimed::Waiting) => {}
            Err(BoundedError::Refused(_)) => {}
            Err(error) => panic!("cleanup failed: {error:?}"),
        }
    }
    panic!("shutdown exceeded {TURNS} turns");
}

/// An input whose cleanup is observable: its bytes, its own reservation, and
/// a release counter, each released in its own admitted unit.
pub struct Instrumented {
    bytes: Vec<u8>,
    permit: Option<<Limits as Allocator>::Permit>,
    released: Arc<AtomicUsize>,
}

// SAFETY: the bytes are never mutated after initialization.
unsafe impl DecodeInput<Limits> for Instrumented {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// What an [`Instrumented`] input still owns, field by field, in the order
/// its cleanup releases them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InputPhase {
    /// Nothing initialized.
    Empty,
    /// Every field owned.
    Owned,
    /// The byte buffer released.
    BytesReleased,
    /// The reservation released.
    PermitReleased,
    /// The observation handle released: nothing remains.
    Released,
}

/// The phase is the input's whole custody: each names exactly the fields
/// still owned.
impl Custody for InputPhase {
    type Observation = Self;

    fn observe(&mut self) -> Self {
        *self
    }
}

// SAFETY: the phase records exactly which fields are owned; each cleanup
// unit releases one field in admitted order. No cleanup path invokes Drop on
// the whole value or reads payload bytes.
unsafe impl Reclaim<Limits> for Instrumented {
    type State = InputPhase;
    const INITIAL: InputPhase = InputPhase::Empty;

    #[expect(
        clippy::disallowed_methods,
        reason = "a custom input resource admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        phase: &mut InputPhase,
        a: &mut Limits,
    ) -> BoundedResult<Reclaimed, Limits> {
        let raw = place.as_ptr().cast::<Self>();
        *phase = match *phase {
            InputPhase::Empty | InputPhase::Released => {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                return Ok(Reclaimed::Done);
            }
            InputPhase::Owned => {
                a.traverse(1, size_of::<Vec<u8>>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe { core::ptr::drop_in_place(core::ptr::addr_of_mut!((*raw).bytes)) };
                InputPhase::BytesReleased
            }
            InputPhase::BytesReleased => {
                a.traverse(1, size_of::<Option<<Limits as Allocator>::Permit>>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe { core::ptr::drop_in_place(core::ptr::addr_of_mut!((*raw).permit)) };
                InputPhase::PermitReleased
            }
            InputPhase::PermitReleased => {
                a.traverse(1, size_of::<Arc<AtomicUsize>>() as u64)
                    .map_err(BoundedError::Refused)?;
                unsafe {
                    (*raw).released.fetch_add(1, Ordering::SeqCst);
                    core::ptr::drop_in_place(core::ptr::addr_of_mut!((*raw).released));
                }
                InputPhase::Released
            }
        };
        Ok(if *phase == InputPhase::Released {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }

    /// One call per field still owned, the last reporting `Done`; one for a
    /// record holding nothing.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, phase: &mut InputPhase) -> u64 {
        match *phase {
            InputPhase::Empty | InputPhase::Released => 1,
            InputPhase::Owned => 3,
            InputPhase::BytesReleased => 2,
            InputPhase::PermitReleased => 1,
        }
    }
}

/// An instrumented input holding `wire`, initialized through the custom
/// resource-binding interface. `released` counts its completed cleanups.
#[expect(
    clippy::disallowed_methods,
    reason = "a custom input resource admits its record's initialization, as \
              `OwnedRecord::destination` documents"
)]
pub fn instrumented<'s>(
    owner: &DecodeOwner<'s, Limits>,
    m: &mut Limits,
    wire: &[u8],
    released: &Arc<AtomicUsize>,
) -> OwnedInitialized<'s, Instrumented, Limits> {
    m.open();
    let mut input = owner
        .allocate_step::<Instrumented>(m, &mut Acquisition::new())
        .expect("input record");
    let bytes = wire.to_vec();
    let permit = m
        .allocate(bytes.capacity() as u64)
        .expect("input reservation");
    m.traverse(1, size_of::<Instrumented>() as u64)
        .expect("input initialization");
    // SAFETY: admitted initialization at the record's final address; the
    // phase records ownership of every field immediately after.
    unsafe {
        let (place, phase) = input.destination();
        place.as_ptr().write(MaybeUninit::new(Instrumented {
            bytes,
            permit: Some(permit),
            released: released.clone(),
        }));
        *phase = InputPhase::Owned;
        input.publish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Multiple retained admissions in one step force ordinary exhaustion
    /// before the selected injection. No allocation or engine fixture can
    /// obscure the scheduler's own accounting in this control.
    #[derive(Default)]
    struct RetainedAdmissions(usize);

    struct PrepaidRelease {
        permit: Option<dcbor::bounded::Reservation>,
        complete: bool,
    }

    impl Resumable<Limits> for PrepaidRelease {
        type Output = ();
        type Error = BoundedError<LimitRefusal>;
        type Position = (bool, bool);

        #[expect(
            clippy::disallowed_methods,
            reason = "harness control admits its final transition"
        )]
        fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
            if self.permit.is_some() {
                drop(self.permit.take());
                return Ok(Step::Progress);
            }
            if self.complete {
                return Ok(Step::Finished);
            }
            m.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.complete = true;
            Ok(Step::Complete(()))
        }

        fn position(&mut self) -> Self::Position {
            (self.permit.is_some(), self.complete)
        }
    }

    #[test]
    fn repeated_turn_observes_prepaid_release_without_inventing_a_refusal() {
        let mut m = Limits::unlimited().logged().strict();
        let mut operation = PrepaidRelease {
            permit: Some(m.allocate(8).unwrap()),
            complete: false,
        };
        m.measure();
        assert_eq!(
            repeated_turn(&mut m, &mut operation, 3).unwrap(),
            Step::Progress
        );
        assert_eq!(m.live_bytes(), 0);
        assert_eq!(m.attempts(), 0);
        assert_eq!(m.injected_refusals(), 0);
        assert_eq!(
            repeated_turn(&mut m, &mut operation, 3).unwrap(),
            Step::Complete(())
        );
        assert_eq!(m.injected_refusals(), 3);
        assert_eq!(m.attempts(), 4);
        assert_eq!(m.used(), WriteWork::new(1, 0));
    }

    struct ReleaseAction<F>(Option<F>);

    impl<F: FnOnce()> Resumable<Limits> for ReleaseAction<F> {
        type Output = ();
        type Error = BoundedError<LimitRefusal>;
        type Position = bool;

        fn step(&mut self, _: &mut Limits) -> Result<Step<()>, Self::Error> {
            self.0.take().unwrap()();
            Ok(Step::Progress)
        }

        fn position(&mut self) -> bool {
            self.0.is_some()
        }
    }

    #[test]
    fn local_release_is_witnessed_when_another_worker_increases_live_storage() {
        let mut m = heap::observe_releases(Limits::unlimited());
        let mut other = m.share();
        let permit = m.allocate(8).unwrap();
        let live = m.live_bytes();
        let mut held = None;
        let mut operation = ReleaseAction(Some(|| {
            held = Some(
                std::thread::spawn(move || other.allocate(16).unwrap())
                    .join()
                    .unwrap(),
            );
            drop(permit);
        }));
        checked(&mut m, |m| contracted(m, &mut operation)).unwrap();
        drop(operation);
        assert_eq!(m.live_bytes(), live + 8);
        drop(held);
        assert_eq!(m.live_bytes(), 0);
    }

    #[test]
    #[should_panic(expected = "reported progress without an admission or a prepaid release")]
    fn another_workers_release_cannot_witness_local_progress() {
        let mut m = heap::observe_releases(Limits::unlimited());
        let permit = m.share().allocate(8).unwrap();
        checked(&mut m, |_| {
            std::thread::spawn(move || drop(permit)).join().unwrap();
            Step::<()>::Progress
        });
    }

    #[test]
    #[should_panic(expected = "progress without an admission or a prepaid release")]
    fn contracted_rejects_another_workers_release_as_local_progress() {
        let mut m = heap::observe_releases(Limits::unlimited());
        let permit = m.share().allocate(8).unwrap();
        let mut operation = ReleaseAction(Some(|| {
            std::thread::spawn(move || drop(permit)).join().unwrap();
        }));
        contracted(&mut m, &mut operation).unwrap();
    }

    #[test]
    fn reservation_transfers_do_not_invent_release_events() {
        let mut m = heap::observe_releases(Limits::unlimited());
        let mut permit = m.allocate(8).unwrap();
        let before = heap::reservation_releases();
        drop(permit.split(0).unwrap());
        let split = permit.split(3).unwrap();
        permit.merge(split).unwrap();
        assert_eq!(heap::reservation_releases(), before);
        let split = permit.split(3).unwrap();
        drop(m);
        drop(split);
        assert_eq!(heap::reservation_releases(), before.wrapping_add(1));
        drop(permit);
        assert_eq!(heap::reservation_releases(), before.wrapping_add(2));
    }

    #[test]
    fn shared_capacity_is_never_overcommitted_by_competing_admissions() {
        const WORKERS: usize = 8;
        let pool = Limits::new(u64::MAX, u64::MAX, 1);
        let barrier = std::sync::Barrier::new(WORKERS);
        std::thread::scope(|scope| {
            for _ in 0..WORKERS {
                let mut m = pool.share();
                let barrier = &barrier;
                scope.spawn(move || {
                    let mut exact = true;
                    for _ in 0..64 {
                        barrier.wait();
                        let permit = m.allocate(1);
                        // Every successful reservation remains held until all
                        // workers have attempted their competing admission.
                        barrier.wait();
                        let live = m.live_bytes();
                        barrier.wait();
                        drop(permit);
                        exact &= live == 1;
                    }
                    assert!(exact, "competing admissions overcommitted shared capacity");
                });
            }
        });
        assert_eq!(pool.peak_bytes(), 1);
        assert_eq!(pool.live_bytes(), 0);
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "policy contract control admits known work"
    )]
    fn shared_storage_does_not_claim_aggregate_work_request_or_deadline_authority() {
        let mut parent = Limits::new(0, 0, 8).requesting_at_most(0);
        parent.deadline(Some(0));
        let mut first = parent.share();
        let mut second = parent.share();
        first.traverse(1, 64).unwrap();
        second.traverse(1, 64).unwrap();
        let held = first.allocate(8).unwrap();
        assert_eq!(second.allocate(1).unwrap_err(), LimitRefusal::Storage);
        assert_eq!(parent.used(), WriteWork::new(0, 0));
        assert_eq!(first.used(), WriteWork::new(1, 64));
        assert_eq!(second.used(), WriteWork::new(1, 64));
        assert_eq!(parent.requested_bytes(), 0);
        assert_eq!(first.requested_bytes(), 8);
        assert_eq!(parent.live_bytes(), 8);
        drop(held);
        drop(second.allocate(8).unwrap());
        assert_eq!(parent.live_bytes(), 0);
        assert_eq!(parent.peak_bytes(), 8);
    }

    impl Resumable<Limits> for RetainedAdmissions {
        type Output = ();
        type Error = BoundedError<LimitRefusal>;
        type Position = usize;

        #[expect(
            clippy::disallowed_methods,
            reason = "harness control admits explicit retained units"
        )]
        fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
            if self.0 == 3 {
                return Ok(Step::Finished);
            }
            for bytes in [64, 16, 1].into_iter().skip(self.0) {
                m.traverse(1, bytes).map_err(BoundedError::Refused)?;
                self.0 += 1;
            }
            Ok(Step::Complete(()))
        }

        fn position(&mut self) -> usize {
            self.0
        }
    }

    #[test]
    fn refusal_matrix_distinguishes_retained_admissions_from_attempts() {
        let baseline = refusal_matrix(
            "retained admission harness control",
            rigor::Rigor::Exhaustive,
            |fault| {
                let mut m = Limits::unlimited().logged().strict();
                refuse(&mut m, fault.refusal);
                let mut operation = RetainedAdmissions::default();
                let turns = allowed(&m, 4);
                let result = drive_faulted(&mut m, &mut operation, turns, fault.cancel).unwrap();
                assert_eq!(result.is_none(), fault.cancel);
                RefusalRun::of(&m)
            },
        );
        assert_eq!(baseline.calls.len(), 4);
        assert_eq!(baseline.admitted.len(), 3);
        assert_eq!(baseline.refusals, [(1, LimitRefusal::Work, false)]);
    }

    #[test]
    fn owned_emission_bound_accounts_for_each_injected_refusal() {
        let text = "x".repeat(130);
        let wire = dcbor::CBOR::from(text.clone()).to_cbor_data();
        let run = |refusal| {
            let mut m = Limits::unlimited().logged().strict();
            let mut owner = scope(&mut m);
            let input = copy(&owner, &mut m, &wire);
            let value = decode::<_, String>(&mut m, input, Options::normalizing(8)).unwrap();
            let bound = turns(
                dcbor::bounded::encoding::owned_prepare_bound::<ByteString, String, Limits, ()>(
                    shape(value.value()),
                )
                .unwrap(),
            );
            let plan = drive_within(
                &mut m,
                &mut dcbor::bounded::encoding::OwnedPreparation::prepare(value),
                bound,
            )
            .unwrap();
            let mut writer = plan.into_writer();
            m.measure();
            refuse(&mut m, refusal);
            assert_eq!(emit(&mut m, &mut writer, wire.len()), wire);
            let run = RefusalRun::of(&m);
            m.fail_call(None);
            m.clear_refusal();
            drop(writer);
            drain(&mut owner, &mut m);
            assert_eq!(m.live_bytes(), 0);
            run
        };
        let baseline = run(pipeline::Refusal::None);
        run(pipeline::Refusal::Each).each(&baseline);
    }

    #[test]
    fn cancellation_waits_for_injected_work_after_ordinary_exhaustion() {
        let mut m = Limits::unlimited().logged().strict();
        refuse(&mut m, pipeline::Refusal::For(3, LimitRefusal::Work));
        let mut operation = RetainedAdmissions::default();
        let mut ordinary = Vec::new();
        assert_eq!(
            drive_faulted_observed(&mut m, &mut operation, 4, true, |m, _, _| {
                ordinary.push(ordinary_exhaustion(
                    m,
                    &BoundedError::Refused(LimitRefusal::Work),
                ));
            })
            .unwrap(),
            None
        );
        assert_eq!(ordinary, [true, false]);
        assert_eq!(operation.position(), 2);
        assert_eq!(
            m.refused_calls(),
            [
                (1, LimitRefusal::Work, false),
                (3, LimitRefusal::Work, true)
            ]
        );
        assert_eq!(m.injected_refusals(), 1);
        assert_eq!(m.scheduled_refusals(), 0);
        assert_eq!(m.used(), WriteWork::new(2, 80));
        drive_within(&mut m, &mut operation, 1).unwrap();
        assert_eq!(m.used(), WriteWork::new(3, 81));
    }

    #[test]
    #[should_panic(expected = "attempt/admission witnesses disagree")]
    fn refusal_accounting_rejects_a_planted_missing_admission() {
        let mut m = Limits::unlimited().logged().strict();
        drive_within(&mut m, &mut RetainedAdmissions::default(), 4).unwrap();
        let mut run = RefusalRun::of(&m);
        run.admitted.remove(0);
        run.events();
    }

    #[global_allocator]
    static HEAP: heap::Heap = heap::Heap;

    struct AllocatingObserver;

    impl Custody for AllocatingObserver {
        type Observation = u8;

        fn observe(&mut self) -> u8 {
            // The allocation is freed before returning: equal observations
            // and unchanged live-byte totals alone cannot detect this defect.
            drop(std::hint::black_box(Box::new(7u8)));
            0
        }
    }

    #[test]
    #[should_panic(expected = "observing changed physical storage")]
    fn transient_observer_allocation_is_rejected() {
        let observer = heap::Observation::begin(None);
        observer.stop();
        observe_custody(
            &mut AllocatingObserver,
            &Limits::unlimited(),
            &observer,
            "planted observer",
        );
    }

    /// An operation whose one unit of work is a byte wider than a turn's
    /// quantum.
    struct Wide;

    impl Resumable<Limits> for Wide {
        type Output = ();
        type Error = BoundedError<LimitRefusal>;
        type Position = usize;

        #[expect(
            clippy::disallowed_methods,
            reason = "a unit no turn admits, admitted directly as the stall it shows"
        )]
        fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
            m.traverse(1, TURN.bytes + 1)
                .map_err(BoundedError::Refused)?;
            Ok(Step::Complete(()))
        }

        fn position(&mut self) -> usize {
            0
        }
    }

    /// A unit no turn admits fails at its first refusal, named, instead of
    /// being retried until the turn bound is spent.
    #[test]
    #[should_panic(
        expected = "call 0: an indivisible unit of 1 values and 65 bytes exceeds a \
                               turn's quantum"
    )]
    fn a_unit_wider_than_a_turn_stalls_at_once() {
        let mut m = Limits::unlimited();
        let _ = drive(&mut m, &mut Wide);
    }
}

/// The owned pipeline in one scope, observed end to end: input acquisition,
/// then either inspection of the parsed document or typed decoding, owned
/// preparation and chunked emission. Every turn is observed by the physical
/// heap observer, and every observed boundary can be a stop. Physical
/// failures are injected and observed only when the binary installs
/// [`heap::Heap`] as its global allocator.
pub mod pipeline {
    use super::*;
    use crate::classes::{Class, Classes, Typed};
    use crate::rigor::{Progress, Rigor};
    use dcbor::bounded::encoding::OwnedPreparation;
    use std::panic::AssertUnwindSafe;

    /// What the pipeline decodes under.
    const OPTIONS: Options = Options::normalizing(16);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Phase {
        Scope,
        Input,
        /// Parsing a document to inspect.
        Inspect,
        Decode,
        Prepare,
        Plan,
        Emit,
    }

    /// What happens at the selected boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Stop {
        /// The consumer drops what it holds.
        Retire,
        /// The consumer's frame unwinds.
        Unwind,
        /// The consumer cancels the operation in progress and steps its
        /// operation-local cleanup to `Finished`, then drops it. A boundary
        /// with no operation in progress retires instead.
        Cancel,
    }

    /// A private, zero-sized payload distinguishes scheduled unwinding from
    /// production panics. `resume_unwind` exercises real stack unwinding and
    /// panicking destructors without invoking the diagnostic panic hook.
    struct ConsumerUnwind;

    fn consumer_unwind() -> ! {
        std::panic::resume_unwind(Box::new(ConsumerUnwind))
    }

    /// How a run refuses admissions: never, every admission once (each
    /// refused at its first attempt and admitted at its retry), the attempted
    /// call of one index as a scheduled refusal, or the attempted call of one
    /// index for a given reason (a work, storage or deadline refusal), which
    /// the engine must treat as any other refusal.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Refusal {
        None,
        Each,
        At(usize),
        For(usize, LimitRefusal),
    }

    /// What one run of the pipeline injects: its refusals, the physical
    /// request it fails, and the boundary it stops at; and whether it
    /// observes its operations' positions, to class boundaries and check
    /// each step's contract, or reads none, as the no-effect check runs it.
    #[derive(Clone, Copy, Debug)]
    pub struct Schedule {
        pub refusal: Refusal,
        pub physical: Option<usize>,
        pub stop: Option<(Phase, usize, Stop)>,
        pub observed: bool,
    }

    impl Schedule {
        /// Nothing injected, every position observed.
        pub const BASELINE: Self = Self {
            refusal: Refusal::None,
            physical: None,
            stop: None,
            observed: true,
        };
    }

    /// One observed boundary, a possible stop: its phase, its turn in the
    /// phase, and the cleanup class of the state it reached, when one is
    /// certified ([`classes`]).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Boundary {
        pub phase: Phase,
        pub turn: usize,
        pub class: Option<Class>,
        /// Policy and heap cursors at the boundary, used to resolve replay
        /// indices to their phase and occurrence without interpreting Debug.
        pub attempts: usize,
        pub physical: usize,
    }

    struct Context {
        m: Limits,
        heap: heap::Observation,
        boundaries: Vec<Boundary>,
        stop: Option<(Phase, usize, Stop)>,
        /// The schedule's refusals, applied when the measured part of the
        /// run begins ([`Self::arm`]).
        refusal: Refusal,
        armed: bool,
        /// The admitted calls made before the selected stop: the stop's
        /// cleanup is every call after them.
        stopped_at: Option<usize>,
        /// Positions are read ([`Schedule::observed`]).
        observed: bool,
    }

    /// How a phase ended short of rejecting its input: its operation's
    /// output, a stop at a boundary, or a physical allocation failure.
    enum Phased<T> {
        Published(T),
        Stopped,
        Failed,
    }

    impl<T> Phased<T> {
        /// The output, or how the pipeline ended without one.
        fn published(self) -> Result<T, Reached> {
            match self {
                Self::Published(output) => Ok(output),
                Self::Stopped => Err(Reached::Stopped),
                Self::Failed => Err(Reached::Failed),
            }
        }
    }

    impl Context {
        /// Record boundary `turn` of `phase`, the state there of cleanup
        /// class `class`, and what the consumer does there: unwinding
        /// happens here; retirement and cancellation are returned for the
        /// caller to perform.
        fn boundary(&mut self, phase: Phase, turn: usize, class: Option<Class>) -> Option<Stop> {
            self.boundaries.push(Boundary {
                phase,
                turn,
                class,
                attempts: self.m.attempts(),
                physical: self.heap.snapshot().calls,
            });
            match self.stop {
                Some((at, stop_turn, stop)) if at == phase && stop_turn == turn => {
                    self.stopped_at = Some(self.m.admitted().len());
                    if stop == Stop::Unwind {
                        self.heap.stop();
                        consumer_unwind();
                    }
                    Some(stop)
                }
                _ => None,
            }
        }

        /// Begin the measured part of the run: from here on the schedule's
        /// refusals apply. Setup a pipeline does not put under test (a
        /// custom input installed through the public resource-binding
        /// interface) runs before, its calls then forgotten by `measure`.
        fn arm(&mut self) {
            assert!(!self.armed, "a run is armed once");
            self.armed = true;
            refuse(&mut self.m, self.refusal);
        }

        /// The turns an operation bounded by `turns` may take under this
        /// run's refusals ([`super::allowed`]).
        fn allowed(&self, turns: usize) -> usize {
            super::allowed(&self.m, turns)
        }

        /// Drop `value`, observed: retirement allocates nothing and releases
        /// no storage synchronously.
        fn retire<T>(&mut self, value: T) {
            let live = self.m.live_bytes();
            let calls = self.heap.snapshot().calls;
            self.heap.window(|| drop(value));
            assert_eq!(self.heap.snapshot().calls, calls, "retirement allocated");
            assert_eq!(self.m.live_bytes(), live, "retirement released storage");
        }

        /// The operation `make` builds, constructed allocation-free, then
        /// driven to its output through at most `turns` observed checked
        /// turns, each a boundary of `phase` whose state `classify` classes;
        /// `cancel` cancels it. Stopped at a boundary or failed physically,
        /// each its own end; a cancelled or failed operation first runs its
        /// own cleanup to `Finished`, which allocates nothing. An invalid
        /// input is reported as `Err`.
        fn phase<O: Resumable<Limits>>(
            &mut self,
            phase: Phase,
            turns: usize,
            make: impl FnOnce() -> O,
            classify: impl Fn(&O::Position) -> Option<Class>,
            cancel: impl FnOnce(&mut O),
        ) -> Result<Phased<O::Output>, Invalid>
        where
            O::Error: Debug,
        {
            let calls = self.heap.snapshot().calls;
            let mut operation = self.heap.window(make);
            assert_eq!(
                self.heap.snapshot().calls,
                calls,
                "{phase:?} constructor allocated"
            );
            let mut cancel = Some(cancel);
            let observed = self.observed;
            // Every operation's bound covers its own cleanup, after a
            // cancellation or a failure alike.
            let cleanup = self.allowed(turns);
            for at in 0..self.allowed(turns) {
                // The controller moves between storage locations every turn:
                // nothing it retains may depend on its own address.
                let mut moved = Some(operation);
                operation = moved.take().expect("the controller was just moved in");
                let class = if observed {
                    classify(&operation.position())
                } else {
                    None
                };
                match self.boundary(phase, at, class) {
                    Some(Stop::Retire) => {
                        self.retire(operation);
                        return Ok(Phased::Stopped);
                    }
                    Some(Stop::Cancel) => {
                        if let Some(cancel) = cancel.take() {
                            cancel(&mut operation);
                        }
                        let calls = self.heap.snapshot().calls;
                        self.heap
                            .window(|| wound(&mut self.m, &mut operation, cleanup, observed));
                        assert_eq!(
                            self.heap.snapshot().calls,
                            calls,
                            "{phase:?} cancellation allocated"
                        );
                        self.retire(operation);
                        return Ok(Phased::Stopped);
                    }
                    Some(Stop::Unwind) | None => {}
                }
                let step = self
                    .heap
                    .window(|| turn(&mut self.m, &mut operation, observed));
                match step {
                    Ok(Step::Progress) => {}
                    Ok(Step::Complete(output)) => {
                        self.heap
                            .window(|| ended(&mut self.m, &mut operation, observed));
                        self.retire(operation);
                        return Ok(Phased::Published(output));
                    }
                    Ok(Step::Finished) => panic!("{phase:?} finished without publication"),
                    // The outcome taxonomy's class, not a stop class: the
                    // module's `Class` names the latter.
                    Err(error) => match error.class() {
                        dcbor::bounded::Class::Refused(_) => refused(&self.m, &mut operation),
                        dcbor::bounded::Class::Allocation => {
                            self.heap
                                .window(|| wound(&mut self.m, &mut operation, cleanup, observed));
                            self.retire(operation);
                            return Ok(Phased::Failed);
                        }
                        dcbor::bounded::Class::Invalid => {
                            self.heap
                                .window(|| wound(&mut self.m, &mut operation, cleanup, observed));
                            self.retire(operation);
                            return Err(Invalid);
                        }
                        dcbor::bounded::Class::Defect => panic!("{phase:?} failed: {error:?}"),
                    },
                }
            }
            panic!("{phase:?} exceeded its bound of {turns} turns");
        }
    }

    /// The input is rejected.
    struct Invalid;

    /// How far the pipeline went.
    enum Reached {
        /// The selected end was reached with the input's exact bytes.
        Complete,
        /// Stopped at a boundary.
        Stopped,
        /// A physical allocation failed.
        Failed,
        /// The input was rejected.
        Invalid,
    }

    /// The scope and the input copied into it, its boundaries classed by
    /// `input`, or how the pipeline stopped.
    fn acquired<'s>(
        context: &mut Context,
        owner: &mut DecodeOwner<'s, Limits>,
        wire: &[u8],
        input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
    ) -> Result<OwnedInitialized<'s, ByteString, Limits>, Reached> {
        // The whole run is measured, the scope's initialization included.
        context.arm();
        // Before the scope exists nothing is held: no class covers it.
        if context.boundary(Phase::Scope, 0, None).is_some() {
            return Err(Reached::Stopped);
        }
        match context.heap.window(|| initialize(owner, &mut context.m)) {
            Ok(()) => {}
            Err(BoundedError::Allocation { .. }) => return Err(Reached::Failed),
            Err(error) => panic!("scope failed: {error:?}"),
        }
        let bound =
            dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(wire.len() as u64)
                .expect("the copy bound of an input held in memory fits in u64");
        match context.phase(
            Phase::Input,
            super::turns(bound),
            || owner.copy_input(wire),
            input,
            |operation| operation.cancel(),
        ) {
            Ok(phased) => {
                let input = phased.published()?;
                assert_eq!(input.value().data(), wire, "the copy differs");
                Ok(input)
            }
            Err(Invalid) => panic!("copying an input rejected it"),
        }
    }

    /// Acquisition alone: the copied input is retired once published.
    fn acquisition(
        context: &mut Context,
        owner: &mut DecodeOwner<'_, Limits>,
        wire: &[u8],
        classes: &Classes<()>,
    ) -> Reached {
        match acquired(context, owner, wire, classes.input) {
            Ok(input) => {
                context.retire(input);
                Reached::Complete
            }
            Err(reached) => reached,
        }
    }

    /// Acquisition, then the parsed document inspected in place without
    /// allocating, then retired.
    fn inspection(
        context: &mut Context,
        owner: &mut DecodeOwner<'_, Limits>,
        wire: &[u8],
        classes: &Classes<()>,
    ) -> Reached {
        let input = match acquired(context, owner, wire, classes.input) {
            Ok(input) => input,
            Err(reached) => return reached,
        };
        let bound = dcbor::bounded::decode::construction::parse_bound::<ByteString, Limits, ()>(
            wire.len() as u64,
            OPTIONS,
        )
        .expect("the parse bound of an input held in memory fits in u64");
        let document = match context.phase(
            Phase::Inspect,
            super::turns(bound),
            || DocumentDecoder::parse(input, OPTIONS),
            classes.parse,
            |operation| operation.cancel(),
        ) {
            Ok(phased) => match phased.published() {
                Ok(document) => document,
                Err(reached) => return reached,
            },
            Err(Invalid) => return Reached::Invalid,
        };
        let calls = context.heap.snapshot().calls;
        context.heap.window(|| {
            document.with_document(|view| assert_eq!(view.root().encoded(), wire));
            assert_eq!(document.root().encoded(), wire);
            assert_eq!(document.bytes(), wire);
        });
        assert_eq!(context.heap.snapshot().calls, calls, "inspection allocated");
        context.retire(document);
        Reached::Complete
    }

    /// Acquisition, typed decoding of `T`, owned preparation and emission,
    /// the emitted chunks appended to `output`.
    fn encoding<T>(
        context: &mut Context,
        owner: &mut DecodeOwner<'_, Limits>,
        wire: &[u8],
        output: &mut Vec<u8>,
        classes: &Classes<Typed<T>>,
    ) -> Reached
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        let input = match acquired(context, owner, wire, classes.input) {
            Ok(input) => input,
            Err(reached) => return reached,
        };
        let bound =
            dcbor::bounded::decode::construction::typed_decode_bound::<ByteString, T, Limits, ()>(
                wire.len() as u64,
                OPTIONS,
            )
            .expect("the typed decode bound of an input held in memory fits in u64");
        let value = match context.phase(
            Phase::Decode,
            super::turns(bound),
            || TypedDecoder::<_, T, Limits>::new(input, OPTIONS),
            classes.decode,
            |operation| operation.cancel(),
        ) {
            Ok(phased) => match phased.published() {
                Ok(value) => value,
                Err(reached) => return reached,
            },
            Err(Invalid) => return Reached::Invalid,
        };
        // Its shape is walked unmetered, outside the observation.
        let shape = super::shape(value.value());
        let bound =
            dcbor::bounded::encoding::owned_prepare_bound::<ByteString, T, Limits, ()>(shape)
                .expect("the preparation bound of a decoded value fits in u64");
        // No cleanup argument covers a preparation's states: every one of
        // its boundaries is its own class.
        let plan = match context.phase(
            Phase::Prepare,
            super::turns(bound),
            || OwnedPreparation::prepare(value),
            |_| None,
            |operation| operation.cancel(),
        ) {
            Ok(phased) => match phased.published() {
                Ok(plan) => plan,
                Err(reached) => return reached,
            },
            Err(Invalid) => panic!("a decoded value was rejected by its preparation"),
        };
        // A published value is canonical: its encoding is the input.
        assert_eq!(plan.len(), wire.len());
        if context.boundary(Phase::Plan, 0, None).is_some() {
            context.retire(plan);
            return Reached::Stopped;
        }
        let calls = context.heap.snapshot().calls;
        let mut writer = context.heap.window(|| plan.into_writer());
        assert_eq!(
            context.heap.snapshot().calls,
            calls,
            "writer constructor allocated"
        );
        for turn in 0..context.allowed(emit_turns(wire.len())) {
            // A writer holds no operation in progress: every stop retires it.
            // No cleanup argument covers its states: each is its own class.
            if context.boundary(Phase::Emit, turn, None).is_some() {
                context.retire(writer);
                return Reached::Stopped;
            }
            let step = {
                let _armed = context.heap.armed();
                emit_turn(&mut context.m, &mut writer)
            };
            match step {
                Ok(OwnedEmitStep::Progress) => {}
                Ok(OwnedEmitStep::Chunk(chunk)) => {
                    assert!(chunk.len() <= 64);
                    output.extend_from_slice(chunk);
                }
                Ok(OwnedEmitStep::Complete) => {
                    context.heap.window(|| emitted(&mut context.m, &mut writer));
                    context.retire(writer);
                    return Reached::Complete;
                }
                Ok(OwnedEmitStep::Finished) => panic!("emission finished without completing"),
                Err(error) if error.refused() => {}
                Err(error) => panic!("emission failed: {error:?}"),
            }
        }
        panic!("emission exceeded {} turns", emit_turns(wire.len()));
    }

    /// A custom input installed through the public resource-binding
    /// interface ([`instrumented`]), then decoded as `T` under `options`,
    /// its boundaries classed by `classes`; the published value, whose
    /// address moving its handle never changes, is given to `inspect` and
    /// retired. The scope and the input are setup the pipeline does not put
    /// under test: they run before the measured part begins, and the
    /// schedule's refusals and failures reach the decode alone. Neither
    /// publication nor retirement releases the input.
    fn decoding<T: Transferable<Limits> + 'static>(
        context: &mut Context,
        owner: &mut DecodeOwner<'static, Limits>,
        wire: &[u8],
        options: Options,
        classes: &Classes<Typed<T>>,
        released: &Arc<AtomicUsize>,
        inspect: impl FnOnce(&T),
    ) -> Reached {
        initialize(owner, &mut context.m).expect("an unobserved scope allocates");
        let input = instrumented(owner, &mut context.m, wire, released);
        context.m.measure();
        context.arm();
        let bound = dcbor::bounded::decode::construction::typed_decode_bound::<
            Instrumented,
            T,
            Limits,
            (),
        >(wire.len() as u64, options)
        .expect("the typed decode bound of an input held in memory fits in u64");
        let value = match context.phase(
            Phase::Decode,
            super::turns(bound),
            || TypedDecoder::<_, T, Limits>::new(input, options),
            classes.decode,
            |operation| operation.cancel(),
        ) {
            Ok(phased) => match phased.published() {
                Ok(value) => value,
                Err(reached) => return reached,
            },
            Err(Invalid) => return Reached::Invalid,
        };
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "publication released the input"
        );
        let address = value.value() as *const T;
        let mut moved = Some(value);
        let value = moved.take().expect("the handle was just moved in");
        assert_eq!(
            value.value() as *const T,
            address,
            "moving the handle moved the value"
        );
        inspect(value.value());
        context.retire(value);
        assert_eq!(
            released.load(Ordering::SeqCst),
            0,
            "retirement ran input destruction"
        );
        Reached::Complete
    }

    pub struct Report {
        /// The same authoritative refusal accounting used by single-operation
        /// matrices, including ordinary exhaustion and injection provenance.
        pub accounting: RefusalRun,
        pub attempts: usize,
        /// All policy refusals, including exhaustion of a fresh turn while
        /// retaining acquisition admissions. `refused` counts injections only.
        pub refusals: usize,
        pub refused: usize,
        pub physical: usize,
        pub denied: usize,
        /// Every observed boundary, in order: each is a possible stop.
        pub boundaries: Vec<Boundary>,
        /// The admitted calls after the selected stop: its cleanup, through
        /// the drain. Empty when no stop was reached.
        pub cleanup: Vec<Call>,
        /// The selected end was reached with the input's exact bytes.
        pub complete: bool,
        /// The input was rejected while parsing or decoding.
        pub invalid: bool,
        /// The requested retirement, cancellation, or unwind boundary was reached.
        pub stopped: bool,
        pub failed: bool,
        /// Queue draining begins after the pipeline's last live boundary.
        pub drain_attempt: usize,
    }

    impl Report {
        fn admission_name(&self, index: usize) -> String {
            let call = self
                .accounting
                .calls()
                .get(index)
                .expect("a selected admission exists");
            if index >= self.drain_attempt {
                return format!(
                    "drain admission {}: {call:?} (replay {index})",
                    index - self.drain_attempt
                );
            }
            let boundary = self
                .boundaries
                .iter()
                .rev()
                .find(|boundary| boundary.attempts <= index)
                .expect("a measured admission has a pipeline boundary");
            let first = self
                .boundaries
                .iter()
                .find(|candidate| candidate.phase == boundary.phase)
                .expect("the phase has an initial boundary");
            format!(
                "{:?} admission {}, turn {}, {call:?}, class {:?} (replay {index})",
                boundary.phase,
                index - first.attempts,
                boundary.turn,
                boundary.class
            )
        }

        fn physical_name(&self, index: usize) -> String {
            let boundary = self
                .boundaries
                .iter()
                .rev()
                .find(|boundary| boundary.physical <= index)
                .expect("a measured physical request has a pipeline boundary");
            let first = self
                .boundaries
                .iter()
                .find(|candidate| candidate.phase == boundary.phase)
                .expect("the phase has an initial boundary");
            format!(
                "{:?} physical request {}, turn {}, class {:?} (replay {index})",
                boundary.phase,
                index - first.physical,
                boundary.turn,
                boundary.class
            )
        }
    }

    /// Run `body` in one scope under observation, injecting what `schedule`
    /// names, then drain the scope: draining allocates nothing and recovers
    /// every reservation, every admission fits one quantum, and no physical
    /// allocation was unadmitted.
    fn observe(
        wire: &[u8],
        schedule: &Schedule,
        body: impl FnOnce(&mut Context, &mut DecodeOwner<'static, Limits>, &mut Vec<u8>) -> Reached,
    ) -> Report {
        let observation = heap::Observation::begin(schedule.physical);
        observation.stop();
        let stop = schedule.stop;
        let mut context = Context {
            m: observed(),
            heap: observation,
            boundaries: Vec::new(),
            stop,
            refusal: schedule.refusal,
            armed: false,
            stopped_at: None,
            observed: schedule.observed,
        };
        let mut owner = DecodeOwner::new();
        // Bookkeeping storage exists before the first observed turn.
        let mut output = Vec::with_capacity(wire.len());
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
            body(&mut context, &mut owner, &mut output)
        }));
        let reached = match outcome {
            Ok(reached) => reached,
            Err(payload) => {
                if !matches!(stop, Some((_, _, Stop::Unwind))) || !payload.is::<ConsumerUnwind>() {
                    std::panic::resume_unwind(payload);
                }
                assert!(
                    context.stopped_at.is_some(),
                    "unwind boundary was not reached"
                );
                Reached::Stopped
            }
        };
        let calls = context.heap.snapshot().calls;
        let drain_attempt = context.m.attempts();
        context.heap.window(|| drain(&mut owner, &mut context.m));
        assert_eq!(context.heap.snapshot().calls, calls, "drain allocated");
        assert_eq!(context.m.live_bytes(), 0);
        let stats = context.heap.snapshot();
        assert_eq!(stats.unadmitted, 0, "physical allocation without admission");
        assert!(!stats.overflow, "heap observation incomplete");
        let complete = matches!(reached, Reached::Complete);
        let accounting = RefusalRun::of(&context.m);
        let cleanup = context
            .stopped_at
            .map_or_else(Vec::new, |at| accounting.admitted()[at..].to_vec());
        Report {
            accounting,
            attempts: context.m.attempts(),
            refusals: context.m.refusals(),
            refused: context.m.injected_refusals(),
            physical: stats.calls,
            denied: stats.denied,
            boundaries: context.boundaries,
            cleanup,
            complete,
            invalid: matches!(reached, Reached::Invalid),
            stopped: matches!(reached, Reached::Stopped),
            failed: matches!(reached, Reached::Failed),
            drain_attempt,
        }
    }

    /// Copy `wire`, which may be any bytes, into a scope, observed
    /// ([`observe`]), its boundaries classed by `classes`; complete once the
    /// published copy equals it.
    pub fn acquire(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
        observe(wire, schedule, |context, owner, _| {
            acquisition(context, owner, wire, classes)
        })
    }

    /// Copy `wire` and parse it to a document inspected in place, observed
    /// ([`observe`]), its boundaries classed by `classes`; complete once the
    /// document's root is the input.
    pub fn inspect(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
        observe(wire, schedule, |context, owner, _| {
            inspection(context, owner, wire, classes)
        })
    }

    /// Copy `wire`, decode it as `T`, prepare the value's encoding owned and
    /// emit it, observed ([`observe`]), its boundaries classed by `classes`;
    /// complete once the emitted bytes are the input, as every canonical
    /// input's are.
    pub fn encode<T>(wire: &[u8], schedule: &Schedule, classes: &Classes<Typed<T>>) -> Report
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        observe(wire, schedule, |context, owner, output| {
            let reached = encoding::<T>(context, owner, wire, output, classes);
            if matches!(reached, Reached::Complete) {
                assert_eq!(output.as_slice(), wire, "emission diverged from the input");
            }
            reached
        })
    }

    /// Decode `wire`, which may be any bytes, as `T` under `options` from a
    /// custom input ([`decoding`]), observed ([`observe`]), its boundaries
    /// classed by `classes`, a published value given to `inspect`. The
    /// drain releases the input exactly once.
    pub fn decode<T: Transferable<Limits> + 'static>(
        wire: &[u8],
        options: Options,
        schedule: &Schedule,
        classes: &Classes<Typed<T>>,
        inspect: impl FnOnce(&T),
    ) -> Report {
        let released = Arc::new(AtomicUsize::new(0));
        let report = observe(wire, schedule, |context, owner, _| {
            decoding::<T>(context, owner, wire, options, classes, &released, inspect)
        });
        assert_eq!(
            released.load(Ordering::SeqCst),
            1,
            "the drain did not release the input exactly once"
        );
        report
    }

    /// Observation without effect: `schedule` run again reading no position
    /// (no boundary classed, no step's contract checked through its
    /// position) reaches the report `observed` did: the same admission
    /// trace, attempts, refusals, physical requests and failures, outcome,
    /// boundaries by phase and turn, and cleanup. Observing a position
    /// admits nothing, allocates nothing and changes nothing an operation
    /// then does.
    fn unaffected(
        run: &impl Fn(&Schedule) -> Report,
        schedule: &Schedule,
        observed: &Report,
        at: &str,
    ) {
        let unobserved = run(&Schedule {
            observed: false,
            ..*schedule
        });
        assert_eq!(
            unobserved.accounting, observed.accounting,
            "{at}: observing positions changed admission or refusal accounting"
        );
        assert_eq!(
            unobserved.drain_attempt, observed.drain_attempt,
            "{at}: observing positions changed retirement timing"
        );
        assert_eq!(
            (
                unobserved.attempts,
                unobserved.refusals,
                unobserved.refused,
                unobserved.physical,
                unobserved.denied
            ),
            (
                observed.attempts,
                observed.refusals,
                observed.refused,
                observed.physical,
                observed.denied
            ),
            "{at}: observing positions changed the run's counts"
        );
        assert_eq!(
            (
                unobserved.complete,
                unobserved.invalid,
                unobserved.stopped,
                unobserved.failed
            ),
            (
                observed.complete,
                observed.invalid,
                observed.stopped,
                observed.failed
            ),
            "{at}: observing positions changed the outcome"
        );
        let turns = |report: &Report| {
            report
                .boundaries
                .iter()
                .map(|boundary| {
                    (
                        boundary.phase,
                        boundary.turn,
                        boundary.attempts,
                        boundary.physical,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            turns(&unobserved),
            turns(observed),
            "{at}: observing positions changed the boundaries"
        );
        assert_eq!(
            unobserved.cleanup, observed.cleanup,
            "{at}: observing positions changed the cleanup"
        );
    }

    /// What the unobstructed pipeline reaches, and so every refused run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Expected {
        /// The selected end, with the input's exact bytes.
        Complete,
        /// The input rejected.
        Invalid,
    }

    impl Expected {
        #[track_caller]
        fn reached(self, report: &Report, run: &str) {
            assert!(!report.failed, "{run}: failed physically");
            assert!(!report.stopped, "{run}: stopped");
            match self {
                Self::Complete => assert!(
                    report.complete && !report.invalid,
                    "{run}: did not complete"
                ),
                Self::Invalid => assert!(
                    report.invalid && !report.complete,
                    "{run}: was not rejected"
                ),
            }
        }
    }

    /// The fault matrix of the pipeline `run` carries out, which reaches
    /// `expected` unobstructed, under `rigor` ([`crate::rigor`]):
    ///
    /// - every admission refused once, in one run that suspends at each from
    ///   the state the unrefused run reaches there: the refused attempts are
    ///   exactly the unrefused run's admissions, the admitted trace is the
    ///   unrefused run's, and the outcome is unchanged. The exhaustive layer
    ///   also refuses each admission in a run of its own;
    /// - every physical request failed in a run of its own, observed,
    ///   classified as a physical failure, and published nothing;
    /// - a retire, an unwind and a cancellation at boundaries: the fast layer
    ///   stops at the first boundary of each certified class and at every
    ///   boundary of none; the exhaustive layer stops at every boundary and
    ///   requires every member of a class to clean up with exactly the
    ///   admitted calls its first member made;
    /// - observation without effect ([`unaffected`]): a schedule run again
    ///   reading no position reaches the same report. The fast layer checks
    ///   the unobstructed run and the one-pass refusal, which together reach
    ///   every admission; the exhaustive layer every schedule it runs.
    ///
    /// Every stage and case is reported as it runs.
    pub fn matrix(name: &str, rigor: Rigor, expected: Expected, run: impl Fn(&Schedule) -> Report) {
        let mut progress = Progress::new(name);
        let baseline = run(&Schedule::BASELINE);
        expected.reached(&baseline, "unobstructed");
        progress.dimension("attempts", baseline.attempts);
        progress.dimension("admitted calls", baseline.accounting.admitted().len());
        progress.dimension("policy refusals", baseline.refusals);
        progress.dimension("physical requests", baseline.physical);
        progress.dimension("boundaries", baseline.boundaries.len());
        progress.dimension(
            "classes",
            baseline
                .boundaries
                .iter()
                .filter_map(|boundary| boundary.class.as_ref())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
        );
        progress.dimension(
            "unclassified boundaries",
            baseline
                .boundaries
                .iter()
                .filter(|boundary| boundary.class.is_none())
                .count(),
        );
        crate::rigor::classes(
            name,
            baseline
                .boundaries
                .iter()
                .map(|boundary| match &boundary.class {
                    Some(class) => format!("{:?}: {class}", boundary.phase),
                    None => format!("unclassified {:?} turn {}", boundary.phase, boundary.turn),
                }),
        );
        assert_eq!(baseline.refused, 0);
        unaffected(&run, &Schedule::BASELINE, &baseline, "unobstructed");
        let each = Schedule {
            refusal: Refusal::Each,
            ..Schedule::BASELINE
        };
        progress.stage("every admission refused in one pass", 1, 1);
        progress.case(format!(
            "{} admissions",
            baseline.accounting.admitted().len()
        ));
        let refused = run(&each);
        assert_eq!(
            refused.refused,
            baseline.accounting.admitted().len(),
            "not every admission was refused exactly once"
        );
        refused.accounting.each(&baseline.accounting);
        expected.reached(&refused, "every admission refused once");
        unaffected(&run, &each, &refused, "every admission refused once");
        let exhaustive = rigor == Rigor::Exhaustive;
        if exhaustive {
            progress.stage(
                "each admission refused in a run of its own",
                baseline.attempts,
                baseline.attempts,
            );
            for index in 0..baseline.attempts {
                let at = baseline.admission_name(index);
                progress.case(&at);
                let schedule = Schedule {
                    refusal: Refusal::At(index),
                    ..Schedule::BASELINE
                };
                let resumed = run(&schedule);
                assert_eq!(resumed.refused, 1, "{at}: refusal unobserved");
                resumed.accounting.resumed(
                    &baseline.accounting,
                    index,
                    LimitRefusal::Scheduled(index),
                );
                expected.reached(&resumed, &at);
                unaffected(&run, &schedule, &resumed, &at);
            }
        }
        super::physical_stage(&mut progress, baseline.physical, |index| {
            let at = baseline.physical_name(index);
            eprintln!("[{name}] {at}");
            let schedule = Schedule {
                physical: Some(index),
                ..Schedule::BASELINE
            };
            let failed = run(&schedule);
            assert_eq!(failed.denied, 1, "{at}: failure unobserved");
            assert!(failed.failed, "{at}: failure misclassified");
            assert!(!failed.complete, "{at}: published after failure");
            if exhaustive {
                unaffected(&run, &schedule, &failed, &at);
            }
        });
        let mut first = std::collections::BTreeSet::new();
        let selected: Vec<&Boundary> = baseline
            .boundaries
            .iter()
            .filter(|boundary| match (&boundary.class, rigor) {
                (_, Rigor::Exhaustive) | (None, Rigor::Fast) => true,
                (Some(class), Rigor::Fast) => first.insert(class.clone()),
            })
            .collect();
        const STOPS: [Stop; 3] = [Stop::Retire, Stop::Unwind, Stop::Cancel];
        progress.stage(
            "stops",
            selected.len() * STOPS.len(),
            baseline.boundaries.len() * STOPS.len(),
        );
        // Every classed stop, keyed by its class and kind of stop, with the
        // cleanup it made: members of one class must clean up alike.
        let mut members = Vec::new();
        for boundary in selected {
            for stop in STOPS {
                let at = format!(
                    "{stop:?} at {:?} {}, class {:?}",
                    boundary.phase, boundary.turn, boundary.class
                );
                progress.case(&at);
                let schedule = Schedule {
                    stop: Some((boundary.phase, boundary.turn, stop)),
                    ..Schedule::BASELINE
                };
                let stopped = run(&schedule);
                assert!(stopped.stopped, "{at}: not reached");
                assert!(
                    !stopped.failed && !stopped.invalid,
                    "{at}: changed the outcome"
                );
                assert!(!stopped.complete, "{at}: published");
                if exhaustive {
                    unaffected(&run, &schedule, &stopped, &at);
                }
                if let Some(class) = &boundary.class {
                    members.push((at, (class.clone(), format!("{stop:?}")), stopped.cleanup));
                }
            }
        }
        super::agree(name, members);
    }

    #[cfg(test)]
    mod accounting_tests {
        use super::*;

        #[test]
        fn pipeline_counts_injections_independently_of_refusal_reason() {
            let classes = Classes::certified();
            let baseline = inspect(&[0], &Schedule::BASELINE, &classes);
            assert!(baseline.complete);
            assert_eq!(baseline.refused, 0);
            for reason in [
                LimitRefusal::Work,
                LimitRefusal::Storage,
                LimitRefusal::Deadline,
                LimitRefusal::Scheduled(0),
            ] {
                let report = inspect(
                    &[0],
                    &Schedule {
                        refusal: Refusal::For(0, reason),
                        ..Schedule::BASELINE
                    },
                    &classes,
                );
                assert!(report.complete, "{reason:?}: pipeline did not complete");
                assert_eq!(report.refused, 1, "{reason:?}: injection was not counted");
                report.accounting.resumed(&baseline.accounting, 0, reason);
            }
        }
    }

    #[cfg(test)]
    mod unwind_tests {
        use super::*;

        #[test]
        fn consumer_unwind_runs_destructors_while_panicking() {
            struct Witness<'a>(&'a std::cell::Cell<bool>);
            impl Drop for Witness<'_> {
                fn drop(&mut self) {
                    self.0.set(std::thread::panicking());
                }
            }
            let witnessed = std::cell::Cell::new(false);
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let _witness = Witness(&witnessed);
                consumer_unwind();
            }));
            assert!(result.unwrap_err().is::<ConsumerUnwind>());
            assert!(witnessed.get(), "consumer frame did not unwind");
        }

        #[test]
        #[should_panic(expected = "unexpected production panic")]
        fn scheduled_unwind_does_not_accept_a_production_panic() {
            observe(
                &[],
                &Schedule {
                    stop: Some((Phase::Scope, 0, Stop::Unwind)),
                    ..Schedule::BASELINE
                },
                |_, _, _| panic!("unexpected production panic"),
            );
        }
    }
}
