//! The shared public-boundary driver for deterministic tests and lifecycle
//! fuzzing. Every retained operation is driven through [`Resumable`], and
//! every step is checked against its contract: admission before work, no
//! refund, at most one quantum per turn, no progress without an admission, a
//! prepaid release or a retained admission spent, a refused unit that alone
//! leaves the position unchanged, and nothing after publication. Scope setup, input handles, retirement and drain build on it.
//! Unsafe code here implements an instrumented input resource, never a
//! decoder. Compiled once as the `dcbor-test-support` crate and shared by
//! every integration test and fuzz target; [`heap`] is the physical heap
//! observer, [`legality`] holds the bindings' successor relations,
//! [`model`] configures every model of a checker build, and [`budgets`]
//! sizes the recordings of the fixtures that outgrow [`CAPACITY`].
pub mod budgets;
pub mod classes;
pub mod heap;
pub mod legality;
pub mod model;
pub mod reclamation;
pub mod rigor;

use core::fmt::Debug;
use core::mem::{MaybeUninit, size_of};
use dcbor::ByteString;
use dcbor::bounded::boundary::Reached as Valuations;
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::in_place::{
    BufferObservation, Entry, InPlace, Session, Stage, Transferable,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot,
};
use dcbor::bounded::decode::construction::{
    Acquisition, Borrowed, Construction, DecodeInput, DecodeOwner, DocumentDecoder, InputDetail,
    OwnedDocument, OwnedInitialized, OwnedRecord, Position, TypedDecoder, TypedPosition,
    TypedValue,
};
use dcbor::bounded::encoding::{OwnedEmitStep, OwnedWriter};
use dcbor::bounded::{
    Admission, Answer, BoundedError, BoundedResult, Call, Capacity, Class, Custodial, CustodySink,
    Event, Failure, Hold, Identity, LimitRefusal, Limits, Observed, Performer, PermitsObserved,
    Releasing, Resumable, Step, TURN, WriteWork,
};
use dcbor_refinement as refinement;

/// A recording session ([`dcbor::bounded::Session`]), named apart from the
/// construction session ([`Session`]) a root binding runs in.
type Recording = dcbor::bounded::Session;
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

/// What one recording session observes completely: every permit record and
/// every event slot of one run, its setup and its drain included. Allocated
/// whole when the run begins, before any heap observation, so recording
/// never allocates while the observer is armed: observation infrastructure,
/// apart from every policy's live-storage capacity. A run that exceeds it
/// makes its session invalid: the first history read of it panics naming
/// the session, and its evidence is refused, never a short history. The
/// library's one default ([`Capacity::DEFAULT`]), which its own tests share.
pub const CAPACITY: Capacity = Capacity::DEFAULT;

/// The recording capacity of a workload measured to record `events`
/// observations and claim `permits` permit records (each grant and each
/// split child, the records a finished session holds): each the next power
/// of two at or above the measurement and a quarter more, never below
/// [`CAPACITY`]'s. A workload whose recording grows past its margin
/// exhausts its session, which refuses its evidence by name: its
/// measurement is taken again and its budget restated, never raised
/// blindly. Every budget stays preallocated whole before the run, as
/// [`CAPACITY`] is: an event slot is 15 words, 120 bytes on a 64-bit target.
const fn measured(events: usize, permits: usize) -> Capacity {
    const fn budget(measured: usize, floor: usize) -> usize {
        let Some(padded) = measured.checked_add(measured.div_ceil(4)) else {
            panic!("recording budget margin overflows usize");
        };
        let Some(budget) = padded.checked_next_power_of_two() else {
            panic!("recording budget rounding overflows usize");
        };
        if budget < floor { floor } else { budget }
    }
    Capacity {
        permits: budget(permits, CAPACITY.permits),
        events: budget(events, CAPACITY.events),
    }
}

/// The policy every recorded run makes, the one construction of it: a new
/// family recorded in `session` with `capacity` live bytes, refusals strict,
/// releases witnessed on this thread (the admission oracle's); with
/// `physical`, each admitted allocation also reported to the heap observer,
/// which matches it against the physical requests an armed observation
/// sees. Configured whole before any reservation or share can escape.
fn recorded_policy(session: &Recording, capacity: u64, physical: bool) -> Limits {
    recorded_allowance(
        session,
        WriteWork::new(u64::MAX, u64::MAX),
        capacity,
        physical,
    )
}

fn recorded_allowance(
    session: &Recording,
    work: WriteWork,
    capacity: u64,
    physical: bool,
) -> Limits {
    let limits =
        heap::observe_releases(Limits::recorded(work.values, work.bytes, capacity, session))
            .strict();
    if physical {
        limits.observe(heap::admitted)
    } else {
        limits
    }
}

/// What a run's finalization requires of the refinement machine: the
/// protocol refined, or, for a negative control over a complete recording,
/// exactly this divergence.
#[derive(Clone, Copy, Debug)]
enum ExpectedVerdict {
    Accepted,
    Rejected(refinement::Divergence),
}

/// What a recording finished as ([`finalize`]), the one result every
/// finalization consumes: its evidence refused, naming why (a family,
/// permit, held obligation or owner of it still alive, its capacity
/// exhausted, an incompatible pairing of policy and owner, or an unpublished
/// slot); or its whole stream, with the refinement machine's verdict on it
/// and the checkpoints, and whether the checkpoints' storage held no more
/// than their changes ([`refinement::History::storage`]).
enum Finalized {
    /// Refused, naming why and, for an invalid session, what first
    /// invalidated it ([`dcbor::bounded::Invalidation`]).
    Refused(
        dcbor::bounded::Incomplete,
        Option<dcbor::bounded::Invalidation>,
    ),
    Finished {
        observed: Vec<Observed>,
        verdict: Result<(), refinement::Divergence>,
        storage: Result<(), String>,
    },
}

/// `observed` and `checkpoints` through the refinement machine: the one
/// call of [`refinement::History::settled`] in this crate, the permit, obligation,
/// admission and custody lifecycle every recorded stream is held to.
fn refine(
    observed: &[Observed],
    checkpoints: &refinement::History,
) -> Result<(), refinement::Divergence> {
    checkpoints.settled(observed)
}

/// `session` finished once nothing that can publish into it lives, and,
/// when it finishes, its stream and `checkpoints` refined ([`refine`]) and
/// the checkpoints' storage held to their changes
/// ([`refinement::History::storage`]): the one completion of every
/// recording, so every checkpoint any recorded run takes, in any workload,
/// is stored within its edits. Never panics; what the result means is its
/// consumers' ([`settled`], [`describe`]).
fn finalize(session: Recording, checkpoints: &refinement::History) -> Finalized {
    let cause = session.invalidation();
    match session.finish() {
        Err(incomplete) => Finalized::Refused(incomplete, cause),
        Ok(observed) => {
            let verdict = refine(&observed, checkpoints);
            Finalized::Finished {
                observed,
                verdict,
                storage: checkpoints.storage(),
            }
        }
    }
}

/// What `finalized` was, described: the report beside a run's own
/// findings ([`recorded_run`]).
fn describe(finalized: &Finalized) -> String {
    match finalized {
        Finalized::Refused(incomplete, None) => {
            format!("the recording is no evidence: {incomplete:?}")
        }
        Finalized::Refused(incomplete, Some(cause)) => {
            format!("the recording is no evidence: {incomplete:?}, first by {cause:?}")
        }
        Finalized::Finished {
            verdict: Ok(()),
            storage: Ok(()),
            ..
        } => "the recording finished and refined the protocol".to_string(),
        Finalized::Finished {
            verdict: Ok(()),
            storage: Err(excess),
            ..
        } => format!(
            "the recording finished and refined the protocol, and its checkpoint storage \
             exceeds its edits: {excess}"
        ),
        Finalized::Finished {
            verdict: Err(divergence),
            ..
        } => format!("the recording finished and does not refine the protocol: {divergence}"),
    }
}

/// The machine's verdict `actual` on `observed` held to `expected`: an
/// unexpected divergence panics naming it and the observation it was found
/// at; an expected one must match in location and rule; an expected
/// rejection the machine accepts panics.
fn enforce(
    observed: &[Observed],
    actual: Result<(), refinement::Divergence>,
    expected: ExpectedVerdict,
) {
    match (expected, actual) {
        (ExpectedVerdict::Accepted, Ok(())) => {}
        (ExpectedVerdict::Rejected(expected), Err(actual)) => {
            assert_eq!(
                actual, expected,
                "the control must fail at its intended location and rule"
            );
        }
        (ExpectedVerdict::Rejected(expected), Ok(())) => {
            panic!("the control unexpectedly refined the protocol: {expected}");
        }
        (ExpectedVerdict::Accepted, Err(divergence)) => {
            panic!(
                "the run's recording does not refine the protocol: {}",
                located(observed, divergence)
            );
        }
    }
}

/// `divergence` named with the observation it was found at, when it was
/// found at one: the one rendering of an unexpected divergence ([`enforce`],
/// [`refinement_of_words`]).
fn located(observed: &[Observed], divergence: refinement::Divergence) -> String {
    match divergence.at {
        refinement::At::Observation(index) => observed.get(index).map_or_else(
            || divergence.to_string(),
            |observation| format!("{divergence}: {}", refinement::render_observed(observation)),
        ),
        _ => divergence.to_string(),
    }
}

/// A recorded stream that crossed a build boundary as each observation's
/// storage-form words (a `dcbor` unit test handing its session's stream to
/// this crate, which links its own build of `dcbor`:
/// `Observed::to_words`), read back whole and refined by the one
/// finalization's checker ([`refine`], no checkpoints): the verdict as
/// data, never a panic, so a caller holding findings of its own reports
/// them beside it (`construction::findings` in `dcbor`). Err names the
/// index of words that are no observation, or the divergence and the
/// observation it was found at, as [`enforce`] names them.
pub fn refinement_of_words(words: &[[u64; dcbor::bounded::OBSERVED_WORDS]]) -> Result<(), String> {
    let mut observed = Vec::with_capacity(words.len());
    for (index, words) in words.iter().enumerate() {
        observed.push(
            Observed::from_words(words).ok_or_else(|| {
                format!("observation {index}: words of no observation: {words:?}")
            })?,
        );
    }
    refine(&observed, &refinement::History::new()).map_err(|divergence| {
        format!(
            "the recording does not refine the protocol: {}",
            located(&observed, divergence)
        )
    })
}

/// [`refinement_of_words`], acceptance required: panics naming its finding.
/// A model's stream (`dcbor`'s `sync::models`), which holds no findings of
/// its own.
pub fn refine_words(words: &[[u64; dcbor::bounded::OBSERVED_WORDS]]) {
    if let Err(finding) = refinement_of_words(words) {
        panic!("{finding}");
    }
}

/// The finished evidence of `session` ([`finalize`]), held to `expected`
/// ([`enforce`]): the one finalization of every recorded run, the scoped
/// runner's ([`recorded_run`], [`recorded_control`]) and the drivers' that
/// own their session whole ([`construction_requests`], `pipeline`). An
/// incomplete recording satisfies no expectation, a rejection included;
/// checkpoints stored beyond their changes fail any run, a control's too.
fn settled(
    session: Recording,
    checkpoints: &refinement::History,
    expected: ExpectedVerdict,
) -> Vec<Observed> {
    match finalize(session, checkpoints) {
        Finalized::Refused(incomplete, None) => {
            panic!("the run's recording is no evidence: {incomplete:?}")
        }
        Finalized::Refused(incomplete, Some(cause)) => {
            panic!("the run's recording is no evidence: {incomplete:?}, first by {cause:?}")
        }
        Finalized::Finished {
            observed,
            verdict,
            storage,
        } => {
            enforce(&observed, verdict, expected);
            if let Err(excess) = storage {
                panic!("the run's checkpoint storage exceeds its edits: {excess}");
            }
            observed
        }
    }
}

/// A policy's history as its session holds it ([`corresponds`]): every
/// call attempted, the calls admitted, and each refusal by its call index,
/// its reason and whether it was injected.
type Correspondence = (Vec<Call>, Vec<Call>, Vec<(usize, LimitRefusal, bool)>);

/// The permits a session recorded granted: each answered `Granted`. What
/// a driver's own allocation record is compared against ([`legal`]).
fn grants(observed: &[Observed], by: Performer) -> usize {
    observed
        .iter()
        .filter(|observation| {
            observation.by == by
                && matches!(
                    observation.event,
                    Event::Call(Call::Allocate(_), Answer::Granted(_))
                )
        })
        .count()
}

/// Each policy's own counters agree with its recorded history: every
/// attempt, refusal and injection the policy counted is the one its family
/// published ([`Limits::history`] reads the session). The one check of a
/// policy's call correspondence, as detached data: the history, or what
/// failed, a history that cannot be read ([`dcbor::bounded::Unreadable`]: an
/// unrecorded family, a session that is no evidence) or a count the history
/// disagrees with ([`history_agrees`]). Never panics, so a finalizer can
/// read every policy, drop them all and still finish its session
/// ([`recorded_run`]).
fn correspondence(m: &Limits) -> Result<Correspondence, String> {
    // The one non-panicking read ([`Limits::history`]): an unrecorded family
    // or a session that is no evidence is a finding, never an unwind.
    let history = m
        .history()
        .map_err(|unreadable| format!("the policy's history cannot be read: {unreadable:?}"))?;
    let counts = dcbor::bounded::HistoryCounts::of(&history);
    history_agrees(
        History {
            calls: counts.calls,
            admitted: counts.admitted,
            refusals: counts.refusals,
            injected: counts.injected,
        },
        Counted {
            attempts: m.attempts(),
            refusals: m.refusals(),
            injected: m.injected_refusals(),
        },
    )?;
    let calls = history.iter().map(|&(call, _)| call).collect();
    let admitted = history
        .iter()
        .filter(|(_, answer)| !matches!(answer, Answer::Refused { .. }))
        .map(|&(call, _)| call)
        .collect();
    let refusals = history
        .iter()
        .enumerate()
        .filter_map(|(index, &(_, answer))| match answer {
            Answer::Refused { refusal, injected } => Some((index, refusal, injected)),
            _ => None,
        })
        .collect();
    Ok((calls, admitted, refusals))
}

/// What a policy's recorded history holds: its calls attempted, admitted
/// and refused, and the refusals injected. Plain counts, so a `dcbor` unit
/// test, whose `Limits` is another build's type, hands its policy's history
/// across as data ([`history_agrees`]).
#[derive(Clone, Copy, Debug)]
pub struct History {
    pub calls: usize,
    pub admitted: usize,
    pub refusals: usize,
    pub injected: usize,
}

/// What a policy's own counters hold: `Limits::attempts`, `refusals` and
/// `injected_refusals`.
#[derive(Clone, Copy, Debug)]
pub struct Counted {
    pub attempts: usize,
    pub refusals: usize,
    pub injected: usize,
}

/// The one comparison of a policy's recorded history with its own counters
/// ([`correspondence`], and `construction::findings` in `dcbor` through
/// plain counts): every attempt recorded, every refusal, every attempt
/// either admitted or refused, every injection. Err names the first
/// quantity that disagrees.
pub fn history_agrees(history: History, counted: Counted) -> Result<(), String> {
    let checks = [
        (history.calls, counted.attempts, "attempts"),
        (history.refusals, counted.refusals, "refusals"),
        (
            history.admitted + counted.refusals,
            counted.attempts,
            "admissions and refusals",
        ),
        (history.injected, counted.injected, "injected refusals"),
    ];
    for (recorded, counted, what) in checks {
        if recorded != counted {
            return Err(format!(
                "the recording holds {recorded} {what}, the policy counted {counted}"
            ));
        }
    }
    Ok(())
}

/// [`correspondence`], asserted: a driver's read of one policy whose run
/// has not yet reached its finalizer ([`RefusalRun::of`]).
fn corresponds(m: &Limits) -> Correspondence {
    correspondence(m).unwrap_or_else(|finding| panic!("{finding}"))
}

/// A policy a [`RecordedRun`] owns, by its place among the run's policies:
/// a handle of the test's own, never a family, permit or performer
/// identity, and never recorded. A handle names a policy of the run that
/// issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyId(usize);

/// A fixture-specific reading of a run's finished evidence, made once the
/// run's mandatory checks pass ([`RecordedRun::inspect_evidence`]).
type Inspection = Box<dyn FnOnce(&[Observed], &refinement::History)>;

/// One recorded run ([`recorded_run`]): its recording session, made before
/// anything runs, the policies it makes, the custody checkpoints it takes,
/// and the fixture's own readings of its evidence. Everything is private:
/// the run alone finishes the session, so no test manages evidence itself.
pub struct RecordedRun {
    session: Recording,
    policies: Vec<Limits>,
    checkpoints: refinement::History,
    inspections: Vec<Inspection>,
    defects: Vec<Finding>,
}

/// Custody retained by the run across a computation and all of its exits.
/// Nested holdings borrow their surroundings; neither needs erased owning
/// storage or an allocation inside a physical window.
pub struct Holding<'r, 's, T: Custodial<Permit>, W: pipeline::Physical> {
    run: &'r mut RecordedRun,
    surrounding: &'s mut dyn Custodial<Permit>,
    value: Held<T>,
    retirement: Retirement,
    window: &'s W,
    /// The checkpoint that observed this value as the output of the turn
    /// that published it, when a holding schedule published it
    /// ([`Self::publication`]); none for every other value. Each holding
    /// keeps its own, so a publication nested inside another's consumer
    /// names its own checkpoint, never its container's.
    publication: Option<CheckpointId>,
}

/// Parent-held worker custody: its scope, operations, and every publication.
/// Workers borrow this storage; only the enclosing run retires it after joins.
pub struct Worked<S, O: Resumable<Limits>> {
    pub scope: S,
    operations: CustodyBatch<O>,
    outputs: CustodyBatch<O::Output>,
    stopped: CustodyBatch<Publications<O::Output>>,
}

impl<S, O: Resumable<Limits>> Worked<S, O>
where
    O::Error: Debug,
{
    /// Reserve all result slots before starting workers.
    pub fn new(scope: S, cases: usize) -> Self {
        Self {
            scope,
            operations: CustodyBatch::with_capacity(cases),
            outputs: CustodyBatch::with_capacity(cases),
            stopped: CustodyBatch::with_capacity(cases),
        }
    }

    /// Retain an operation before execution and its outcome before reporting.
    pub fn drive(
        &mut self,
        m: &mut Limits,
        operation: O,
        turns: usize,
    ) -> Result<&mut O::Output, Finding> {
        let operation = self.operations.retain(operation);
        match drive_controlled(
            m,
            operation,
            Course::within(turns),
            |_, _, _| false,
            |_, _, _| {},
            &pipeline::Unwitnessed,
        ) {
            Ok(Some(output)) => Ok(self.outputs.retain(output)),
            Ok(None) => unreachable!("an uncancelled worker schedule cannot stop"),
            Err(stop) => {
                let (halt, outputs) = stop.detach();
                self.stopped.retain(outputs);
                Err(Finding::from(halt))
            }
        }
    }
}

impl<'s, O: Resumable<Limits>> Worked<DecodeOwner<'s, Limits>, O> {
    /// Initialize the worker's own scope under its policy share `m` by the
    /// one initialization schedule ([`initialize_by`]); any stop is the
    /// worker's finding, returned through its join.
    pub fn initialize(&mut self, m: &mut Limits) -> Result<(), Finding> {
        initialize_by(
            &mut self.scope,
            m,
            |_| {},
            |owner, m| checked(m, |m| owner.initialize_step(m)),
        )
        .map_err(Finding::from)
    }
}

impl<S, O> Custodial<Permit> for Worked<S, O>
where
    S: Custodial<Permit>,
    O: Resumable<Limits> + Custodial<Permit>,
    O::Output: Custodial<Permit>,
{
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        dcbor::bounded::observed_all([
            self.scope.observe_custody(sink),
            self.operations.observe_custody(sink),
            self.outputs.observe_custody(sink),
            self.stopped.observe_custody(sink),
        ])
    }
}

struct EmptyCustody;

/// Sibling custody retained together until their parent observes its
/// retirement: worker custody outside every fixture's unwind frame
/// ([`RecordedRun::workers`]), and values held side by side rather than
/// nested (two preparations taking turns, a scope's authority and the value
/// that outlives it). Each member keeps its index for the batch's life. A
/// batch lent to nested holdings ([`Holding::lending`], [`Lent`]) is filled
/// and drawn from by them ([`Holding::deposit`], [`Holding::drawn`]), every
/// member observed in their surroundings through the lent borrow. Its
/// capacity is reserved whole when it is made, so a deposit never allocates.
pub struct CustodyBatch<T> {
    members: std::cell::RefCell<Vec<Option<T>>>,
}

impl<T> CustodyBatch<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            members: std::cell::RefCell::new(Vec::with_capacity(capacity)),
        }
    }

    /// A batch of `slots` empty slots, each filled by a nested holding's
    /// deposit ([`Holding::deposit`]) and drawn from by index.
    pub fn slots(slots: usize) -> Self {
        Self {
            members: std::cell::RefCell::new((0..slots).map(|_| None).collect()),
        }
    }

    /// Register publication before any assertion or diagnostic can unwind.
    pub fn retain(&mut self, value: T) -> &mut T {
        let members = self.members.get_mut();
        members.push(Some(value));
        members
            .last_mut()
            .and_then(Option::as_mut)
            .expect("the publication was just retained")
    }

    /// Every member still held, moved out: the batch's destruction member by
    /// member ([`Holding::retire_concurrently`]).
    fn into_members(self) -> impl Iterator<Item = T> {
        self.members.into_inner().into_iter().flatten()
    }

    /// Every member still held, exclusively.
    fn held(&mut self) -> impl Iterator<Item = &mut T> {
        self.members.get_mut().iter_mut().flatten()
    }

    /// Place `value` in empty slot `index` through a shared borrow; the
    /// slots exist from the batch's making, so nothing allocates.
    fn place(&self, index: usize, value: T) {
        let mut members = self.members.borrow_mut();
        let slot = members
            .get_mut(index)
            .expect("a deposit names a slot of its batch");
        assert!(
            slot.is_none(),
            "a deposit into a slot already holding custody"
        );
        *slot = Some(value);
    }

    /// Take member `index` out through a shared borrow.
    fn take(&self, index: usize) -> T {
        self.members
            .borrow_mut()
            .get_mut(index)
            .and_then(Option::take)
            .expect("a drawn batch member is held")
    }
}

/// The batch's custody, one traversal, through a shared borrow: every member
/// still held, in index order. A batch lent to nested holdings is observed
/// in their surroundings through this borrow ([`Holding::lending`]).
impl<T: Custodial<Permit>> Custodial<Permit> for &CustodyBatch<T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        let mut members = self.members.borrow_mut();
        dcbor::bounded::observed_all(
            members
                .iter_mut()
                .flatten()
                .map(|member| member.observe_custody(sink)),
        )
    }
}

/// An owned batch's custody: its shared borrow's traversal.
impl<T: Custodial<Permit>> Custodial<Permit> for CustodyBatch<T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        <&Self as Custodial<Permit>>::observe_custody(&mut &*self, sink)
    }
}

/// A held value shared with the holdings nested in its lending
/// ([`Holding::lending`]): the lent borrow in their surroundings reports the
/// value's custody, so the view itself reports none and holds nothing to
/// release. How nested holdings reach a scope's authority ([`Scope`]) and a
/// batch they deposit into ([`Holding::deposit`]).
pub struct Lent<'v, T>(&'v T);

impl<'v, T> Lent<'v, T> {
    /// The view of `value`, for [`Holding::lending`]'s `make`.
    pub fn new(value: &'v T) -> Self {
        Self(value)
    }

    /// The shared value, for the full extent of the lending.
    pub fn get(&self) -> &'v T {
        self.0
    }
}

impl<T> Custodial<Permit> for Lent<'_, T> {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// A holding becomes empty only after explicit, observed retirement.
struct Held<T>(Option<T>);

impl<T> Held<T> {
    fn get(&mut self) -> &mut T {
        self.0
            .as_mut()
            .expect("retired custody cannot execute again")
    }
}

impl<T: Custodial<Permit>> Custodial<Permit> for Held<T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        self.0.as_mut().map_or(PermitsObserved::Complete, |value| {
            value.observe_custody(sink)
        })
    }
}

impl Custodial<Permit> for EmptyCustody {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// A borrowed view of the enclosing holdings, in nesting order.
struct Surrounding<'a, T> {
    outer: &'a mut dyn Custodial<Permit>,
    value: &'a mut T,
}

impl<T: Custodial<Permit>> Custodial<Permit> for Surrounding<'_, T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        dcbor::bounded::observed_all([
            self.outer.observe_custody(sink),
            self.value.observe_custody(sink),
        ])
    }
}

impl<T: Custodial<Permit>, W: pipeline::Physical> Holding<'_, '_, T, W> {
    /// Borrow the held value and a policy for computation, without transferring
    /// the value's destruction responsibility to the computation's frame.
    pub fn with_policy<R>(
        &mut self,
        policy: PolicyId,
        body: impl FnOnce(&mut T, &mut Limits) -> R,
    ) -> R {
        self.run
            .with_policy(policy, |policy| body(self.value.get(), policy))
    }

    /// Read or operate on the held value without moving it out of the scope.
    pub fn value(&mut self) -> &mut T {
        self.value.get()
    }

    /// Record the retirement state established by a completed operation.
    pub fn retirement(&mut self, retirement: Retirement) {
        self.retirement = retirement;
    }

    /// Observe the complete holding stack at this quiescent boundary.
    pub fn checkpoint(&mut self) {
        self.run.checkpoint(|sink| {
            dcbor::bounded::observed_all([
                self.surrounding.observe_custody(sink),
                self.value.observe_custody(sink),
            ])
        });
    }

    /// The session boundary now ([`RecordedRun::boundary`]): where a
    /// driver's mark is placed.
    pub fn boundary(&self) -> usize {
        self.run.boundary()
    }

    /// The checkpoint that observed this held value as its publisher's
    /// output, at the turn that published it, beside the operation that
    /// published it ([`Holding::drive`]); `None` for a value no holding
    /// schedule published here (a setup value, a hand-over of a value
    /// published outside a schedule, [`Self::hand_over`]).
    pub fn publication(&self) -> Option<CheckpointId> {
        self.publication
    }

    /// Hold a value made from a shared borrow of this holding's value (a
    /// writer of a held plan) until `body` exits, retiring it before the
    /// lent value can be released. The lent value stays observed, through
    /// the same shared borrow the made value holds ([`Custodial`] for
    /// `&T`), so every checkpoint and the retirement see it.
    pub fn lending<'v, U: Custodial<Permit>, R>(
        &'v mut self,
        retirement: Retirement,
        make: impl FnOnce(&'v T) -> U,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R
    where
        &'v T: Custodial<Permit>,
    {
        let Self {
            run,
            surrounding,
            value,
            window,
            ..
        } = self;
        let shared: &'v T = value.get();
        let mut lent = shared;
        let mut surrounding = Surrounding {
            outer: &mut **surrounding,
            value: &mut lent,
        };
        Holding {
            run,
            surrounding: &mut surrounding,
            value: Held(Some(make(shared))),
            retirement,
            window: *window,
            publication: None,
        }
        .execute(body)
    }

    /// Hand the custody of `output`, which the held value published, over
    /// from its publisher: the held value retired now as `retirement`
    /// ([`retired`]), observed beside `output` and its surroundings, inside
    /// the holding's physical window; then `output` held as `published` for
    /// `consume`. The output outlives its publisher. After the hand-over the
    /// held value is gone: this holding reports no custody of it, and a
    /// later execution of it fails explicitly. An output published outside a
    /// holding schedule names no publishing checkpoint
    /// ([`Holding::publication`]).
    pub fn hand_over<U: Custodial<Permit>, R>(
        &mut self,
        retirement: Retirement,
        output: U,
        published: Retirement,
        consume: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        self.handed_over(retirement, output, published, None, consume)
    }

    /// [`Self::hand_over`], the output's holding naming `publication`, the
    /// checkpoint that observed it at the turn that published it: the one
    /// hand-over, a holding schedule's ([`Self::drive`]) and a caller's.
    fn handed_over<U: Custodial<Permit>, R>(
        &mut self,
        retirement: Retirement,
        mut output: U,
        published: Retirement,
        publication: Option<CheckpointId>,
        consume: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        let publisher = self
            .value
            .0
            .take()
            .expect("a publisher is held until it hands its output over");
        retired(
            &self.run.session,
            &mut self.run.checkpoints,
            &mut self.run.defects,
            retirement,
            publisher,
            |publisher, sink| {
                dcbor::bounded::observed_all([
                    self.surrounding.observe_custody(sink),
                    output.observe_custody(sink),
                    publisher.map_or(PermitsObserved::Complete, |publisher| {
                        publisher.observe_custody(sink)
                    }),
                ])
            },
            self.window,
        );
        self.nested(output, published, publication, consume)
    }

    /// Move the held value, with its declared retirement, into a holding
    /// witnessed by `window` instead (setup done unwitnessed, the operation
    /// under test inside the armed window): a transfer, not a retirement.
    /// The new holding retires the value inside `window` when `body` exits;
    /// this holding then holds nothing and a later execution of it fails
    /// explicitly.
    pub fn witnessed<V: pipeline::Physical, R>(
        &mut self,
        window: &V,
        body: impl FnOnce(&mut Holding<'_, '_, T, V>) -> R,
    ) -> R {
        let (retirement, publication) = (self.retirement, self.publication);
        self.moved(window, |value| value, retirement, publication, body)
    }

    /// Move the held value into the custody `then` makes of it (a published
    /// input into the operation that consumes it, a plan into its writer),
    /// constructed inside the holding's physical window, and hold that as
    /// `next` declares for `body`: a transfer, never a destruction, so the
    /// moved value is not retired here. `then` only constructs: it admits
    /// and unwinds nothing. This holding then holds nothing, and a later
    /// execution of it fails explicitly.
    pub fn transfer<U: Custodial<Permit>, R>(
        &mut self,
        then: impl FnOnce(T) -> U,
        next: Retirement,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        let window = self.window;
        self.moved(
            window,
            |value| window.window(|| then(value)),
            next,
            None,
            body,
        )
    }

    /// The one move of held custody into a holding of its own
    /// ([`Self::witnessed`], [`Self::transfer`]): the value taken out, made
    /// into `U`, and held under `window` as `retirement` until `body` exits,
    /// naming `publication` ([`Self::publication`]): the moved value's own
    /// when it is the same value, none when `make` makes another.
    fn moved<U: Custodial<Permit>, V: pipeline::Physical, R>(
        &mut self,
        window: &V,
        make: impl FnOnce(T) -> U,
        retirement: Retirement,
        publication: Option<CheckpointId>,
        body: impl FnOnce(&mut Holding<'_, '_, U, V>) -> R,
    ) -> R {
        let value = self
            .value
            .0
            .take()
            .expect("a value is held until it moves out of its holding");
        Holding {
            run: &mut *self.run,
            surrounding: &mut *self.surrounding,
            value: Held(Some(make(value))),
            retirement,
            window,
            publication,
        }
        .execute(body)
    }

    /// Move the held value up into slot `index` of `batch`, a batch an
    /// enclosing holding keeps and lends to this one's surroundings
    /// ([`CustodyBatch`], [`Lent`]): a transfer, never a retirement, observed
    /// at once beside everything still held. This holding then holds nothing,
    /// and a later execution of it fails explicitly.
    pub fn deposit(&mut self, batch: &CustodyBatch<T>, index: usize) {
        let value = self
            .value
            .0
            .take()
            .expect("a deposited value is held until it moves into its batch");
        batch.place(index, value);
        self.checkpoint();
    }

    /// Draw slot `index` of `batch`, kept by an enclosing holding, into a
    /// holding nested in this one, held as `retirement` for `body`: retired
    /// when `body` exits, unless `body` deposits it back
    /// ([`Self::deposit`]). A member retired alone, beside the members still
    /// held, is drawn and not deposited.
    pub fn drawn<U: Custodial<Permit>, R>(
        &mut self,
        batch: &CustodyBatch<U>,
        index: usize,
        retirement: Retirement,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        let value = batch.take(index);
        self.holding(value, retirement, body)
    }

    /// Retain a child until its computation exits, retiring it before the
    /// enclosing custody can be released.
    pub fn holding<U: Custodial<Permit>, R>(
        &mut self,
        value: U,
        retirement: Retirement,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        self.nested(value, retirement, None, body)
    }

    /// The one nested holding ([`Self::holding`], [`Self::handed_over`]):
    /// `value` held as `retirement` for `body` beside this holding's value,
    /// naming `publication` ([`Self::publication`]).
    fn nested<U: Custodial<Permit>, R>(
        &mut self,
        value: U,
        retirement: Retirement,
        publication: Option<CheckpointId>,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> R {
        let mut surrounding = Surrounding {
            outer: self.surrounding,
            value: &mut self.value,
        };
        Holding {
            run: self.run,
            surrounding: &mut surrounding,
            value: Held(Some(value)),
            retirement,
            window: self.window,
            publication,
        }
        .execute(body)
    }

    fn execute<R>(mut self, body: impl FnOnce(&mut Self) -> R) -> R {
        // Custody lives outside the unwinding computation. Retirement runs
        // after catching its payload, avoiding diagnostics in an unwinding
        // destructor. Resume the same payload only after custody is retired.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut self)));
        let Self {
            run,
            surrounding,
            value,
            retirement,
            window,
            publication: _,
        } = self;
        if let Some(value) = value.0 {
            retired(
                &run.session,
                &mut run.checkpoints,
                &mut run.defects,
                retirement,
                value,
                |value, sink| {
                    dcbor::bounded::observed_all([
                        surrounding.observe_custody(sink),
                        value.map_or(PermitsObserved::Complete, |value| {
                            value.observe_custody(sink)
                        }),
                    ])
                },
                window,
            );
        }
        match result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

/// What a publisher still holds once it has published, as the retirement
/// its drop then performs ([`Holding::hand_over`]): a property of the
/// operation's type, stated once per type by the kind it belongs to
/// ([`terminal!`]), never at a call site. Every holding schedule reads it
/// ([`Holding::drive`]); a type of no kind does not compile, so there is no
/// default. A finished cleanup holds nothing whatever the type: that is the
/// cleanup contract itself ([`Holding::finish`]), not a property of a type.
pub trait Terminal {
    /// How the publisher retires once it has published, observed beside
    /// its surviving output.
    const PUBLISHED: Retirement;
}

/// The one declaration of each publisher type's kind ([`Terminal`]), each
/// kind's rule stated here once:
///
/// - `Exhausted`: publication moves everything the operation holds into
///   its output, or it holds nothing to begin with, so the published
///   wrapper reports no permit ([`Retirement::Exhausted`]);
/// - `Released`: a borrowed operation whose publication moves only its plan
///   out, keeping the arenas it worked in until its drop releases them
///   ([`Retirement::Released`]);
/// - `Wraps`: a wrapper that forwards its steps and custody to the operation
///   it wraps, and so publishes as that operation does.
///
/// Each type is written `[generics] Type`, with an optional `where [bounds]`.
#[macro_export]
macro_rules! terminal {
    (@kind Exhausted) => { $crate::Retirement::Exhausted };
    (@kind Released) => { $crate::Retirement::Released };
    (Wraps: $( [$($generics:tt)*] $ty:ty => $inner:ty $(where [$($bounds:tt)*])? ),+ $(,)?) => {
        $(
            impl<$($generics)*> $crate::Terminal for $ty $(where $($bounds)*)? {
                const PUBLISHED: $crate::Retirement = <$inner as $crate::Terminal>::PUBLISHED;
            }
        )+
    };
    ($kind:ident: $( [$($generics:tt)*] $ty:ty $(where [$($bounds:tt)*])? ),+ $(,)?) => {
        $(
            impl<$($generics)*> $crate::Terminal for $ty $(where $($bounds)*)? {
                const PUBLISHED: $crate::Retirement = $crate::terminal!(@kind $kind);
            }
        )+
    };
}

// The engine's publishers. An owned operation (`Operation`, by each public
// alias: its task trait is not public) moves its record whole into its
// output. A typed decode publishes its construction's value; "a finished
// decode holds nothing" (its `Custodial` impl). A retained parse releases
// its frame stack before it publishes (`ReleaseStack`) and moves its node
// arena into the document (`Publish`). A string's decode publishes after
// its parse has: the document dropped, the string's permit moved out. A
// text's normalization releases its ordering scratch (`ReleaseOrdering`)
// and its scalars (`ReleaseChars`) before it publishes its encoding; a
// text's preparation moves the scalars into its plan, its scratch released
// before. A header cursor, a key comparison and the two writers borrow
// their input and own no storage.
terminal!(Exhausted:
    ['s, I: DecodeInput<Limits> + 's, T: Transferable<Limits> + 's]
        Construction<'s, I, T, Limits>,
    ['s, I: DecodeInput<Limits> + 's] DocumentDecoder<'s, I, Limits>,
    ['s, I, T] dcbor::bounded::encoding::OwnedPreparation<'s, I, T, Limits>
        where [
            I: DecodeInput<Limits> + 's,
            T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 's,
        ],
    ['s] dcbor::bounded::decode::construction::InputBorrow<'s, Limits>,
    ['src, 's] dcbor::bounded::decode::construction::InputAcquisition<'src, 's, Limits>,
    ['s, I: DecodeInput<Limits> + 's, T: Transferable<Limits> + 's]
        TypedDecoder<'s, I, T, Limits>,
    [I, P, O: dcbor::bounded::Origin] dcbor::bounded::decode::cursor::ParserContinuation<I, P, O>,
    [P, O: dcbor::bounded::Origin] dcbor::bounded::decode::string_cursor::StringDecoder<'_, P, O>,
    [] dcbor::bounded::decode::header::HeaderCursor<'_>,
    [] dcbor::bounded::decode::comparison::KeyComparison<'_>,
    [P] dcbor::bounded::encoding::Writer<'_, '_, P>,
    [P] dcbor::bounded::text_cursor::pipeline::TextWriter<'_, '_, P>,
    [S, P, O: dcbor::bounded::Origin] dcbor::bounded::text_cursor::TextContinuation<S, P, O>,
    [P, O: dcbor::bounded::Origin] dcbor::bounded::text_cursor::pipeline::TextPreparation<'_, P, O>,
);

// The engine's one borrowed publisher: a source's preparation moves only its
// plan's bytes and header gaps into the plan, every other arena keeping its
// capacity until its cleanup or its drop (`PreparationTerms`).
terminal!(Released:
    [P, O: dcbor::bounded::Origin] dcbor::bounded::encoding::Preparation<'_, P, O>,
);

terminal!(Wraps: [O: Terminal] Traced<O> => O);

/// The turn bound supplied to the shared execution schedule.
#[derive(Clone, Copy, Debug)]
enum TurnBound {
    /// A production bound to expand under the policy's refusal schedule.
    Allowed(usize),
    /// An execution bound whose refusal allowance is already included.
    Exact(usize),
}

/// What the shared execution schedule runs: its turn bound; the refusal schedule
/// of `fault` applied first, cancelling at its refusal when the fault does;
/// each step's contract observed through the operation's position when
/// `observed`; each turn's admission first refused `repeats` times.
#[derive(Clone, Copy, Debug)]
struct Course {
    turns: TurnBound,
    fault: Option<Fault>,
    observed: bool,
    repeats: usize,
}

impl Course {
    /// An observed course of `turns`, no fault, no repeated refusal.
    const fn of(turns: usize) -> Self {
        Self {
            turns: TurnBound::Allowed(turns),
            fault: None,
            observed: true,
            repeats: 0,
        }
    }

    /// A schedule bounded by an already-computed execution allowance.
    const fn within(turns: usize) -> Self {
        Self {
            turns: TurnBound::Exact(turns),
            ..Self::of(turns)
        }
    }
}

/// What one held turn of a fixture's own schedule reached
/// ([`Holding::step`]): progress; a finished operation; a publication,
/// consumed under the output's own holding, its result; or the operation's
/// own error, a refusal included, for the fixture to classify.
#[derive(Debug)]
pub enum Stepped<E, R> {
    Progress,
    Finished,
    Published(R),
    Failed(E),
}

/// The holding scope's execution: the held value is an operation, driven by
/// the one execution schedule ([`drive_controlled`]) and the one cleanup schedule
/// ([`wound_by`]), each turn inside the holding's physical window, the
/// complete holding stack checkpointed after every turn whose recording is
/// still evidence: the surroundings, the operation, and the turn's output.
impl<T, W> Holding<'_, '_, T, W>
where
    T: Custodial<Permit> + Resumable<Limits> + Terminal,
    T::Output: Custodial<Permit>,
    T::Error: Debug,
    W: pipeline::Physical,
{
    /// Drive the held operation under `policy` within `turns` (allowed under
    /// its refusals, [`allowed`]). A publication retires the operation as
    /// its type declares ([`Terminal::PUBLISHED`]), observed beside its
    /// output, then holds the output, retired as `published`, where `consume` reads
    /// it: the output outlives its publisher, in every holding schedule
    /// ([`Self::hand_over`]). Any other end is the stop as an outcome
    /// ([`Halt`]): an output it carried (a violated publication, or one
    /// published at the turn the recording was lost) is held and retired as
    /// `published` before the stop is returned, and the operation stays
    /// held under the retirement its holder declared. A checkpoint's
    /// observer that panics is the run's defect, contained at the turn: no
    /// output is dropped by an unwinding frame.
    pub fn drive<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<R, Halt<T>> {
        self.drive_observed(policy, turns, published, |_, _| {}, consume)
    }

    /// Observe each recorded turn outside its physical window, before its
    /// outcome moves. Observer panics become findings while the output remains
    /// held by the schedule, so retirement still sees its custody.
    pub fn drive_observed<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<R, Halt<T>> {
        self.drive_with(
            policy,
            published,
            Course::of(turns),
            |_, _, _| false,
            observe,
            consume,
        )
        .map(|result| result.expect("an uncancelled drive publishes or stops"))
    }

    /// Apply a refusal schedule to held custody, `observe` reading the
    /// operation after each recorded turn while it is still held
    /// ([`Self::drive_observed`]). Cancellation leaves the operation held for
    /// its declared retirement; a publication is handed over as every
    /// schedule's is ([`Self::drive`]).
    pub fn drive_faulted<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        fault: Fault,
        observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<Option<R>, Halt<T>> {
        self.drive_with(
            policy,
            published,
            Course {
                fault: Some(fault),
                ..Course::of(turns)
            },
            |_, _, _| false,
            observe,
            consume,
        )
    }

    /// [`Self::drive`], the published output's custody moved at once into
    /// the next operation `then` makes of it ([`Holding::transfer`]): an
    /// input handle into the decode that consumes it, held as `next`
    /// declares for `body`.
    pub fn drive_then<U: Custodial<Permit>, R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        then: impl FnOnce(T::Output) -> U,
        next: Retirement,
        body: impl FnOnce(&mut Holding<'_, '_, U, W>) -> R,
    ) -> Result<R, Halt<T>> {
        self.drive(policy, turns, published, |output| {
            output.transfer(then, next, body)
        })
    }

    /// Drive under a boundary controller while retaining all custody in this
    /// holding. Returning true from `stop_before` stops before production work;
    /// the controller may request cancellation on the borrowed operation. A
    /// publication is handed over as every schedule's is ([`Self::drive`]).
    pub fn controlled<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        observed: bool,
        stop_before: impl FnMut(&Limits, &mut T, usize) -> bool,
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<Option<R>, Halt<T>> {
        self.drive_with(
            policy,
            published,
            Course {
                observed,
                ..Course::of(turns)
            },
            stop_before,
            |_, _| {},
            consume,
        )
    }

    /// [`Self::drive_observed`], every turn's next admission first refused
    /// `repeats` times, each refusal checked to change nothing
    /// ([`repeated_refusal`]): a refusal-stability schedule over the held
    /// operation. `observe` reads the operation after each turn, while it is
    /// still held; refused attempts move nothing, so the positions it reads,
    /// with the operation's position before the schedule, are every position
    /// a turn begins at. A publication is handed over as every schedule's is
    /// ([`Self::drive`]).
    pub fn repeated<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        repeats: usize,
        observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<R, Halt<T>> {
        assert!(repeats > 0, "a repeated schedule refuses at least once");
        self.drive_with(
            policy,
            published,
            Course {
                repeats,
                ..Course::of(turns)
            },
            |_, _, _| false,
            observe,
            consume,
        )
        .map(|result| result.expect("an uncancelled drive publishes or stops"))
    }

    /// At the boundary the held operation has reached, its next admission
    /// refused `repeats` times in place ([`repeated_refusal`]), each attempt
    /// checked to report the injected refusal and leave the position, the
    /// paid work and the storage unchanged; then the holding stack
    /// checkpointed. An attempt that was not refused, a prepaid release
    /// included (the boundary had no admission to refuse), or a lost
    /// recording is the stop, any output it published held and retired as a
    /// published handle first ([`Self::halted`]).
    pub fn refused(
        &mut self,
        policy: PolicyId,
        repeats: usize,
        published: Retirement,
    ) -> Result<(), Halt<T>> {
        assert!(repeats > 0, "a boundary is refused at least once");
        let refused = {
            let m = self
                .run
                .policies
                .get_mut(policy.0)
                .expect("a policy handle names a policy of the run that issued it");
            repeated_refusal(m, self.value.get(), repeats, 0, |m, operation| {
                let before = operation.position();
                let checked = contract_in(m, operation, self.window);
                (before, operation.position(), checked)
            })
        };
        match refused {
            Ok(None) => {
                self.checkpoint();
                Ok(())
            }
            Ok(Some(outcome)) => {
                let stop = Stopped::Violated {
                    output: None,
                    outcome: Some(Ok(outcome)),
                    lost: None,
                    report: "a refused boundary admitted nothing: a prepaid release, not a refusal"
                        .to_owned(),
                };
                Err(self.halted(stop, published))
            }
            Err(stop) => Err(self.halted(stop, published)),
        }
    }

    /// One fresh checked turn of the held operation under `policy` for a
    /// fixture's own schedule (a handwritten loop over the operation's own
    /// steps), the `at`-th of it: the shared turn ([`turn_in`]) inside the
    /// holding's physical window, its contract checked through its position;
    /// then, while the recording is still evidence, the holding stack
    /// checkpointed beside the turn's output and `observe` reading the
    /// operation while it is still held, the publishing turn's included. A
    /// publication is probed terminal ([`terminal`]) while its publisher is
    /// held, then handed over as every schedule's is ([`Self::hand_over`]) to
    /// `consume`. The operation's own error, a refusal included, is returned
    /// for the fixture to classify; a lost recording, a contract violation
    /// and a failed terminal probe are the stop, any output it carries held
    /// first ([`Self::halted`]).
    pub fn step<R>(
        &mut self,
        policy: PolicyId,
        at: usize,
        published: Retirement,
        observe: impl FnOnce(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<Stepped<T::Error, R>, Halt<T>> {
        let window = self.window;
        let mut publication = None;
        let stepped = {
            let RecordedRun {
                session,
                policies,
                checkpoints,
                defects,
                ..
            } = &mut *self.run;
            let m = policies
                .get_mut(policy.0)
                .expect("a policy handle names a policy of the run that issued it");
            let surrounding = &mut *self.surrounding;
            let operation = self.value.get();
            require_evidence(m, at).and_then(|()| {
                let turned = turn_in(m, operation, true, at, window);
                let outcome = observe_turn(m, operation, turned, at, |m, operation, outcome| {
                    let checkpoint = stack_checkpoint(
                        session,
                        checkpoints,
                        defects,
                        surrounding,
                        operation,
                        outcome,
                    );
                    if matches!(outcome, Ok(Step::Complete(_))) {
                        publication = Some(checkpoint);
                    }
                    observe(m, operation);
                })?;
                match outcome {
                    Ok(Step::Complete(output)) => {
                        let Turned {
                            outcome,
                            lost,
                            violation,
                        } = terminal(m, operation, true, at + 1, window);
                        if violation.is_some() || lost.is_some() {
                            return Err(Stopped::Violated {
                                output: Some(output),
                                outcome,
                                lost,
                                report: violation
                                    .unwrap_or_else(|| "terminal probe lost recording".to_owned()),
                            });
                        }
                        Ok(Ok(Step::Complete(output)))
                    }
                    other => Ok(other),
                }
            })
        };
        match stepped {
            Ok(Ok(Step::Progress)) => Ok(Stepped::Progress),
            Ok(Ok(Step::Finished)) => Ok(Stepped::Finished),
            Ok(Ok(Step::Complete(output))) => Ok(Stepped::Published(self.handed_over(
                T::PUBLISHED,
                output,
                published,
                publication,
                consume,
            ))),
            Ok(Err(error)) => Ok(Stepped::Failed(error)),
            Err(stop) => Err(self.halted(stop, published)),
        }
    }

    /// The one schedule body of every holding schedule, run as `course`
    /// declares ([`Course`]): a publication handed over to `consume`, the
    /// publisher retired first, as its type declares
    /// ([`Terminal::PUBLISHED`]), beside its surviving output, so the
    /// output outlives its publisher
    /// ([`Self::hand_over`]); any other end
    /// detached, its output held as `published` ([`Self::halted`]).
    fn drive_with<R>(
        &mut self,
        policy: PolicyId,
        published: Retirement,
        course: Course,
        stop_before: impl FnMut(&Limits, &mut T, usize) -> bool,
        observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<Option<R>, Halt<T>> {
        let window = self.window;
        self.drive_executed(
            policy,
            published,
            (
                course,
                Execution {
                    step: |m: &mut Limits, operation: &mut T, observed, at| {
                        turn_in(m, operation, observed, at, window)
                    },
                    end: |m: &mut Limits, operation: &mut T, observed, at| {
                        terminal(m, operation, observed, at, window)
                    },
                },
            ),
            stop_before,
            observe,
            consume,
        )
    }

    fn drive_executed<R, S, E>(
        &mut self,
        policy: PolicyId,
        published: Retirement,
        execution: (Course, Execution<S, E>),
        stop_before: impl FnMut(&Limits, &mut T, usize) -> bool,
        mut observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, W>) -> R,
    ) -> Result<Option<R>, Halt<T>>
    where
        S: FnMut(&mut Limits, &mut T, bool, usize) -> Turned<StepOf<T>>,
        E: FnMut(&mut Limits, &mut T, bool, usize) -> Turned<Option<StepOf<T>>>,
    {
        let (course, execution) = execution;
        // The checkpoint the publishing turn stored, which observed its
        // output ([`Self::publication`]).
        let mut publication = None;
        let result = {
            let RecordedRun {
                session,
                policies,
                checkpoints,
                defects,
                ..
            } = &mut *self.run;
            let m = policies
                .get_mut(policy.0)
                .expect("a policy handle names a policy of the run that issued it");
            let surrounding = &mut *self.surrounding;
            drive_executed(
                m,
                self.value.get(),
                course,
                stop_before,
                |m, operation, outcome| {
                    let checkpoint = stack_checkpoint(
                        session,
                        checkpoints,
                        defects,
                        surrounding,
                        operation,
                        outcome,
                    );
                    // The checkpoint that observed a publication in this
                    // turn's own outcome: that output's publishing checkpoint.
                    if matches!(outcome, Ok(Step::Complete(_))) {
                        publication = Some(checkpoint);
                    }
                    observe(m, operation);
                },
                self.window,
                execution,
            )
        };
        match result {
            Ok(Some(output)) => Ok(Some(self.handed_over(
                T::PUBLISHED,
                output,
                published,
                publication,
                consume,
            ))),
            Ok(None) => Ok(None),
            Err(stop) => Err(self.halted(stop, published)),
        }
    }

    /// Drive the held operation's own cleanup to `Finished` under `policy`
    /// within `turns` ([`wound_by`]), each turn inside the holding's physical
    /// window, the holding stack checkpointed after each. Finished, the
    /// operation holds nothing and retires as [`Retirement::Exhausted`]. A
    /// publication cleanup admits none of is a stop, its output held and
    /// retired as `published` first ([`Self::drive`]).
    pub fn finish(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
    ) -> Result<(), Halt<T>> {
        self.cleanup(policy, turns, published, true, |_| {})
    }

    /// [`Self::finish`], `observe` reading the operation after each recorded
    /// cleanup turn while it is still held, outside the physical window: the
    /// cleanup counterpart of [`Self::drive_observed`].
    pub fn finish_observed(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        observe: impl FnMut(&mut T),
    ) -> Result<(), Halt<T>> {
        self.cleanup(policy, turns, published, true, observe)
    }

    /// The one held cleanup schedule ([`wound_by`]): each step's contract
    /// checked through the operation's position when `observed`, the
    /// holding stack checkpointed and `observe` run after every turn; once
    /// finished, the operation holds nothing ([`Retirement::Exhausted`]).
    fn cleanup(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        observed: bool,
        mut observe: impl FnMut(&mut T),
    ) -> Result<(), Halt<T>> {
        let (completed, result) = {
            let RecordedRun {
                session,
                policies,
                checkpoints,
                defects,
                ..
            } = &mut *self.run;
            let m = policies
                .get_mut(policy.0)
                .expect("a policy handle names a policy of the run that issued it");
            let bound = allowed(m, turns);
            let surrounding = &mut *self.surrounding;
            let window = self.window;
            wound_by(
                m,
                self.value.get(),
                bound,
                observed,
                |operation, outcome| {
                    stack_checkpoint(
                        session,
                        checkpoints,
                        defects,
                        surrounding,
                        operation,
                        outcome,
                    );
                    observe(operation);
                },
                Execution {
                    step: |m: &mut Limits, operation: &mut T, observed, at| {
                        turn_in(m, operation, observed, at, window)
                    },
                    end: |m: &mut Limits, operation: &mut T, observed, at| {
                        terminal(m, operation, observed, at, window)
                    },
                },
            )
        };
        if completed {
            self.retirement = Retirement::Exhausted;
        }
        match result {
            Ok(()) => {
                self.retirement = Retirement::Exhausted;
                Ok(())
            }
            Err(stop) => Err(self.halted(stop, published)),
        }
    }

    /// Retain the operation at the selected refusal. Any unexpected
    /// publication remains custody of this holding until observed retirement.
    pub fn suspend(
        &mut self,
        policy: PolicyId,
        reason: LimitRefusal,
        turns: usize,
        schedule: TurnSchedule,
        published: Retirement,
    ) -> Result<usize, Halt<T>> {
        let result = {
            let RecordedRun {
                session,
                policies,
                checkpoints,
                defects,
                ..
            } = &mut *self.run;
            let m = policies
                .get_mut(policy.0)
                .expect("a policy handle names a policy of the run that issued it");
            let surrounding = &mut *self.surrounding;
            suspend_by(
                m,
                self.value.get(),
                reason,
                turns,
                schedule,
                |_, operation, outcome| {
                    stack_checkpoint(
                        session,
                        checkpoints,
                        defects,
                        surrounding,
                        operation,
                        outcome,
                    );
                },
                self.window,
            )
        };
        match result {
            Ok(index) => {
                self.checkpoint();
                Ok(index)
            }
            Err(stop) => Err(self.halted(stop, published)),
        }
    }

    /// A stop as an outcome: any output it carries held and retired as
    /// `published` first, so the stop returned holds no custody.
    fn halted(&mut self, stop: Driven<T>, published: Retirement) -> Halt<T> {
        let (halt, outputs) = stop.detach();
        if outputs.0.iter().any(Option::is_some) {
            self.holding(outputs, published, |_| ());
        }
        halt
    }
}

/// Execute one checked turn on a joined worker. The result slot belongs to the
/// parent, so even a join failure after publication cannot destroy the outcome.
fn worker_turn<R: Send>(body: impl FnOnce() -> Turned<R> + Send) -> Turned<R> {
    let mut result = None;
    let joined = std::thread::scope(|threads| threads.spawn(|| result = Some(body())).join());
    match (result, joined) {
        (Some(mut result), Err(payload)) => {
            let report = format!("worker turn panicked: {}", panic_report(payload.as_ref()));
            match &mut result.violation {
                Some(violation) => {
                    violation.push_str("; ");
                    violation.push_str(&report);
                }
                None => result.violation = Some(report),
            }
            result
        }
        (Some(result), Ok(())) => result,
        (None, Err(payload)) => std::panic::resume_unwind(payload),
        (None, Ok(())) => unreachable!("a successful worker stores its checked outcome"),
    }
}

impl<T> Holding<'_, '_, T, pipeline::Unwitnessed>
where
    T: Custodial<Permit> + Resumable<Limits> + Terminal + Send,
    T::Output: Custodial<Permit> + Send,
    T::Error: Debug + Send,
{
    /// Drive each turn and the terminal probe on a fresh joined worker.
    /// Custody stays parent-held; contract checks and release observations run
    /// on the executing worker, while custody checkpoints and retirement run in
    /// the parent. Thread-local physical attribution is not used across threads.
    /// `observe` reads the operation in the parent after each recorded turn,
    /// while it is still held, as [`Self::drive_observed`]'s does: what the
    /// operation carried across the worker boundary.
    pub fn drive_threaded<R>(
        &mut self,
        policy: PolicyId,
        turns: usize,
        published: Retirement,
        observe: impl FnMut(&Limits, &mut T),
        consume: impl FnOnce(&mut Holding<'_, '_, T::Output, pipeline::Unwitnessed>) -> R,
    ) -> Result<R, Halt<T>> {
        self.drive_executed(
            policy,
            published,
            (
                Course::of(turns),
                Execution {
                    step: |m: &mut Limits, operation: &mut T, observed, at| {
                        worker_turn(|| turn(m, operation, observed, at))
                    },
                    end: |m: &mut Limits, operation: &mut T, observed, at| {
                        worker_turn(|| terminal(m, operation, observed, at, &pipeline::Unwitnessed))
                    },
                },
            ),
            |_, _, _| false,
            observe,
            consume,
        )
        .map(|result| result.expect("an uncancelled threaded drive publishes or stops"))
    }
}

impl<W: pipeline::Physical> Holding<'_, '_, dcbor::bounded::Prepared<Permit>, W> {
    /// Consume a synchronous plan through its production in-place publication,
    /// retaining the resulting encoding before observation or fixture execution.
    pub fn publish<R>(
        &mut self,
        policy: PolicyId,
        consume: impl FnOnce(&mut Holding<'_, '_, dcbor::bounded::Encoded<Permit>, W>) -> R,
    ) -> Result<R, Finding> {
        self.run.with_policy(policy, |m| {
            require_evidence::<(), BoundedError<LimitRefusal>, Rendered>(m, 0)
        })?;
        let plan = self
            .value
            .0
            .take()
            .expect("a plan is held until publication");
        let result = self
            .run
            .with_policy(policy, |m| self.window.window(|| plan.publish(m)));
        let loss = self.run.with_policy(policy, |m| lost(m, 0));
        match result {
            Ok(output) => self.holding(output, Retirement::Released, |output| {
                output.checkpoint();
                match loss {
                    Some(lost) => Err(Finding::Lost {
                        lost,
                        outcome: "published encoding".to_owned(),
                    }),
                    None => Ok(consume(output)),
                }
            }),
            Err(error) => {
                self.checkpoint();
                Err(match loss {
                    Some(lost) => Finding::Lost {
                        lost,
                        outcome: format!("Err({error:?})"),
                    },
                    None => Finding::Driver(format!("plan publication failed: {error:?}")),
                })
            }
        }
    }
}

/// Start a complete borrowed batch before admitting any job, then join every
/// worker. Partial startup leaves all unexecuted custody with the caller.
fn joined_batch<J: Send>(jobs: &mut [J], task: impl Fn(usize, &mut J) + Sync) -> Vec<Finding> {
    let count = jobs.len();
    let mut failures = Vec::new();
    std::thread::scope(|threads| {
        let mut workers = Vec::with_capacity(count);
        for (worker, job) in jobs.iter_mut().enumerate() {
            let task = &task;
            let (start, ready) = std::sync::mpsc::sync_channel(1);
            let spawned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                threads.spawn(move || match ready.recv() {
                    Ok(true) => task(worker, job),
                    Ok(false) => {}
                    Err(error) => panic!("worker {worker} startup disconnected: {error}"),
                })
            }));
            match spawned {
                Ok(handle) => workers.push((worker, handle, start)),
                Err(payload) => {
                    failures.push(Finding::Defect(format!(
                        "worker {worker} spawn panicked: {}",
                        panic_report(payload.as_ref())
                    )));
                    break;
                }
            }
        }
        let complete = workers.len() == count;
        for (worker, _, start) in &workers {
            if let Err(error) = start.send(complete) {
                failures.push(Finding::Defect(format!(
                    "worker {worker} startup failed: {error}"
                )));
            }
        }
        for (worker, handle, _) in workers {
            if let Err(payload) = handle.join() {
                failures.push(Finding::Defect(format!(
                    "worker {worker} join panicked: {}",
                    panic_report(payload.as_ref())
                )));
            }
        }
    });
    failures
}

impl<T: Custodial<Permit> + Send> Holding<'_, '_, CustodyBatch<T>, pipeline::Unwitnessed> {
    /// Retire the held batch now, as the holding declared it, every member
    /// destroyed on a worker thread of its own, the workers released
    /// together so the destructions race, each joined before the custody
    /// after the retirement is observed ([`retired_by`]): one retirement,
    /// checkpointed and checked against its rule as any other. A worker's
    /// panic is the destruction's, kept as the run's defect. The holding then
    /// holds nothing.
    pub fn retire_concurrently(&mut self) {
        let mut failures = Vec::new();
        let batch = self
            .value
            .0
            .take()
            .expect("a batch is held until it retires");
        retired_by(
            &self.run.session,
            &mut self.run.checkpoints,
            &mut self.run.defects,
            self.retirement,
            batch,
            |batch, sink| {
                dcbor::bounded::observed_all([
                    self.surrounding.observe_custody(sink),
                    batch.map_or(PermitsObserved::Complete, |batch| {
                        batch.observe_custody(sink)
                    }),
                ])
            },
            self.window,
            |batch| {
                let mut members: Vec<_> = batch.into_members().map(Some).collect();
                failures.extend(joined_batch(&mut members, |_, member| drop(member.take())));
                // A partial startup admits no jobs. Retire each remaining
                // member independently so one destructor cannot skip another.
                for (worker, member) in members.iter_mut().enumerate() {
                    if let Err(payload) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            drop(member.take());
                        }))
                    {
                        failures.push(Finding::Defect(format!(
                            "worker {worker} fallback retirement panicked: {}",
                            panic_report(payload.as_ref())
                        )));
                    }
                }
            },
        );
        self.run.defects.extend(failures);
    }
}

/// Where a scope's typed decode takes its input from
/// ([`Holding::decoder`]): the input's acquisition operation, made of the
/// scope, and the turns its bound allows.
pub trait Source<'s> {
    /// The input the decode reads.
    type Input: DecodeInput<Limits> + 's;
    /// The scope's operation acquiring it.
    type Acquire: Resumable<
            Limits,
            Output = OwnedInitialized<'s, Self::Input, Limits>,
            Error = BoundedError<LimitRefusal>,
        > + Custodial<Permit>
        + Terminal;
    /// The acquisition's turn bound.
    fn turns(&self) -> usize;
    /// The acquisition, made of `owner`.
    fn acquire(self, owner: &DecodeOwner<'s, Limits>) -> Self::Acquire;
}

/// Input borrowed from bytes that outlive the scope
/// ([`DecodeOwner::borrow_input`], [`borrow_bound`]).
///
/// [`borrow_bound`]: dcbor::bounded::decode::construction::borrow_bound
pub struct Borrowing<'s>(pub &'s [u8]);

impl<'s> Source<'s> for Borrowing<'s> {
    type Input = Borrowed<'s>;
    type Acquire = dcbor::bounded::decode::construction::InputBorrow<'s, Limits>;

    fn turns(&self) -> usize {
        turns(
            dcbor::bounded::decode::construction::borrow_bound::<Limits, ()>()
                .expect("borrow bound fits in u64"),
        )
    }

    fn acquire(self, owner: &DecodeOwner<'s, Limits>) -> Self::Acquire {
        owner.borrow_input(self.0)
    }
}

/// Input copied into the scope's own storage ([`DecodeOwner::copy_input`],
/// [`copy_bound`]).
///
/// [`copy_bound`]: dcbor::bounded::decode::construction::copy_bound
pub struct Copying<'src>(pub &'src [u8]);

impl<'src, 's> Source<'s> for Copying<'src> {
    type Input = ByteString;
    type Acquire = dcbor::bounded::decode::construction::InputAcquisition<'src, 's, Limits>;

    fn turns(&self) -> usize {
        turns(
            dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(self.0.len() as u64)
                .expect("copy bound fits in u64"),
        )
    }

    fn acquire(self, owner: &DecodeOwner<'s, Limits>) -> Self::Acquire {
        owner.copy_input(self.0)
    }
}

/// What an owned operation driven within a holding reached for its fixture
/// to classify: what the fixture's body made of the published value, or
/// the operation's own error, its custody already retired by the scope; a
/// stop of the driver itself is the run's [`Finding`].
pub type Reached<R, E> = Result<Result<R, E>, Finding>;

/// A typed decode's own error.
pub type DecodeFailure = dcbor::bounded::decode::DecodeError<LimitRefusal>;

/// The held scope's shared operations: its initialization and its drain by
/// the one scope drivers ([`initialize`], [`drain`]), and every input and
/// decode made in it, each a nested holding of its own, so a fixture
/// supplies only its wire, its options, its policy and its assertions.
impl<'s, W: pipeline::Physical> Holding<'_, '_, DecodeOwner<'s, Limits>, W> {
    /// Initialize the held scope under `policy`, refusals retried, each turn
    /// inside the holding's physical window; then the holding stack
    /// checkpointed. Any stop is returned for its caller to classify (a
    /// failed physical allocation is the initialization's own error,
    /// [`Stopped::Operation`]), or to make the run's finding.
    pub fn initialize(
        &mut self,
        policy: PolicyId,
    ) -> Result<(), Scoped<BoundedResult<(), Limits>>> {
        let RecordedRun {
            session,
            policies,
            checkpoints,
            defects,
            ..
        } = &mut *self.run;
        let m = policies
            .get_mut(policy.0)
            .expect("a policy handle names a policy of the run that issued it");
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        initialize_by(
            self.value.get(),
            m,
            |owner| {
                capture(session, checkpoints, defects, |sink| {
                    dcbor::bounded::observed_all([
                        surrounding.observe_custody(sink),
                        owner.observe_custody(sink),
                    ])
                });
            },
            |owner, m| checked(m, |m| window.window(|| owner.initialize_step(m))),
        )
    }

    /// Shut the held scope down under `policy`, every record it holds
    /// reclaimed; then the holding stack checkpointed. Any stop is the
    /// run's finding.
    pub fn drain(&mut self, policy: PolicyId) -> Result<(), Finding> {
        let RecordedRun {
            session,
            policies,
            checkpoints,
            defects,
            ..
        } = &mut *self.run;
        let m = policies
            .get_mut(policy.0)
            .expect("a policy handle names a policy of the run that issued it");
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        drain_by(
            self.value.get(),
            m,
            |owner| {
                capture(session, checkpoints, defects, |sink| {
                    dcbor::bounded::observed_all([
                        surrounding.observe_custody(sink),
                        owner.observe_custody(sink),
                    ])
                });
            },
            |owner, m| {
                scope_checked(m, owner, |owner, m| {
                    window.window(|| owner.shutdown_step(m))
                })
            },
        )
        .map_err(Finding::from)
    }
}

/// Custody that gives access to a decode scope: the scope's authority
/// itself, or its lent view ([`Lent`]), shared with nested holdings
/// ([`Holding::lending`]) whose operations act on the scope while it is
/// borrowed: every acquisition and queue step reads the authority through
/// `&DecodeOwner`.
pub trait Scope<'s>: Custodial<Permit> {
    /// The scope's authority.
    fn scope(&self) -> &DecodeOwner<'s, Limits>;
}

impl<'s> Scope<'s> for DecodeOwner<'s, Limits> {
    fn scope(&self) -> &DecodeOwner<'s, Limits> {
        self
    }
}

impl<'s> Scope<'s> for Lent<'_, DecodeOwner<'s, Limits>> {
    fn scope(&self) -> &DecodeOwner<'s, Limits> {
        self.0
    }
}

/// Every input and decode made in a scope the holding gives access to
/// ([`Scope`]), each a nested holding of its own, so a fixture supplies only
/// its wire, its options, its policy and its assertions.
impl<'s, D: Scope<'s>, W: pipeline::Physical> Holding<'_, '_, D, W> {
    /// One fresh checked turn of a step of the held scope under `policy` for
    /// a fixture's own schedule, the `at`-th of it ([`scope_checked`]), the
    /// step inside the holding's physical window; then the recording's
    /// integrity read ([`scope_turn`]) and the holding stack checkpointed.
    /// The step's outcome as the scope returned it, for the fixture to
    /// classify; a lost recording is the run's finding, that outcome kept in
    /// it ([`Stopped::Lost`]).
    pub fn scope_step(
        &mut self,
        policy: PolicyId,
        at: usize,
        step: impl FnOnce(&mut D, &mut Limits) -> BoundedResult<Reclaimed, Limits>,
    ) -> Result<BoundedResult<Reclaimed, Limits>, Finding> {
        let window = self.window;
        let outcome = self.with_policy(policy, |scope, m| {
            let outcome = scope_checked(m, scope, |scope, m| window.window(|| step(scope, m)));
            scope_turn(m, outcome, at)
                .checked::<(), BoundedError<LimitRefusal>>()
                .map_err(Finding::from)
        })?;
        self.checkpoint();
        Ok(outcome)
    }

    /// Acquire an input under this holding and retain its publication for `body`.
    pub fn input<S: Source<'s>, R>(
        &mut self,
        policy: PolicyId,
        source: S,
        body: impl FnOnce(&mut Holding<'_, '_, OwnedInitialized<'s, S::Input, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        let bound = source.turns();
        self.acquiring(source, |acquiring| {
            acquiring
                .drive(policy, bound, Retirement::Published, body)
                .map_err(Finding::from)
        })
    }

    /// Construct an acquisition inside the physical window and retain it before
    /// checking that construction allocated nothing. The continuation chooses
    /// the acquisition's schedule; this holding owns every exit.
    pub fn acquiring<S: Source<'s>, R>(
        &mut self,
        source: S,
        body: impl FnOnce(&mut Holding<'_, '_, S::Acquire, W>) -> R,
    ) -> R {
        let window = self.window;
        let requests = window.requests();
        let acquisition = window.window(|| source.acquire(self.value.get().scope()));
        self.holding(acquisition, Retirement::Stopped, |acquisition| {
            assert_eq!(
                window.requests(),
                requests,
                "input acquisition constructor allocated"
            );
            body(acquisition)
        })
    }

    /// `wire` borrowed as an input of the held scope, then decoded as `T`
    /// under `options`, each within its bound ([`borrow_bound`],
    /// [`typed_decode_bound`]): the borrow's operation held while it runs,
    /// its input moved into the decode, the decode held while it runs, and
    /// the published value held for `body`, retired as a published handle
    /// once `body` returns. A stopped borrow or decode is retired as
    /// stopped. The decode's own error is returned for its fixture to
    /// classify; every other stop is the run's finding.
    ///
    /// [`borrow_bound`]: dcbor::bounded::decode::construction::borrow_bound
    /// [`typed_decode_bound`]: dcbor::bounded::decode::construction::typed_decode_bound
    pub fn decoded<T: Transferable<Limits> + 's, R>(
        &mut self,
        policy: PolicyId,
        wire: &'s [u8],
        options: Options,
        body: impl FnOnce(&mut Holding<'_, '_, TypedValue<'s, Borrowed<'s>, T, Limits>, W>) -> R,
    ) -> Reached<R, DecodeFailure> {
        let decoded = borrowed_decode_turns::<T>(wire.len(), options);
        let window = self.window;
        self.decoder::<_, T, W, _>(policy, Borrowing(wire), options, window, |decoding| {
            match decoding.drive(policy, decoded, Retirement::Published, body) {
                Ok(made) => Ok(Ok(made)),
                Err(Stopped::Operation(error)) => Ok(Err(error)),
                Err(halt) => Err(Finding::from(halt)),
            }
        })
        .and_then(|reached| reached)
    }

    /// The one borrow-then-decode composition: `wire` borrowed as an input
    /// of the held scope within its bound ([`borrow_bound`]), the borrow's
    /// operation held while it runs under this holding's witness, its input
    /// moved into a typed decoder of `T` under `options` constructed inside
    /// `window`, and that decoder held under `window` ([`Self::witnessed`]),
    /// retired as stopped unless it is exhausted, for `body` to schedule
    /// ([`Self::decoded`] drives it to publication under the holding's own
    /// witness). Any stop of the borrow is the run's finding.
    ///
    /// [`borrow_bound`]: dcbor::bounded::decode::construction::borrow_bound
    pub fn decoder<S: Source<'s>, T: Transferable<Limits> + 's, V: pipeline::Physical, R>(
        &mut self,
        policy: PolicyId,
        source: S,
        options: Options,
        window: &V,
        body: impl FnOnce(&mut Holding<'_, '_, TypedDecoder<'s, S::Input, T, Limits>, V>) -> R,
    ) -> Result<R, Finding> {
        self.input(policy, source, |input| {
            input.moved(
                window,
                |input| {
                    window.window(|| TypedDecoder::<'s, S::Input, T, Limits>::new(input, options))
                },
                Retirement::Stopped,
                // The decoder is another value than the input it consumes.
                None,
                body,
            )
        })
    }

    /// `bytes` copied into an input of the held scope within its bound
    /// ([`copy_bound`]), the copy's operation held while it runs, the input
    /// held for `body` and retired as a published handle once it returns.
    /// Any stop is the run's finding, the stopped copy retired as stopped.
    ///
    /// [`copy_bound`]: dcbor::bounded::decode::construction::copy_bound
    pub fn copied<R>(
        &mut self,
        policy: PolicyId,
        bytes: &[u8],
        body: impl FnOnce(&mut Holding<'_, '_, OwnedInitialized<'s, ByteString, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        self.input(policy, Copying(bytes), body)
    }
}

impl RecordedRun {
    /// One initialized scope, its held scenario, and its successful shutdown.
    /// Failed or unwinding scenarios retire their custody without scheduling
    /// additional production work.
    pub fn scoped<'s, W: pipeline::Physical, R>(
        &mut self,
        policy: PolicyId,
        window: &W,
        body: impl FnOnce(&mut Holding<'_, '_, DecodeOwner<'s, Limits>, W>) -> Result<R, Finding>,
    ) -> Result<R, Finding> {
        self.holding(DecodeOwner::new(), Retirement::Scope, window, |owner| {
            owner.initialize(policy)?;
            let result = body(owner)?;
            owner.drain(policy)?;
            Ok(result)
        })
    }
}

/// Which of a scope's authority and a value published in it retires first
/// ([`RecordedRun::terminal`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropOrder {
    /// The value retires to the queue, then the authority's terminal
    /// destruction drains it.
    ValueFirst,
    /// The authority is dropped while the value keeps the scope alive
    /// ([`Retirement::Abandoned`]); the value's retirement, the scope's last
    /// reference, then drains it ([`Retirement::LastReference`]).
    OwnerFirst,
}

impl RecordedRun {
    /// `wire` copied into a scope initialized under `policy` and decoded as
    /// `T` under `options`, every turn and every retirement inside `window`;
    /// the published value held for `body` once the authority's own
    /// retirement stands where `order` puts it, then both retired in that
    /// order by the scope's terminal cleanup, never its drain, each
    /// retirement checked against its rule. Owner first, the value is held
    /// beside the scope, outside it ([`CustodyBatch`]), so the authority is
    /// retired while the value lives, and `body` runs with the scope
    /// abandoned. Any stop is the run's finding.
    pub fn terminal<T, W, R>(
        &mut self,
        policy: PolicyId,
        wire: &[u8],
        options: Options,
        window: &W,
        order: DropOrder,
        body: impl FnOnce(&mut Holding<'_, '_, TypedValue<'static, ByteString, T, Limits>, W>) -> R,
    ) -> Result<R, Finding>
    where
        T: Transferable<Limits> + 'static,
        W: pipeline::Physical,
    {
        match order {
            DropOrder::ValueFirst => {
                self.holding(DecodeOwner::new(), Retirement::Scope, window, |owner| {
                    owner.initialize(policy)?;
                    owner.copied(policy, wire, |input| {
                        input.decode::<T, _>(policy, options, body)
                    })?
                })
            }
            DropOrder::OwnerFirst => self.holding(
                CustodyBatch::slots(1),
                Retirement::Exhausted,
                window,
                |values| {
                    values.lending(Retirement::Exhausted, Lent::new, |lent| {
                        let values = lent.value().get();
                        lent.holding(DecodeOwner::new(), Retirement::Abandoned, |owner| {
                            owner.initialize(policy)?;
                            owner.copied(policy, wire, |input| {
                                input.decode::<T, _>(policy, options, |value| {
                                    value.deposit(values, 0)
                                })
                            })??;
                            Ok::<_, Finding>(())
                        })?;
                        Ok(lent.drawn(values, 0, Retirement::LastReference, body))
                    })
                },
            ),
        }
    }
}

/// A held acquisition's record acquisition in a scope it names.
impl<'s, T, W> Holding<'_, '_, Acquisition<'s, T, Limits>, W>
where
    T: Reclaim<Limits> + Send + 's,
    T::State: Send,
    W: pipeline::Physical,
{
    /// A record of `T` acquired in `scope` under `policy` by the held
    /// acquisition ([`acquire_by`]), each turn inside the holding's physical
    /// window and the holding stack checkpointed after it, the acquired
    /// record beside the acquisition; the record held for `body` and retired
    /// as a published handle once it returns. Any stop is the run's finding,
    /// a record acquired at the stopping turn held and retired as published
    /// before the finding is returned; a fixture classifying a refused
    /// acquisition steps it itself ([`Self::with_policy`]).
    pub fn acquire<R>(
        &mut self,
        policy: PolicyId,
        scope: &DecodeOwner<'s, Limits>,
        body: impl FnOnce(&mut Holding<'_, '_, OwnedRecord<'s, T, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        let RecordedRun {
            session,
            policies,
            checkpoints,
            defects,
            ..
        } = &mut *self.run;
        let m = policies
            .get_mut(policy.0)
            .expect("a policy handle names a policy of the run that issued it");
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        let acquired = acquire_by(
            self.value.get(),
            m,
            |acquisition, record| {
                capture(session, checkpoints, defects, |sink| {
                    dcbor::bounded::observed_all([
                        surrounding.observe_custody(sink),
                        acquisition.observe_custody(sink),
                        record.map_or(PermitsObserved::Complete, |record| {
                            record.observe_custody(sink)
                        }),
                    ])
                });
            },
            |acquisition, m| window.window(|| scope.allocate_step(m, acquisition)),
        );
        match acquired {
            Ok(record) => Ok(self.holding(record, Retirement::Published, body)),
            Err(stop) => {
                let finding = Finding::from(&stop);
                if let Stopped::Lost(_, Ok(record))
                | Stopped::Violated {
                    outcome: Some(Ok(record)),
                    ..
                } = stop
                {
                    self.holding(record, Retirement::Published, |_| ());
                }
                Err(finding)
            }
        }
    }
}

impl<'s, I: DecodeInput<Limits> + 's, W: pipeline::Physical>
    Holding<'_, '_, OwnedInitialized<'s, I, Limits>, W>
{
    /// Parse held input through the shared execution and retirement schedule.
    pub fn parse<R>(
        &mut self,
        policy: PolicyId,
        options: Options,
        body: impl FnOnce(&mut Holding<'_, '_, OwnedDocument<'s, I, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        let bound = turns(
            dcbor::bounded::decode::construction::parse_bound::<I, Limits, ()>(
                self.value().value().bytes().len() as u64,
                options,
            )
            .expect("parse bound fits in u64"),
        );
        self.transfer(
            |input| DocumentDecoder::parse(input, options),
            Retirement::Stopped,
            |parser| parser.drive(policy, bound, Retirement::Published, body),
        )
        .map_err(Finding::from)
    }

    /// Decode held input without transporting custody in an error.
    pub fn decode<T: Transferable<Limits> + 's, R>(
        &mut self,
        policy: PolicyId,
        options: Options,
        body: impl FnOnce(&mut Holding<'_, '_, TypedValue<'s, I, T, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        let bound = turns(
            dcbor::bounded::decode::construction::typed_decode_bound::<I, T, Limits, ()>(
                self.value().value().bytes().len() as u64,
                options,
            )
            .expect("typed decode bound fits in u64"),
        );
        self.transfer(
            |input| TypedDecoder::new(input, options),
            Retirement::Stopped,
            |decoder| decoder.drive(policy, bound, Retirement::Published, body),
        )
        .map_err(Finding::from)
    }
}

impl<'s, I: DecodeInput<Limits> + 's, W: pipeline::Physical>
    Holding<'_, '_, OwnedDocument<'s, I, Limits>, W>
{
    /// Construct from a held document through the shared execution schedule.
    pub fn construct<T: Transferable<Limits> + 's, R>(
        &mut self,
        policy: PolicyId,
        body: impl FnOnce(&mut Holding<'_, '_, TypedValue<'s, I, T, Limits>, W>) -> R,
    ) -> Result<R, Finding> {
        let bound = turns(
            dcbor::bounded::decode::construction::construction_bound::<I, T, Limits, ()>(
                self.value().bytes().len() as u64,
            )
            .expect("construction bound fits in u64"),
        );
        self.transfer(
            Construction::construct,
            Retirement::Stopped,
            |construction| construction.drive(policy, bound, Retirement::Published, body),
        )
        .map_err(Finding::from)
    }
}

impl<'s, I, T, W> Holding<'_, '_, TypedValue<'s, I, T, Limits>, W>
where
    I: DecodeInput<Limits> + 's,
    T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 's,
    W: pipeline::Physical,
{
    /// Prepare a held value, retaining its plan under the same lifecycle.
    pub fn prepare<R>(
        &mut self,
        policy: PolicyId,
        body: impl FnOnce(
            &mut Holding<'_, '_, dcbor::bounded::encoding::OwnedPrepared<'s, I, T, Limits>, W>,
        ) -> R,
    ) -> Result<R, Finding> {
        let bound = turns(
            dcbor::bounded::encoding::owned_prepare_bound::<I, T, Limits, ()>(shape(
                self.value().value(),
            ))
            .expect("owned preparation bound fits in u64"),
        );
        self.transfer(
            dcbor::bounded::encoding::OwnedPreparation::prepare,
            Retirement::Stopped,
            |preparation| preparation.drive(policy, bound, Retirement::Published, body),
        )
        .map_err(Finding::from)
    }
}

/// The checkpoint of a holding stack after one turn: the surroundings, the
/// operation, and the turn's output while the outcome holds it, each its
/// own custody, so no permit is reported twice; the identity of the
/// checkpoint stored. An observer that panics is the run's defect, caught
/// here: the turn's output stays in the outcome, never dropped by an
/// unwinding frame. A capture that stored no checkpoint fails the turn
/// (`observe_turn` keeps it as the turn's violation): no identity is ever
/// returned for a checkpoint that does not exist.
fn stack_checkpoint<O: Custodial<Permit> + Resumable<Limits>>(
    session: &Recording,
    checkpoints: &mut refinement::History,
    defects: &mut Vec<Finding>,
    surrounding: &mut dyn Custodial<Permit>,
    operation: &mut O,
    outcome: &mut StepOf<O>,
) -> CheckpointId
where
    O::Output: Custodial<Permit>,
{
    let before = defects.len();
    let stored = capture(session, checkpoints, defects, |sink| {
        let output = match outcome {
            Ok(Step::Complete(output)) => output.observe_custody(sink),
            _ => PermitsObserved::Complete,
        };
        dcbor::bounded::observed_all([
            surrounding.observe_custody(sink),
            operation.observe_custody(sink),
            output,
        ])
    });
    assert_eq!(
        defects.len(),
        before,
        "custody checkpoint failed; the run retains its observation diagnostics"
    );
    stored.expect("a capture that recorded no defect stored its checkpoint")
}

/// Why a custody observation is no checkpoint ([`collect`]). Each refuses
/// the whole capture: no partial checkpoint is ever stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unobserved {
    /// A queue of the custody was being stepped by another caller: what it
    /// holds is unknown, never empty, and groups already emitted are no
    /// observation either.
    Contended,
    /// A held obligation or permit reported outside every group.
    OutsideGroup,
    /// A group closed that was never opened.
    UnmatchedEnd,
    /// A group opened and never closed.
    UnclosedGroup,
    /// A held obligation or permit reported directly in a group whose owner
    /// is deferred (`begin(None)`): custody no stored owner names.
    Unowned,
    /// One binding reported twice.
    DuplicateBound(Identity),
    /// One obligation reported twice.
    DuplicateHeld(Identity),
    /// One permit reported twice.
    DuplicatePermit(Identity),
}

/// The permit type every recorded policy grants.
type Permit = <Limits as Releasing>::Permit;

/// The one collector of a custody observation ([`CustodySink`]): a stack of
/// open groups, each item attributed to the innermost, each owner's groups
/// combined into one entry ([`refinement::Custody`]), every identity
/// reported once. An initialized owner's group stays represented when it
/// holds nothing; a deferred owner's contributes nothing and may only hold
/// child groups. The first fault is kept.
/// A record's payload is observed inside the record's own group
/// (`Record::observe_custody`), so a record block reported in a group nested
/// inside another record's group is held in that record's payload: the
/// collector keeps, for each record block, the record of the nearest
/// enclosing group that reported one ([`Collected::within`]).
struct Collector {
    open: Vec<Option<Identity>>,
    /// For each open group, the record block reported directly in it.
    records: Vec<Option<Identity>>,
    custody: std::collections::BTreeMap<Identity, refinement::Custody>,
    seen: std::collections::BTreeSet<Identity>,
    within: std::collections::BTreeMap<Identity, Identity>,
    fault: Option<Unobserved>,
}

/// A whole custody observation ([`collected`]): its custody by owner, and
/// each record block held in another record's payload, with that record.
struct Collected {
    custody: Vec<refinement::Custody>,
    within: std::collections::BTreeMap<Identity, Identity>,
}

impl Collector {
    /// The owner the next item belongs to: the innermost open group's.
    fn owner(&mut self) -> Option<Identity> {
        let fault = match self.open.last().copied() {
            Some(Some(owner)) => return Some(owner),
            Some(None) => Unobserved::Unowned,
            None => Unobserved::OutsideGroup,
        };
        self.fail(fault);
        None
    }

    fn fail(&mut self, fault: Unobserved) {
        self.fault.get_or_insert(fault);
    }

    /// The entry of `owner`, made on its first group.
    fn entry(&mut self, owner: Identity) -> &mut refinement::Custody {
        self.custody
            .entry(owner)
            .or_insert_with(|| refinement::Custody {
                owner,
                bound: Vec::new(),
                held: Vec::new(),
                permits: Vec::new(),
            })
    }
}

impl CustodySink<Permit> for Collector {
    fn begin(&mut self, owner: Option<Identity>) {
        if let Some(owner) = owner {
            self.entry(owner);
        }
        self.open.push(owner);
        self.records.push(None);
    }

    fn bound(&mut self, acquisition: Identity) {
        if let Some(owner) = self.owner() {
            if self.seen.insert(acquisition) {
                self.entry(owner).bound.push(acquisition);
            } else {
                self.fail(Unobserved::DuplicateBound(acquisition));
            }
        }
    }

    fn held(&mut self, hold: Hold) {
        if let Some(owner) = self.owner() {
            if self.seen.insert(hold.id) {
                self.entry(owner).held.push(hold);
            } else {
                self.fail(Unobserved::DuplicateHeld(hold.id));
            }
        }
    }

    fn permit(&mut self, permit: &Permit, record: Option<dcbor::bounded::RecordStage>) {
        let id = <Limits as Releasing>::permit_identity(permit);
        if let Some(owner) = self.owner() {
            if self.seen.insert(id) {
                self.entry(owner)
                    .permits
                    .push(refinement::Reported { permit: id, record });
                if record.is_some() {
                    // The record of the nearest enclosing group holds this
                    // one in its payload; this group's own is its sibling.
                    let groups = self.records.len().saturating_sub(1);
                    if let Some(container) = self.records[..groups].iter().rev().find_map(|r| *r) {
                        self.within.insert(id, container);
                    }
                    if let Some(own) = self.records.last_mut() {
                        own.get_or_insert(id);
                    }
                }
            } else {
                self.fail(Unobserved::DuplicatePermit(id));
            }
        }
    }

    fn end(&mut self) {
        self.records.pop();
        if self.open.pop().is_none() {
            self.fail(Unobserved::UnmatchedEnd);
        }
    }

    /// Shared custody is reported by the first holder that reaches it: its
    /// permit is then seen, and every later holder passes it over.
    fn shared(&mut self, custody: Identity) -> bool {
        !self.seen.contains(&custody)
    }
}

/// The session boundary of `session` now: the observations recorded so far.
/// Panics naming why the recording is no evidence.
fn boundary(session: &Recording) -> usize {
    session
        .boundary()
        .unwrap_or_else(|incomplete| {
            panic!("a mark over a recording that is no evidence: {incomplete:?}")
        })
        .get()
}

/// The one checkpoint body: `observe`'s custody collected whole
/// ([`collect`]), then `session`'s boundary taken and the checkpoint
/// appended to `checkpoints`. An observation that is no observation (the
/// collector's typed refusal: malformed grouping, an item no stored owner
/// names, an identity reported twice, contention), and a boundary over a
/// recording that is no evidence, are kept in `defects` instead: no
/// checkpoint, partial or whole, is stored, nothing unwinds, and the run
/// goes on through its cleanup to its finalization, which fails naming the
/// finding beside what the recording finished as ([`concluded`]).
fn capture(
    session: &Recording,
    checkpoints: &mut refinement::History,
    defects: &mut Vec<Finding>,
    observe: impl FnOnce(&mut dyn CustodySink<Permit>) -> PermitsObserved,
) -> Option<CheckpointId> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(observe))) {
        Ok(collected) => {
            capture_collected(session, checkpoints, defects, collected).map(|(id, _)| id)
        }
        Err(payload) => {
            defects.push(Finding::Defect(format!(
                "a checkpoint's observation panicked: {}",
                panic_report(payload.as_ref()),
            )));
            None
        }
    }
}

/// One stored checkpoint, named by its place among the run's checkpoints:
/// the place the refinement machine names a divergence at
/// ([`refinement::At::Checkpoint`]). Only the checkpoint operation mints
/// one, for the checkpoint it stored ([`capture_collected`]); a capture that
/// stores nothing names none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointId(usize);

impl CheckpointId {
    /// The checkpoint's place among the run's checkpoints.
    pub fn index(self) -> usize {
        self.0
    }
}

/// Store the exact collected custody used by a boundary comparison: the
/// stored checkpoint's identity with its custody, or none, the reason kept
/// in `defects`, when nothing was stored.
fn capture_collected(
    session: &Recording,
    checkpoints: &mut refinement::History,
    defects: &mut Vec<Finding>,
    collected: Result<Vec<refinement::Custody>, Unobserved>,
) -> Option<(CheckpointId, Vec<refinement::Custody>)> {
    let custody = match collected {
        Ok(custody) => custody,
        Err(unobserved) => {
            defects.push(Finding::Defect(format!(
                "a checkpoint's custody is no observation: {unobserved:?}"
            )));
            return None;
        }
    };
    match session.boundary() {
        Ok(boundary) => {
            let id = CheckpointId(checkpoints.len());
            checkpoints.push(refinement::Checkpoint {
                boundary: boundary.get(),
                custody: custody.clone(),
            });
            Some((id, custody))
        }
        Err(incomplete) => {
            defects.push(Finding::Defect(format!(
                "a checkpoint's recording is no evidence: {incomplete:?}"
            )));
            None
        }
    }
}

/// The custody one production traversal reports (`observe`, a custody's
/// `observe_custody`), collected by owner ([`Collector`]): every group
/// properly nested and closed, every item inside a group of a stored owner,
/// every identity once, and the traversal whole. Contention refuses the
/// whole capture, whatever was emitted before it.
pub fn collect(
    observe: impl FnOnce(&mut dyn CustodySink<Permit>) -> PermitsObserved,
) -> Result<Vec<refinement::Custody>, Unobserved> {
    collected(observe).map(|collected| collected.custody)
}

/// [`collect`], with each record block held in another record's payload
/// ([`Collected`]): the one collection, the retirement comparison's.
fn collected(
    observe: impl FnOnce(&mut dyn CustodySink<Permit>) -> PermitsObserved,
) -> Result<Collected, Unobserved> {
    let mut collector = Collector {
        open: Vec::new(),
        records: Vec::new(),
        custody: std::collections::BTreeMap::new(),
        seen: std::collections::BTreeSet::new(),
        within: std::collections::BTreeMap::new(),
        fault: None,
    };
    if observe(&mut collector) == PermitsObserved::Contended {
        return Err(Unobserved::Contended);
    }
    if let Some(fault) = collector.fault {
        return Err(fault);
    }
    if !collector.open.is_empty() {
        return Err(Unobserved::UnclosedGroup);
    }
    Ok(Collected {
        custody: collector.custody.into_values().collect(),
        within: collector.within,
    })
}

/// What a retirement legally does to the custody around it, declared by the
/// holding scope ([`RecordedRun::holding`]): which permits may be
/// released, by their record stage, and which stage transitions the
/// permits that remain may take. No blanket rule: a retirement that
/// releases what its kind does not, or keeps what its kind must release,
/// is a defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retirement {
    /// The scope authority's terminal destruction releases its own block
    /// and queued or active records. Live handles belong to nested holdings
    /// and must have retired before this boundary.
    Scope,
    /// The scope authority dropped while live handles keep its scope alive:
    /// its terminal drain may release the queued and active records and the
    /// storage their payloads held, as [`Self::Scope`]'s does, but the scope
    /// block remains, reported from then on by the handles that hold it as
    /// shared custody ([`dcbor::bounded::CustodySink::shared`]), under the
    /// same owner and stage. Something the authority held must remain.
    Abandoned,
    /// The last handle of an abandoned scope dropped: its release is the
    /// scope's terminal drain, which may release the handle's own record, the
    /// queued and active records, the storage their payloads held and the
    /// scope block the handle reported as shared custody. Nothing it held
    /// remains.
    LastReference,
    /// A value whose own drop releases the ordinary storage it holds (a
    /// borrowed operation's arenas, a plan, an encoding, a document, a
    /// string): every ordinary permit it reported is released, and it holds
    /// no record block.
    Released,
    /// A stopped operation dropped: of what it held, its granted, unowned
    /// blocks may be released and every `Handle` record must queue; nothing
    /// else it held is released or restaged, and its surroundings stay
    /// intact.
    Stopped,
    /// An exhausted operation wrapper dropped: it reports no permit of its
    /// own, so none is released and none changes stage or owner.
    Exhausted,
    /// A published owning handle dropped: its record transfers to the scope
    /// queue, `Handle` to `Queued`; nothing is released.
    Published,
    /// A granted, unowned record block cancelled: at least one `Granted`
    /// block released, nothing else released; no permit changes stage.
    GrantedCancelled,
    /// A handle's own cleanup completed: at least one `Handle` record
    /// released, with the ordinary permits its payload held; no record of
    /// another stage released.
    HandleReclaimed,
    /// Queued cleanup completed: at least one `Active` record released, with
    /// the ordinary permits its payload held; no record of another stage
    /// released.
    ActiveReclaimed,
}

/// Every permit `custody` reports, by identity: its owner and its record
/// stage.
fn reported_permits(
    custody: &[refinement::Custody],
) -> std::collections::BTreeMap<Identity, (Identity, Option<dcbor::bounded::RecordStage>)> {
    custody
        .iter()
        .flat_map(|group| {
            group
                .permits
                .iter()
                .map(move |reported| (reported.permit, (group.owner, reported.record)))
        })
        .collect()
}

/// Every way the custody `after` a retirement departs from what `kind`
/// permits of the custody `before` it, compared by permit identity and
/// record stage ([`Retirement`]), each named. Empty for a legal retirement.
/// `owned` names the permits the retired value itself reported before its
/// destruction; every other permit is surrounding custody (its scope, a
/// published output), which no retirement may release, move or restage.
/// The positive rules apply to the value alone: a published handle, and a
/// stopped operation's own handle, must queue every `Handle` record it held
/// directly; an exhausted wrapper holds nothing. A record held in another
/// record's payload is that record's custody: `within`, the records each
/// record payload held before the retirement ([`Collected::within`]), places
/// it. A `Handle` record inside a record the retirement queued stays a
/// handle until the queue's cleanup steps its container; a record of any
/// stage inside a record the retirement legally released is released with
/// its container's payload.
fn retirement_violations(
    before: &[refinement::Custody],
    after: &[refinement::Custody],
    within: &std::collections::BTreeMap<Identity, Identity>,
    owned: &std::collections::BTreeSet<Identity>,
    kind: Retirement,
) -> Vec<String> {
    use dcbor::bounded::RecordStage;
    let (before, after) = (reported_permits(before), reported_permits(after));
    let mut violations = Vec::new();
    let queues = matches!(kind, Retirement::Published | Retirement::Stopped);
    // The value's handles the retirement queued.
    let queued: std::collections::BTreeSet<Identity> = before
        .iter()
        .filter(|(permit, (owner, stage))| {
            owned.contains(*permit)
                && *stage == Some(RecordStage::Handle)
                && after.get(*permit) == Some(&(*owner, Some(RecordStage::Queued)))
        })
        .map(|(permit, _)| *permit)
        .collect();
    // A record held, directly or through further payloads, in a record the
    // retirement queued.
    let in_queued = |permit: &Identity| {
        let mut at = *permit;
        while let Some(container) = within.get(&at) {
            if queued.contains(container) {
                return true;
            }
            at = *container;
        }
        false
    };
    if kind == Retirement::Exhausted && !owned.is_empty() {
        violations.push(format!(
            "Exhausted: the wrapper held permits {owned:?}, an exhausted wrapper holds nothing"
        ));
    }
    if kind == Retirement::Published && queued.is_empty() {
        violations.push("Published: no Handle record queued".to_owned());
    }
    for (permit, (owner, stage)) in &after {
        match before.get(permit) {
            None => violations.push(format!(
                "{kind:?}: permit {permit:?} appeared under {owner:?}, a retirement acquires nothing"
            )),
            Some((was_owner, _)) if was_owner != owner => violations.push(format!(
                "{kind:?}: permit {permit:?} moved from owner {was_owner:?} to {owner:?}"
            )),
            Some((_, was)) if !owned.contains(permit) => {
                if was != stage {
                    violations.push(format!(
                        "{kind:?}: surrounding permit {permit:?} moved from {was:?} to {stage:?}"
                    ));
                }
            }
            Some((_, was)) => {
                if matches!(
                    kind,
                    Retirement::Scope | Retirement::Released | Retirement::LastReference
                ) {
                    violations.push(format!(
                        "{kind:?}: owned permit {permit:?} remained after its destruction"
                    ));
                }
                let queued =
                    *was == Some(RecordStage::Handle) && *stage == Some(RecordStage::Queued);
                // A handle left a handle inside a record this retirement
                // queued is that record's payload, not the value's own.
                let nested = *was == Some(RecordStage::Handle)
                    && *stage == Some(RecordStage::Handle)
                    && in_queued(permit);
                if queues && *was == Some(RecordStage::Handle) && !queued && !nested {
                    violations.push(format!(
                        "{kind:?}: the value's Handle record {permit:?} was not queued, it is {stage:?}"
                    ));
                } else if was != stage && !(queues && queued) {
                    violations.push(format!(
                        "{kind:?}: permit {permit:?} moved from {was:?} to {stage:?}"
                    ));
                }
            }
        }
    }
    let released: Vec<(Identity, Option<RecordStage>)> = before
        .iter()
        .filter(|(permit, _)| !after.contains_key(permit))
        .map(|(permit, (_, stage))| (*permit, *stage))
        .collect();
    for &(permit, stage) in &released {
        if !owned.contains(&permit) {
            violations.push(format!(
                "{kind:?}: surrounding permit {permit:?} of stage {stage:?} released"
            ));
        }
    }
    let released: Vec<(Identity, Option<RecordStage>)> = released
        .into_iter()
        .filter(|(permit, _)| owned.contains(permit))
        .collect();
    if kind == Retirement::Abandoned && !owned.iter().any(|permit| after.contains_key(permit)) {
        violations.push(
            "Abandoned: nothing the authority held remains, a scope retirement instead".to_owned(),
        );
    }
    let (required, payload) = match kind {
        Retirement::Scope
        | Retirement::Abandoned
        | Retirement::Released
        | Retirement::LastReference => (None, true),
        Retirement::Exhausted | Retirement::Published => (None, false),
        Retirement::GrantedCancelled | Retirement::Stopped => (Some(RecordStage::Granted), false),
        Retirement::HandleReclaimed => (Some(RecordStage::Handle), true),
        Retirement::ActiveReclaimed => (Some(RecordStage::Active), true),
    };
    // A release `kind` permits of a permit of `stage` on its own.
    let direct = |stage: Option<RecordStage>| match stage {
        None => payload,
        Some(stage) => {
            Some(stage) == required
                || (matches!(kind, Retirement::Scope | Retirement::Abandoned)
                    && matches!(stage, RecordStage::Queued | RecordStage::Active))
                || (kind == Retirement::LastReference
                    && matches!(
                        stage,
                        RecordStage::Handle | RecordStage::Queued | RecordStage::Active
                    ))
        }
    };
    let released_stage: std::collections::BTreeMap<Identity, Option<RecordStage>> =
        released.iter().copied().collect();
    // A record released inside a record this retirement released on its own
    // right, directly or through further payloads: its container's payload.
    let in_released = |permit: &Identity| {
        let mut at = *permit;
        while let Some(container) = within.get(&at) {
            if released_stage
                .get(container)
                .is_some_and(|&stage| direct(stage))
            {
                return true;
            }
            at = *container;
        }
        false
    };
    for &(permit, stage) in &released {
        let legal = direct(stage) || (stage.is_some() && in_released(&permit));
        if !legal {
            violations.push(format!(
                "{kind:?}: permit {permit:?} of stage {stage:?} released"
            ));
        }
    }
    if kind != Retirement::Stopped
        && let Some(required) = required
        && !released.iter().any(|&(_, stage)| stage == Some(required))
    {
        violations.push(format!("{kind:?}: no {required:?} record released"));
    }
    violations
}

/// The one retirement orchestration ([`RecordedRun::holding`]): the custody
/// `observe` reports with `value` (`Some`) checkpointed before, and the
/// surroundings it reports without it (`None`) read at the same moment to
/// classify the value's own permits; `value` destroyed inside `window`,
/// any physical allocation or destructor panic kept as a
/// defect; the custody after (`None`) checkpointed once the recording is
/// still evidence ([`capture_collected`] names a recording that is not);
/// and every departure from `kind` kept as a defect
/// ([`retirement_violations`]), compared on exactly the two checkpointed
/// observations. Observer and destructor panics become findings independently:
/// failed observation never skips destruction or supplies partial evidence.
fn retired<T, W: pipeline::Physical>(
    session: &Recording,
    checkpoints: &mut refinement::History,
    defects: &mut Vec<Finding>,
    kind: Retirement,
    value: T,
    observe: impl FnMut(Option<&mut T>, &mut dyn CustodySink<Permit>) -> PermitsObserved,
    window: &W,
) {
    retired_by(
        session,
        checkpoints,
        defects,
        kind,
        value,
        observe,
        window,
        |value| window.window(|| drop(value)),
    );
}

/// [`retired`], the value destroyed by `destroy` rather than dropped inside
/// `window`: the one retirement orchestration, whose destruction a holding
/// whose members are destroyed on worker threads supplies
/// ([`Holding::retire_concurrently`]). `window` still witnesses the
/// physical requests around the destruction.
#[expect(
    clippy::too_many_arguments,
    reason = "the run's evidence, the value, its observation, its witness and its destruction"
)]
fn retired_by<T, W: pipeline::Physical>(
    session: &Recording,
    checkpoints: &mut refinement::History,
    defects: &mut Vec<Finding>,
    kind: Retirement,
    mut value: T,
    mut observe: impl FnMut(Option<&mut T>, &mut dyn CustodySink<Permit>) -> PermitsObserved,
    window: &W,
    destroy: impl FnOnce(T),
) {
    // Keep the value outside the observation's unwind frame. An observer
    // failure must not invoke its destructor outside the physical window.
    let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The custody before, checkpointed, with the records each record
        // payload holds ([`Collected::within`]): the containment every rule of
        // the comparison reads, a property of the custody the retirement
        // starts from.
        let (custody, within) = match collected(|sink| observe(Some(&mut value), sink)) {
            Ok(Collected { custody, within }) => (Ok(custody), within),
            Err(unobserved) => (Err(unobserved), std::collections::BTreeMap::new()),
        };
        let before =
            capture_collected(session, checkpoints, defects, custody).map(|(_, before)| before);
        // The surrounding custody at the same moment, the value withheld: a
        // read-only classification, never a checkpoint. The value's own permits
        // are those the checkpointed observation adds to it, the custody the
        // positive rules of its kind apply to ([`retirement_violations`]).
        let surrounding = collect(|sink| observe(None, sink));
        let owned: Option<std::collections::BTreeSet<Identity>> = match (&before, surrounding) {
            (Some(before), Ok(surrounding)) => {
                let surrounding = reported_permits(&surrounding);
                Some(
                    reported_permits(before)
                        .into_keys()
                        .filter(|permit| !surrounding.contains_key(permit))
                        .collect(),
                )
            }
            (Some(_), Err(unobserved)) => {
                defects.push(Finding::Defect(format!(
                    "a retirement's surrounding custody is no observation: {unobserved:?}"
                )));
                None
            }
            (None, _) => None,
        };
        (before.map(|before| (before, within)), owned)
    }));
    let (before, owned) = match observation {
        Ok(observation) => observation,
        Err(payload) => {
            defects.push(Finding::Defect(format!(
                "pre-retirement observation panicked: {}",
                panic_report(payload.as_ref())
            )));
            (None, None)
        }
    };
    let requests = window.requests();
    let destruction = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| destroy(value)));
    let after_requests = window.requests();
    if after_requests != requests {
        defects.push(Finding::Defect(format!(
            "{kind:?}: retirement allocated: physical requests {requests:?} -> {after_requests:?}"
        )));
    }
    if let Err(payload) = destruction {
        defects.push(Finding::Defect(format!(
            "retirement destructor panicked: {}",
            panic_report(payload.as_ref())
        )));
    }
    let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        capture_collected(
            session,
            checkpoints,
            defects,
            collect(|sink| observe(None, sink)),
        )
        .map(|(_, after)| after)
    }));
    let after = match observation {
        Ok(after) => after,
        Err(payload) => {
            defects.push(Finding::Defect(format!(
                "post-retirement observation panicked: {}",
                panic_report(payload.as_ref())
            )));
            None
        }
    };
    // A malformed observation was named by its capture; only two whole
    // observations, the value's custody classified, are compared.
    if let (Some((before, within)), Some(after), Some(owned)) = (before, after, owned) {
        defects.extend(
            retirement_violations(&before, &after, &within, &owned, kind)
                .into_iter()
                .map(Finding::Defect),
        );
    }
}

impl RecordedRun {
    /// Borrow registered policies and parent-held custody into scoped workers.
    /// Factory, spawn, task and join unwinds cannot take the batch out of its
    /// holding. Findings remain in parent storage even if a worker unwinds.
    /// Every spawned worker is joined before observed parent retirement;
    /// recording loss and task panics stop that worker's remaining fixtures.
    pub fn workers<C: Custodial<Permit> + Send>(
        &mut self,
        policies: &[PolicyId],
        repetitions: usize,
        retirement: Retirement,
        make: impl Fn(usize) -> C,
        task: impl Fn(usize, usize, &mut C, &mut Limits) -> Result<(), Finding> + Sync,
    ) -> Result<(), Finding> {
        let mut selected = std::collections::BTreeMap::new();
        for (worker, policy) in policies.iter().enumerate() {
            assert!(
                policy.0 < self.policies.len(),
                "worker policy is not registered"
            );
            assert!(
                selected.insert(policy.0, worker).is_none(),
                "workers cannot borrow the same policy twice"
            );
        }
        self.holding(
            CustodyBatch::with_capacity(policies.len()),
            retirement,
            &pipeline::Unwitnessed,
            |batch| {
                // Each successful factory result enters parent custody before
                // another factory can unwind. Workers receive only borrows.
                for worker in 0..policies.len() {
                    batch.value.get().retain(make(worker));
                }
                let mut assigned: Vec<_> = batch
                    .run
                    .policies
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(index, policy)| {
                        selected.get(&index).map(|worker| (*worker, policy))
                    })
                    .collect();
                assigned.sort_by_key(|(worker, _)| *worker);
                let mut reports: Vec<Vec<Finding>> =
                    (0..policies.len()).map(|_| Vec::new()).collect();
                let mut jobs: Vec<_> = assigned
                    .into_iter()
                    .zip(batch.value.get().held())
                    .zip(&mut reports)
                    .collect();
                let failures =
                    joined_batch(&mut jobs, |_, (((worker, policy), held), findings)| {
                        for fixture in 0..repetitions {
                            if let Some(lost) = lost(policy, fixture) {
                                findings.push(Finding::Lost {
                                    lost,
                                    outcome: format!(
                                        "worker {worker} stopped before fixture {fixture}"
                                    ),
                                });
                                break;
                            }
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    task(*worker, fixture, held, policy)
                                }));
                            match result {
                                Ok(Ok(())) => {}
                                Ok(Err(finding @ Finding::Lost { .. })) => {
                                    findings.push(finding);
                                    break;
                                }
                                Ok(Err(finding)) => {
                                    findings.push(Finding::Defect(format!(
                                        "worker {worker}, fixture {fixture}: {finding}"
                                    )));
                                }
                                Err(payload) => {
                                    findings.push(Finding::Defect(format!(
                                        "worker {worker}, fixture {fixture}: {}",
                                        panic_report(payload.as_ref())
                                    )));
                                    break;
                                }
                            }
                        }
                    });
                drop(jobs);
                let mut findings = reports.into_iter().flatten().chain(failures);
                let first = findings.next();
                batch.run.defects.extend(findings);
                match first {
                    Some(finding) => Err(finding),
                    None => Ok(()),
                }
            },
        )
    }

    /// Own custody through computation, error propagation and unwinding.
    /// Results must be detached from the held custody.
    pub fn holding<T: Custodial<Permit>, W: pipeline::Physical, R>(
        &mut self,
        value: T,
        retirement: Retirement,
        window: &W,
        body: impl FnOnce(&mut Holding<'_, '_, T, W>) -> R,
    ) -> R {
        Holding {
            run: self,
            surrounding: &mut EmptyCustody,
            value: Held(Some(value)),
            retirement,
            window,
            publication: None,
        }
        .execute(body)
    }

    /// A new policy of this run, `capacity` live bytes, the admission
    /// oracle's ([`recorded_policy`]).
    pub fn policy(&mut self, capacity: u64) -> PolicyId {
        self.adopt(recorded_policy(&self.session, capacity, false))
    }

    /// A recorded cumulative work allowance for synchronous bounded calls.
    pub fn budget(&mut self, work: WriteWork, capacity: u64) -> PolicyId {
        self.adopt(recorded_allowance(&self.session, work, capacity, false))
    }

    /// A new policy of this run, `capacity` live bytes, that also reports
    /// each admitted allocation to the heap observer
    /// ([`recorded_policy`]): for a fixture that witnesses physical
    /// storage.
    pub fn observed_policy(&mut self, capacity: u64) -> PolicyId {
        self.adopt(recorded_policy(&self.session, capacity, true))
    }

    /// A new policy of this run as the physical witness `W` makes it
    /// ([`pipeline::Physical::policy`]): the heap guard's natively, the
    /// admission oracle's alone in a model.
    pub fn witnessed_policy<W: pipeline::Physical>(&mut self) -> PolicyId {
        self.adopt(W::policy(&self.session))
    }

    /// The session boundary now ([`dcbor::bounded::Session::boundary`]):
    /// the observations recorded so far, where a driver's mark (a
    /// checkpoint, cleanup's start, a publication) is placed. Panics naming
    /// why the recording is no evidence.
    pub fn boundary(&self) -> usize {
        boundary(&self.session)
    }

    fn adopt(&mut self, policy: Limits) -> PolicyId {
        self.policies.push(policy);
        PolicyId(self.policies.len() - 1)
    }

    /// Keep a policy share in this run, with its own trace and the original
    /// family's storage and credit accounting.
    pub fn shared_policy(&mut self, id: PolicyId) -> PolicyId {
        let share = self.with_policy(id, |policy| policy.share());
        self.adopt(share)
    }

    /// `body` under policy `id`, borrowed for the call: an operation kept
    /// outside the borrow resumes under any policy of the run, in turn.
    pub fn with_policy<R>(&mut self, id: PolicyId, body: impl FnOnce(&mut Limits) -> R) -> R {
        let policy = self
            .policies
            .get_mut(id.0)
            .expect("a policy handle names a policy of the run that issued it");
        body(policy)
    }

    /// Place the run's custody, observed at a driver boundary where none of
    /// it can change by `observe` (the production traversal of everything
    /// the run holds, each custody's `observe_custody` in turn), at this
    /// run's session boundary taken after the observation succeeds
    /// ([`dcbor::bounded::Session::boundary`]): replayed with the session's
    /// observations before it and compared at finalization. The observation
    /// is collected whole first ([`collect`]); one that is no observation
    /// is the run's defect, kept without unwinding ([`capture`]): no
    /// checkpoint, partial or whole, is stored, and the run fails at its
    /// finalization naming it.
    pub fn checkpoint(
        &mut self,
        observe: impl FnOnce(&mut dyn CustodySink<Permit>) -> PermitsObserved,
    ) {
        capture(
            &self.session,
            &mut self.checkpoints,
            &mut self.defects,
            observe,
        );
    }

    /// Read the run's finished evidence with `inspect`, after the run's
    /// mandatory checks pass: a fixture's own assertions over the stream and
    /// the checkpoints the run took, the same ones the machine refined.
    pub fn inspect_evidence(
        &mut self,
        inspect: impl FnOnce(&[Observed], &refinement::History) + 'static,
    ) {
        self.inspections.push(Box::new(inspect));
    }

    /// Record a defect the fixture detected (`finding`, its diagnostic)
    /// without unwinding, so the fixture can still drop every capability it
    /// holds and the run still reaches its finalization: the run then fails
    /// at its finalization, reporting every recorded defect beside what its
    /// recording actually finished as ([`recorded_run`]). A planted defect
    /// that also leaks a capability is reported with its own diagnostic and
    /// the recording's refusal both; one the recording does not show is not
    /// erased by a finalization that succeeds.
    pub fn defect(&mut self, finding: impl Into<Finding>) {
        self.defects.push(finding.into());
    }
}

/// Run `body` as one recorded run, then finish it: the one authority over a
/// recorded run's life. The run's recording session is made first
/// ([`CAPACITY`]); `body` makes its policies, runs its operation and its
/// semantic assertions, and returns only detached data: its result, or the
/// finding that stopped it ([`Finding`]), a driver's stop among them,
/// returned once the body dropped every operation, owner and output it
/// held, so nothing it held outlives it. Then, in order:
/// each policy's counters are checked against its recorded history, every
/// finding kept as detached data ([`correspondence`]); the policies are
/// dropped; the session is finished, refused naming why when anything that
/// can publish into it still lives (an operation, owner, permit or output
/// `body` kept), and its whole stream and every checkpoint go through the
/// refinement machine ([`finalize`]); and the fixture's own readings run. No
/// step is optional, and none runs in a destructor: a fixture that panics
/// has already failed. A body that returned a finding, a fixture that
/// recorded a defect ([`RecordedRun::defect`]) instead of panicking, and a
/// policy whose history disagrees with its counters, reach finalization
/// too: no later mandatory check can skip it. The run then fails naming
/// every finding, every correspondence finding and what the recording
/// finished as ([`describe`]); acceptance stays strict, any finding alone
/// failing the run.
pub fn recorded_run<R>(body: impl FnOnce(&mut RecordedRun) -> Result<R, Finding>) -> R {
    recorded_run_with(CAPACITY, ExpectedVerdict::Accepted, body)
}

/// [`recorded_run`] into a recording shorter than the default: `capacity`
/// within [`CAPACITY`] in both dimensions and below it in at least one, so
/// the run can witness its recording's exhaustion. The one public sizing of
/// a recording apart from a measured budget ([`budgets`]): a recording no
/// fixture outgrows by design is never enlarged by hand. Exhaustion remains
/// a failed recording; finalization is identical to [`recorded_run`].
pub fn recorded_run_short<R>(
    capacity: Capacity,
    body: impl FnOnce(&mut RecordedRun) -> Result<R, Finding>,
) -> R {
    assert!(
        capacity.events <= CAPACITY.events
            && capacity.permits <= CAPACITY.permits
            && (capacity.events < CAPACITY.events || capacity.permits < CAPACITY.permits),
        "a short recording of {capacity:?} is not shorter than the default {CAPACITY:?}: \
         a recording is enlarged only by its measured budget (budgets::Budgets)"
    );
    recorded_run_with(capacity, ExpectedVerdict::Accepted, body)
}

/// A negative control over a complete recording: [`recorded_run`]'s one
/// finalization, requiring the machine to refuse with exactly `expected`.
/// An incomplete recording, an unexpected acceptance, or another divergence
/// fails the control.
pub fn recorded_control<R>(
    expected: refinement::Divergence,
    body: impl FnOnce(&mut RecordedRun) -> Result<R, Finding>,
) -> R {
    recorded_run_with(CAPACITY, ExpectedVerdict::Rejected(expected), body)
}

/// The one recorded-run finalization ([`recorded_run`]), against `expected`.
/// The body's finding joins the run's own, and the run finalizes once.
fn recorded_run_with<R>(
    capacity: Capacity,
    expected: ExpectedVerdict,
    body: impl FnOnce(&mut RecordedRun) -> Result<R, Finding>,
) -> R {
    recorded_evidence(capacity, expected, body).0
}

/// Execute and finalize once, returning detached results beside accepted evidence.
/// Drivers attach that evidence to their reports only after all mandatory checks.
fn recorded_evidence<R>(
    capacity: Capacity,
    expected: ExpectedVerdict,
    body: impl FnOnce(&mut RecordedRun) -> Result<R, Finding>,
) -> (R, Vec<Observed>) {
    let mut run = RecordedRun {
        session: Recording::new(capacity),
        policies: Vec::new(),
        checkpoints: refinement::History::new(),
        inspections: Vec::new(),
        defects: Vec::new(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut run)))
        .unwrap_or_else(|payload| Err(Finding::Defect(panic_report(payload.as_ref()))));
    let RecordedRun {
        session,
        policies,
        checkpoints,
        inspections,
        mut defects,
    } = run;
    let result = result.map_err(|finding| defects.push(finding));
    let observed = concluded(session, policies, &checkpoints, &defects, expected);
    for inspect in inspections {
        inspect(&observed, &checkpoints);
    }
    match result {
        Ok(result) => (result, observed),
        Err(()) => unreachable!("the finalization refuses a run holding a finding"),
    }
}

/// The error of a production call made outside a driver (one step, unit or
/// one-shot call) where its fixture requires success, classified there as
/// the run's finding, named by `what`: a fixture's own schedule, like a
/// driver's, ends with its finding returned, never a panic.
pub fn failed<E: Debug>(what: &str) -> impl FnOnce(E) -> Finding + '_ {
    move |error| Finding::Driver(format!("{what} failed: {error:?}"))
}

/// The message a panic carries: a `String` or `&str` payload's, or a
/// placeholder for any other. The one reader of a caught panic's report,
/// for a witness that requires a run to fail naming what it found.
pub fn panic_report(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "a panic of no message".to_owned()
    }
}

/// The one ending of every recorded run, the scoped runner's and the
/// drivers' that own their session whole ([`construction_requests`],
/// `pipeline`): each of `policies` read against its recorded history
/// ([`correspondence`]), every finding kept; the policies dropped; the
/// session finished and refined ([`finalize`]). With a finding (`defects`)
/// or a correspondence finding, the run fails naming each and what the
/// recording finished as ([`describe`]); otherwise the finished stream is
/// held to `expected` ([`settled`]'s [`enforce`]) and returned. No
/// mandatory check comes before the session's finish that could skip it.
fn concluded(
    session: Recording,
    policies: Vec<Limits>,
    checkpoints: &refinement::History,
    defects: &[Finding],
    expected: ExpectedVerdict,
) -> Vec<Observed> {
    let mismatches: Vec<String> = policies
        .iter()
        .enumerate()
        .filter_map(|(index, policy)| {
            correspondence(policy)
                .err()
                .map(|finding| format!("policy {index}: {finding}"))
        })
        .collect();
    drop(policies);
    if !defects.is_empty() || !mismatches.is_empty() {
        let finalized = describe(&finalize(session, checkpoints));
        let mut report = String::new();
        if !defects.is_empty() {
            let rendered: Vec<String> = defects.iter().map(ToString::to_string).collect();
            report += &format!(
                "the run found {} defect(s): {}; ",
                defects.len(),
                rendered.join("; ")
            );
        }
        if !mismatches.is_empty() {
            report += &format!(
                "{} correspondence finding(s): {}; ",
                mismatches.len(),
                mismatches.join("; ")
            );
        }
        panic!("{report}finalization: {finalized}");
    }
    settled(session, checkpoints, expected)
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
        dcbor::bounded::decode::cursor::retained_decode_bound::<
            dcbor::bounded::Reservation,
            dcbor::bounded::Family,
            (),
        >(len as u64, any_depth(len))
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

/// The turn bound for a typed decode of `T` from a borrowed input of `len`
/// bytes under `options` (`decode::construction::typed_decode_bound`): the
/// bound of the scope's decode ([`Holding::decoded`], [`Holding::decoder`]).
pub fn borrowed_decode_turns<T: InPlace<Limits>>(len: usize, options: Options) -> usize {
    turns(
        dcbor::bounded::decode::construction::typed_decode_bound::<Borrowed<'_>, T, Limits, ()>(
            len as u64, options,
        )
        .expect("typed decode bound fits in u64"),
    )
}

/// The turn bound for a string decode of arbitrary input of `len` bytes
/// (`decode::string_cursor::string_bound`).
pub fn string_turns(len: usize) -> usize {
    turns(
        dcbor::bounded::decode::string_cursor::string_bound::<
            dcbor::bounded::Reservation,
            dcbor::bounded::Family,
            (),
        >(len as u64, any_depth(len))
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
        dcbor::bounded::encoding::prepare_bound::<
            dcbor::bounded::Reservation,
            dcbor::bounded::Family,
            (),
        >(shape)
        .expect("the preparation bound of a source held in memory fits in u64"),
    )
}

/// The shape of `source`, walked unmetered.
pub fn shape(source: &dyn dcbor::bounded::encoding::Schema) -> dcbor::bounded::encoding::Shape {
    dcbor::bounded::encoding::Shape::of(source, &mut Limits::unlimited())
        .expect("the source is within the engine's limits")
}

/// The custody observation of `T`'s construction at the root: its root
/// session's stage and the binding's own observation
/// (`in_place::SessionObservation`), which every relation, class and
/// reduction at the root reads.
pub type Observation<T> = <Session<<T as Reclaim<Limits>>::State> as Custody>::Observation;

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
/// cleanup unit; every transition between observations, by build steps that
/// made progress or rejected the input (a refused step is none) and by
/// admitted cleanup units; the bytes of every allocation request it was granted,
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
    /// The construction policy's performer in the run's session: whose
    /// grants [`Self::allocations`] are. The document it builds from is
    /// parsed under a policy of its own in the same session.
    pub performer: Performer,
    pub snapshots: Vec<Snapshot<O>>,
    /// The run's recording session, finished once construction, cleanup,
    /// the driver and the policy are gone, and refined: every observation in
    /// its one order, the stream the refinement machine accepted.
    pub observed: Vec<Observed>,
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
            performer: self.performer,
            snapshots: self
                .snapshots
                .iter()
                .map(|snapshot| Snapshot {
                    observation: project(&snapshot.observation),
                    live: snapshot.live,
                    physical: snapshot.physical,
                })
                .collect(),
            observed: self.observed,
        }
    }
}

/// The bound of constructing `T` at the root from `wire` and cleaning it up:
/// its cost and its root session's transitions
/// (`in_place::root_cost`), as the standalone driver charges them.
pub fn root_bound<T: InPlace<Limits>>(wire: &[u8]) -> dcbor::bounded::ResourceBound {
    dcbor::bounded::decode::construction::in_place::root_cost(T::COST)
        .expect("the root cost of a fixture fits in u64")
        .bound::<()>(wire.len() as u64)
        .expect("the cost of a fixture fits in u64")
}

/// A custody observation `observe` takes, taken twice: the two are equal,
/// and observing admits nothing and changes no live byte.
fn observe_custody<O: PartialEq + Debug>(
    mut observe: impl FnMut() -> O,
    m: &Limits,
    heap: &heap::Observation,
    at: &str,
) -> O {
    let (attempts, live) = (m.attempts(), m.live_bytes());
    let physical = heap.snapshot();
    let first = heap.window(&mut observe);
    let second = heap.window(&mut observe);
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

/// Storage whose initialized prefix is owned and observed by its standalone
/// driver. The driver borrows this slot until reclamation finishes.
struct Destination<T>(MaybeUninit<T>);

impl<T> Custodial<Permit> for Destination<T> {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// Construct `T` in place from the root of canonical `wire`, one quantum per
/// step, to completion or to its terminal error, or, when `cancel` names a
/// build step, until that step and no further; `inspect` a built value;
/// then reclaim it to `Done`, every cleanup unit refused once before it is
/// admitted. Both run under one policy of their own: the document is parsed
/// under another policy of the same recorded run, held by the run until the
/// construction is reclaimed, its parse not measured; no scope record is
/// involved; the run records into the default capacity ([`CAPACITY`],
/// [`budgets::Budgets::construction`] for a measured one). The work, requests and
/// storage measured are exactly what `InPlace::COST` bounds, which refusals
/// do not change. The state is observed after every build step and every
/// cleanup unit ([`Custody`]), and the construction's custody, its one
/// grouped production traversal (`Standalone::observe_custody`), is
/// checkpointed at the session boundary there too ([`capture`]), from the
/// initial state on: the refinement machine compares each with the custody
/// the observations before it reach, owner by owner, at finalization
/// ([`settled`]). A refused build step, after any number of attempts, must
/// leave the observation unchanged and is no transition: what it admitted is
/// the pending custody the checkpoint reports. A cleanup unit whose only
/// attempt was refused must leave the observation unchanged, and no refusal
/// may change what is held. Steps are bounded by `T`'s cost. The heap observer is armed around
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

/// [`construction`] of the whole value into a recording of `capacity`, the
/// budget its fixture was measured to need ([`measured`]): a construction
/// whose session outgrows [`CAPACITY`].
fn construction_in<T: InPlace<Limits>>(
    wire: &[u8],
    capacity: Capacity,
    inspect: impl FnOnce(&T),
) -> Constructed<Observation<T>> {
    construction_under::<T>(wire, None, 0, capacity, inspect).0
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
    construction_under::<T>(wire, cancel, requests, CAPACITY, inspect)
}

/// The one observed construction driver ([`construction_requests`]),
/// recording into `capacity`.
fn construction_under<T: InPlace<Limits>>(
    wire: &[u8],
    cancel: Option<usize>,
    requests: usize,
    capacity: Capacity,
    inspect: impl FnOnce(&T),
) -> (Constructed<Observation<T>>, RefusalRun) {
    let bound = turns(root_bound::<T>(wire));
    assert!(
        heap::installed(),
        "the observed construction witnesses physical storage: install heap::Heap as the \
         binary's global allocator"
    );
    let ((mut constructed, accounting), observed) = recorded_evidence(
        capacity,
        ExpectedVerdict::Accepted,
        |run| {
            let parsing = run.policy(u64::MAX);
            let document = run.with_policy(parsing, |m| {
                dcbor::bounded::decode::decode(wire, 64, m).expect("the fixture parses")
            });
            let policy = run.observed_policy(u64::MAX);
            run.with_policy(policy, |m| m.fail_requests(requests));
            let observer = heap::Observation::begin(None);
            observer.stop();
            let physical = || observer.snapshot().live as u64;
            run.holding(document, Retirement::Released, &pipeline::Unwitnessed, |document| {
              document.lending(Retirement::Exhausted, Lent::new, |document| {
                let source = document.value().get();
                document.holding(Destination(MaybeUninit::<T>::uninit()), Retirement::Exhausted, |destination| {
                  destination.standalone(source, policy, bound, &observer, |held| {
            // The value is built at the root through the engine's standalone
            // driver: its root session binds node 0 of this document, and every
            // build, the count and cleanup go through it. The session's
            // observation, its stage with the binding's own, is what the root
            // relation and classes read; its stage transitions are checked here.
            let (mut previous, mut attempts, mut live, mut stage) = held.with_policy(policy, |driver, m| {
            assert_eq!(
                driver.stage(),
                Stage::Unbound,
                "a new driver's session is bound"
            );
            let previous =
                observe_custody(|| driver.observe(), m, &observer, "the initial state");
            // The construction's custody at each session boundary the driver
            // reaches, its observation taken with the heap observer stopped: the
            // collection allocates, and is no part of the construction.
            (previous, m.attempts(), m.live_bytes(), driver.stage())
            });
            let mut snapshots = vec![Snapshot {
                observation: previous,
                live,
                physical: physical(),
            }];
            let mut building = Vec::new();
            let mut built = false;
            let mut rejected = false;
            let mut steps = 0;
            let build_bound = bound
                .checked_add(requests)
                .expect("request retry bound fits");
            let result = held.build_standalone(policy, build_bound, cancel, |driver, m, result| {
                steps += 1;
                // The root session's stage: the first admitted unit binds node 0
                // as a standalone value, `Done` completes it, and nothing else
                // moves it.
                match (result, stage, driver.stage()) {
                    (
                        Ok(Step::Progress),
                        Stage::Unbound,
                        Stage::Building {
                            node: 0,
                            entry: Entry::Standalone,
                        },
                    )
                    | (
                        Ok(Step::Complete(())),
                        Stage::Building { .. },
                        Stage::Built {
                            node: 0,
                            entry: Entry::Standalone,
                        },
                    )
                    | (Ok(Step::Progress), Stage::Building { .. }, Stage::Building { .. }) => {}
                    (Err(_), before, after) if before == after => {}
                    (result, before, after) => {
                        panic!(
                            "build step {steps} moved the root session {before:?} to {after:?}: {result:?}"
                        )
                    }
                }
                let next = observe_custody(
                    || driver.observe(),
                    m,
                    &observer,
                    &format!("after build step {steps}"),
                );
                snapshots.push(Snapshot {
                    observation: next,
                    live: m.live_bytes(),
                    physical: physical(),
                });
                match result {
                    Ok(Step::Progress) => {
                        building.push((previous, next));
                        previous = next;
                    }
                    Ok(Step::Complete(())) => {
                        building.push((previous, next));
                        previous = next;
                        built = true;
                    }
                    Err(error) if error.refused() => {
                        assert!(
                            ordinary_exhaustion(m, error)
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
                        // A refused step is no transition, at any count of attempts:
                        // what it admitted before the refusal (an acquisition bound,
                        // its write admitted) is the operation's pending custody,
                        // reported by the custody observation and checkpointed above,
                        // never the binding's progress.
                        assert_eq!(
                            next,
                            previous,
                            "build step {steps}, refused after {} attempts, moved the binding's progress",
                            m.attempts() - attempts
                        );
                        if m.attempts() == attempts + 1 {
                            assert_eq!(m.live_bytes(), live, "refusal changed live storage");
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
                        // The rejecting step is the last, which [`legal`] holds to
                        // leaving the observation unchanged.
                        building.push((previous, next));
                        previous = next;
                        rejected = true;
                    }
                    Ok(Step::Finished) => panic!("construction finished without publication"),
                }
                attempts = m.attempts();
                live = m.live_bytes();
                stage = driver.stage();
            });
            match result {
                Ok(Some(())) => assert!(built),
                Ok(None) => assert_eq!(cancel, Some(steps)),
                Err(Stopped::Operation(error)) if error.class() == Class::Invalid => assert!(rejected),
                Err(stop) => return Err(Finding::from(stop)),
            }
            let (reached, accounting, held_bytes, retained, declared, mut before, mut stage, mut attempts, mut live, mut admitted) = held.with_policy(policy, |driver, m| {
            let reached = previous;
            let accounting = RefusalRun::of(m);
            let held = m.live_bytes();
            let retained = if built { held } else { 0 };
            if built {
                inspect(
                    driver
                        .value()
                        .expect("a completed construction's value is readable"),
                );
            }
            // The binding's declared cleanup count, read as an observation is: it
            // admits nothing and changes nothing, and the cleanup that follows takes
            // no more successful calls than it declares.
            let (attempts, live) = (m.attempts(), m.live_bytes());
            let declared = driver
                .remaining()
                .expect("the cleanup count of a fixture fits in u64");
            assert_eq!(
                (m.attempts(), m.live_bytes()),
                (attempts, live),
                "declaring the cleanup count admitted work or changed what is held"
            );
            refuse(m, pipeline::Refusal::Each);
            (reached, accounting, held, retained, declared, driver.observe(), driver.stage(), m.attempts(), m.live_bytes(), m.admitted_calls().len())
            });
            let mut cleanup = Vec::new();
            let mut cleaning = Vec::new();
            let mut unit = 0;
            // Every cleanup unit refused once, then admitted.
            held.reclaim_standalone(policy, bound, |driver, m, result| {
                let at = format!("after {steps} build steps, cleanup unit {unit}");
                match result {
                    Err(error) if error.refused() => {
                        if m.attempts() - attempts == 1 {
                            assert_eq!(
                                observe_custody(|| driver.observe(), m, &observer, &at),
                                before,
                                "{at}: a cleanup unit whose only attempt was refused moved"
                            );
                        }
                        assert_eq!(
                            driver.stage(),
                            stage,
                            "{at}: a refused unit moved the root session"
                        );
                        assert_eq!(m.live_bytes(), live, "{at}: a refusal changed what is held");
                    }
                    Ok(outcome) => {
                        // The root session's stage: an unbound session releases in
                        // one unit; a bound one begins cleanup in one unit, the
                        // binding unchanged by it; the binding's `Done` releases it.
                        match (stage, driver.stage(), *outcome) {
                            (Stage::Unbound, Stage::Released, Reclaimed::Done)
                            | (
                                Stage::Building { .. } | Stage::Built { .. },
                                Stage::Cleaning,
                                Reclaimed::Progress,
                            )
                            | (
                                Stage::Cleaning,
                                Stage::Cleaning,
                                Reclaimed::Progress | Reclaimed::Waiting,
                            )
                            | (Stage::Cleaning, Stage::Released, Reclaimed::Done) => {}
                            (before, after, outcome) => panic!(
                                "{at}: cleanup moved the root session {before:?} to {after:?}, {outcome:?}"
                            ),
                        }
                        let after = observe_custody(|| driver.observe(), m, &observer, &at);
                        snapshots.push(Snapshot {
                            observation: after,
                            live: m.live_bytes(),
                            physical: physical(),
                        });
                        cleaning.push((before, after));
                        let done = *outcome == Reclaimed::Done;
                        assert!(m.live_bytes() <= live, "{at}: cleanup acquired storage");
                        cleanup.push(CleanupUnit {
                            done,
                            released: live - m.live_bytes(),
                            admitted: m.admitted_calls()[admitted..].to_vec(),
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
                        }
                    }
                    Err(error) => panic!("{at}: cleanup failed: {error:?}"),
                }
                before = observe_custody(|| driver.observe(), m, &observer, &at);
                stage = driver.stage();
                attempts = m.attempts();
                live = m.live_bytes();
                admitted = m.admitted_calls().len();
                unit += 1;
            })?;
            held.with_policy(policy, |_, m| {
                            let allocations = m
                                .admitted_calls()
                                .into_iter()
                                .filter_map(|call| match call {
                                    Call::Allocate(bytes) => Some(bytes),
                                    Call::Work { .. } => None,
                                })
                                .collect();
                            let (used, requested, peak) =
                                (m.used(), m.requested_bytes(), m.peak_bytes());
                            Ok((
                                Constructed {
                                    used,
                                    requested,
                                    peak,
                                    retained,
                                    built,
                                    rejected,
                                    steps,
                                    reached,
                                    held: held_bytes,
                                    cleanup,
                                    building,
                                    cleaning,
                                    allocations,
                                    performer: dcbor::bounded::Budget::performer(m),
                                    snapshots,
                                    observed: Vec::new(),
                                },
                                accounting,
                            ))
            })
                  })
                })
              })
            })
        },
    );
    constructed.observed = observed;
    (constructed, accounting)
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
    // The root relation: the session's reduction over the binding's
    // (`in_place::Session`'s `Reduction`), what the root's cleanup reads.
    simulation::<T, <Session<T::State> as Reduction>::Class>(name, wire, |observation| {
        <Session<T::State> as Reduction>::class(observation)
    })
}

/// `complete` is the class, by `class`, of every state construction of `T`
/// from `wire` reaches complete: the claim a container's reduction rests on
/// ([`dcbor::bounded::decode::construction::Uniform`]). The production
/// check passes `T`'s declared reduction and complete class
/// ([`uniform`]); a planted complete class must fail it. Returns the reached
/// states.
pub fn complete_class<T: InPlace<Limits>, C: Ord + Debug>(
    name: &str,
    wire: &[u8],
    class: impl Fn(&Observation<T>) -> C,
    complete: C,
) -> Vec<Constructed<Observation<T>>> {
    let states = reached::<T>(name, wire);
    let built: Vec<_> = states.iter().filter(|state| state.built).collect();
    assert!(
        !built.is_empty(),
        "{name}: no construction of {} from {wire:02x?} completed",
        core::any::type_name::<T>()
    );
    for state in built {
        assert_eq!(
            class(&state.reached),
            complete,
            "{name}: a complete state of {} from {wire:02x?} is not of its declared complete \
             class",
            core::any::type_name::<T>()
        );
    }
    states
}

/// `T`'s declared reduction is a simulation of cleanup ([`certified`]) and
/// its declared complete class ([`complete_class`]) the class of every
/// complete state it reaches, building `T` from `wire`.
pub fn uniform<T>(name: &str, wire: &[u8]) -> Vec<Constructed<Observation<T>>>
where
    T: InPlace<Limits>,
    T::State: dcbor::bounded::decode::construction::Uniform,
{
    use dcbor::bounded::decode::construction::{Reduction, Uniform};
    complete_class::<T, _>(
        name,
        wire,
        <Session<T::State> as Reduction>::class,
        <Session<T::State> as Uniform>::COMPLETE,
    );
    certified::<T>(name, wire)
}

/// Every transition the reached `states` took is in the binding's successor
/// relations ([`legality::Legality`]), and its cleanup is exactly as long as
/// they say: each construction starts from the binding's initial
/// observation; every build step that made progress takes a build
/// transition, a last step that rejected the input must leave the
/// observation unchanged, and a refused step is no transition
/// ([`construction`] holds it unchanged); every admitted cleanup unit takes
/// a cleanup transition; and
/// the units remaining from the state each construction reached, and from
/// each state its cleanup passed through before completing, are exactly the
/// units that followed. Every observation is witnessed: the policy's live
/// bytes are exactly the granted bytes of the permits it claims, and the
/// heap observer's live bytes exactly those of the physical allocations it
/// claims ([`Snapshot`]). The first violation is named.
pub fn legal<I: Copy + Eq + Debug + 'static>(
    name: &str,
    states: &[Constructed<dcbor::bounded::decode::construction::in_place::SessionObservation<I>>],
    binding: &legality::Legality<I>,
) {
    // Every construction here is a root: its relation is the root
    // session's over the binding's own ([`legality::root`]).
    let legality = &legality::root(binding);
    for state in states {
        let at = format!("{name}, after {} build steps", state.steps);
        // The session is the evidence of what the policy's history reports:
        // every allocation the construction's policy was granted is one grant
        // it published; the document's, under the parsing policy, is not the
        // construction's. Every permit's lifecycle, each released exactly once
        // by identity, was refined when the construction finished ([`settled`]).
        assert_eq!(
            grants(&state.observed, state.performer),
            state.allocations.len(),
            "{at}: the session's grants differ from the allocations the run was granted"
        );
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
    let bound = root_bound::<T>(wire);
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

/// Require that one step reported `Progress`: anything else it reported, an
/// unexpected production outcome, is the run's finding, naming it. Outputs
/// need not be comparable or printable.
pub fn expect_progress<O, E: Debug>(result: Result<Step<O>, E>) -> Result<(), Finding> {
    match result {
        Ok(Step::Progress) => Ok(()),
        other => Err(Finding::Driver(format!(
            "expected Progress, got {}",
            label(&other)
        ))),
    }
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
    quantum(m, |m| (step(m), false))
}

/// One fresh scheduler turn of a step of `owner`'s scope ([`checked`]), the
/// scope's own position read before and after it: a step whose progress
/// spent the removal admission an earlier `Waiting` step retained
/// ([`ScopePosition::removal_admitted`](dcbor::bounded::decode::construction::reclamation::ScopePosition))
/// made progress on that admission, and needs none of its own. Every scope
/// step a driver checks goes through here.
pub fn scope_checked<'s, D: Scope<'s>, R: Outcome>(
    m: &mut Limits,
    owner: &mut D,
    step: impl FnOnce(&mut D, &mut Limits) -> R,
) -> R {
    quantum(m, |m| {
        let retained = owner.scope().position().removal_admitted;
        let result = step(owner, m);
        (
            result,
            retained && !owner.scope().position().removal_admitted,
        )
    })
}

/// The turn [`checked`] and [`scope_checked`] share: `step` returns its
/// result and whether it spent an admission retained from an earlier call,
/// which witnesses progress as an admission of its own does.
fn quantum<R: Outcome>(m: &mut Limits, step: impl FnOnce(&mut Limits) -> (R, bool)) -> R {
    violated(quantum_checked(m, step))
}

/// A checked result whose violation, if any, is a fixture's panic: the
/// fixture-facing form of [`quantum_checked`] and [`contract_checked`],
/// whose messages it keeps.
fn violated<R>((result, violation): (R, Option<String>)) -> R {
    if let Some(violation) = violation {
        panic!("{violation}");
    }
    result
}

/// The one turn check ([`quantum`]): the step's result and the first rule
/// of the turn it broke, as data, so a scheduler that owns the result (a
/// published output among it) keeps it through a violation: no refund of
/// admitted work, at most a quantum admitted, and progress witnessed by an
/// admission, a prepaid release or a retained admission spent.
fn quantum_checked<R: Outcome>(
    m: &mut Limits,
    step: impl FnOnce(&mut Limits) -> (R, bool),
) -> (R, Option<String>) {
    m.turn();
    let (before, attempts) = (m.used(), m.attempts());
    let releases = ReleaseWitness::capture(m);
    let (result, spent) = step(m);
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let after = m.used();
        if !(after.values >= before.values && after.bytes >= before.bytes) {
            Some(format!("admitted work refunded: {before:?} -> {after:?}"))
        } else if !(after.values - before.values <= TURN.values
            && after.bytes - before.bytes <= TURN.bytes)
        {
            Some(format!(
                "turn exceeded its quantum: {before:?} -> {after:?}"
            ))
        } else if result.progressed() && !(m.attempts() > attempts || releases.released(m) || spent)
        {
            Some(
                "reported progress without an admission or a prepaid release, and spent no \
             retained admission"
                    .to_owned(),
            )
        } else {
            None
        }
    }));
    let violation = match checked {
        Ok(violation) => violation,
        Err(payload) => Some(format!(
            "turn contract observation panicked: {}",
            panic_report(payload.as_ref()),
        )),
    };
    (result, violation)
}

/// One step of `operation` under the policy's current allowance, checked
/// against the [`Resumable`] contract ([`contract_checked`]), a violation
/// the fixture's panic.
pub fn contracted<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O) -> StepOf<O>
where
    O::Error: Debug,
{
    violated(contract_checked(m, operation))
}

/// The one [`Resumable`] contract check of a step: progress made an
/// admission or a prepaid release, and a step whose only admission attempt
/// was refused left the position unchanged. The step's result and the rule
/// it broke, as data ([`quantum_checked`]).
fn contract_checked<O: Resumable<Limits>>(m: &mut Limits, operation: &mut O) -> Checked<StepOf<O>>
where
    O::Error: Debug,
{
    contract_in(m, operation, &pipeline::Unwitnessed)
}

/// A step's outcome beside the contract rule it broke, if any: the data
/// form of a contract check ([`contract_in`]).
type Checked<R> = (R, Option<String>);

/// [`contract_checked`] with the step, alone, inside `window`.
fn contract_in<O: Resumable<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    operation: &mut O,
    window: &W,
) -> Checked<StepOf<O>>
where
    O::Error: Debug,
{
    let position = operation.position();
    let attempts = m.attempts();
    let releases = ReleaseWitness::capture(m);
    let result = window.window(|| operation.step(m));
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let attempted = m.attempts() - attempts;
        match &result {
            Ok(Step::Progress) if !(attempted > 0 || releases.released(m)) => Some(format!(
                "progress without an admission or a prepaid release: from {position:?} to {:?}",
                operation.position()
            )),
            Err(error) if error.refused() && attempted == 1 => {
                let after = operation.position();
                (after != position).then(|| {
                    format!(
                        "assertion `left == right` failed: a step whose only admission was refused \
                     moved the operation\n  left: {after:?}\n right: {position:?}"
                    )
                })
            }
            _ => None,
        }
    }));
    let violation = match checked {
        Ok(violation) => violation,
        Err(payload) => Some(format!(
            "post-step contract observation panicked: {}",
            panic_report(payload.as_ref()),
        )),
    };
    (result, violation)
}

/// A step's result with the contract rule it broke ([`contract_checked`]),
/// carried through the turn check ([`quantum_checked`]), whose progress rule
/// reads the step's.
struct Contracted<R> {
    result: R,
    violation: Option<String>,
}

impl<R: Outcome> Outcome for Contracted<R> {
    fn progressed(&self) -> bool {
        self.result.progressed()
    }
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

/// Probe terminal behavior without putting either publication in an unwind
/// frame. Only the production step runs in the physical window; diagnostics
/// are collected after it closes.
fn terminal<O: Resumable<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    operation: &mut O,
    observed: bool,
    at: usize,
    window: &W,
) -> Turned<Option<StepOf<O>>>
where
    O::Error: Debug,
{
    let mut outcome = None;
    let mut violations = Vec::new();
    let attempts = m.attempts();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let position = observed.then(|| operation.position());
        window.window(|| {
            outcome = Some(operation.step(m));
        });
        if !matches!(outcome, Some(Ok(Step::Finished))) {
            violations.push(format!(
                "a finished operation stepped to {}",
                outcome.as_ref().expect("the step returned").label(),
            ));
        }
        if m.attempts() != attempts {
            violations.push(format!(
                "a finished operation admitted work: attempts {attempts} -> {}",
                m.attempts(),
            ));
        }
        if let Some(position) = &position {
            let after = operation.position();
            if &after != position {
                violations.push(format!(
                    "a finished operation moved: {position:?} -> {after:?}",
                ));
            }
        }
    }));
    if let Err(payload) = checked {
        violations.push(panic_report(payload.as_ref()));
    }
    // Integrity is independent of position observation: a broken observer
    // cannot hide recording loss or destroy the probe's output.
    let lost = lost(m, at);
    Turned {
        outcome,
        lost,
        violation: (!violations.is_empty()).then(|| violations.join("; ")),
    }
}

/// What the recorder held after a driver's turn that found its run's
/// recording no evidence: a snapshot of the recorder's own sticky state
/// ([`Limits::evidence`], [`Limits::invalidation`]), never a validity flag
/// of the driver's. `turn` counts the driver's fresh turns from 0;
/// operation diagnostics are rendered separately while custody remains held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lost {
    pub incomplete: dcbor::bounded::Incomplete,
    pub cause: Option<dcbor::bounded::Invalidation>,
    pub turn: usize,
}

/// The one integrity read of every driver, after each of its turns: once
/// the run's recording is no evidence (a claim exhausted, an unencodable
/// observation, or an owner of another session paired with it), no later
/// turn is evidence either, and every later pairing is refused
/// `Unrecorded`. The loss is returned at the turn it is found, before
/// another turn is taken and before any history read could panic over the
/// invalid session and mask it. A family that records nothing loses
/// nothing.
fn lost(m: &Limits, turn: usize) -> Option<Lost> {
    match m.evidence() {
        Ok(()) | Err(dcbor::bounded::Unreadable::Unrecorded) => None,
        Err(dcbor::bounded::Unreadable::Session(incomplete)) => Some(Lost {
            incomplete,
            cause: m.invalidation(),
            turn,
        }),
    }
}

/// The position of `operation`, rendered: the one way a driver names where
/// a held operation stopped.
fn rendered<O: Resumable<Limits>>(operation: &mut O) -> String {
    format!("{:?}", operation.position())
}

/// Refuse execution after recording loss without inventing a production outcome.
fn require_evidence<T, E, R>(m: &Limits, at: usize) -> Result<(), Stopped<T, E, R>> {
    match lost(m, at) {
        None => Ok(()),
        Some(lost) => Err(Stopped::Violated {
            output: None,
            outcome: None,
            lost: Some(lost),
            report: "recording lost before scheduled execution".to_owned(),
        }),
    }
}

/// One checked turn as a scheduler receives it: the turn's production
/// outcome whole (`R`, the driver's own: a [`Resumable`] step's
/// `Result<Step<_>, _>`, a drain's `Reclaimed`, an acquisition's record),
/// the recording's loss at that turn when the recorder reports one, and the
/// first turn or contract rule the turn broke ([`quantum_checked`],
/// [`contract_checked`]). Any of them can hold together: a turn can publish
/// an output, exhaust the recording and break a rule, and the scheduler
/// keeps all three.
struct Turned<R> {
    outcome: R,
    lost: Option<Lost>,
    violation: Option<String>,
}

impl<R> Turned<R> {
    /// Observe a valid recorded outcome without moving it into the observer's
    /// unwind frame. Preserve the first loss and any pre-existing violation.
    fn observed(mut self, m: &Limits, at: usize, observe: impl FnOnce(&mut R)) -> Self {
        if self.lost.is_none() {
            self.lost = lost(m, at);
        }
        if self.lost.is_none() {
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observe(&mut self.outcome)
            })) {
                let observation = format!(
                    "turn observation panicked: {}",
                    panic_report(payload.as_ref())
                );
                match &mut self.violation {
                    Some(report) => {
                        report.push_str("; ");
                        report.push_str(&observation);
                    }
                    None => self.violation = Some(observation),
                }
            }
            self.lost = lost(m, at);
        }
        self
    }

    /// Preserve the production outcome when integrity and contract checks fail
    /// together. Classification never destroys an outcome.
    fn checked<T, E>(self) -> Result<R, Stopped<T, E, R>> {
        let Self {
            outcome,
            lost,
            violation,
        } = self;
        if let Some(report) = violation {
            Err(Stopped::Violated {
                output: None,
                outcome: Some(outcome),
                lost,
                report,
            })
        } else if let Some(lost) = lost {
            Err(Stopped::Lost(lost, outcome))
        } else {
            Ok(outcome)
        }
    }
}

/// A turn's production outcome named for a detached report ([`Finding`]):
/// what a stop keeps of its turn ([`Stopped::Lost`]) is rendered only once
/// its caller classified the stop as the run's failure. One rendering per
/// production outcome type, each its type's own: a step's ([`label`]), whose
/// output need not be printable; a drain's or an initialization's, printed
/// whole; a record acquisition's, its record named; an emission's,
/// detached at its turn while the chunk's borrow was valid ([`Emission`]).
pub trait Labelled {
    fn label(&self) -> String;
}

impl<O, E: Debug> Labelled for Result<Step<O>, E> {
    fn label(&self) -> String {
        label(self)
    }
}

impl<E: Debug> Labelled for Result<Reclaimed, E> {
    fn label(&self) -> String {
        format!("{self:?}")
    }
}

impl<E: Debug> Labelled for Result<(), E> {
    fn label(&self) -> String {
        format!("{self:?}")
    }
}

impl<'s, T: Reclaim<Limits>, E: Debug> Labelled for Result<OwnedRecord<'s, T, Limits>, E> {
    fn label(&self) -> String {
        match self {
            Ok(_) => "Ok(a record)".to_string(),
            Err(error) => format!("Err({error:?})"),
        }
    }
}

/// One fresh checked turn of `operation` ([`checked`]), the `at`-th of its
/// driver: its contract checked through its position when `observed`
/// ([`contracted`]), or, unobserved, stepped without its position read at
/// all, as the no-effect check runs it; then the recording's integrity
/// read ([`lost`]), the position read for it only when observed. The one
/// turn of every [`Resumable`] driver here.
fn turn<O: Resumable<Limits>>(
    m: &mut Limits,
    operation: &mut O,
    observed: bool,
    at: usize,
) -> Turned<StepOf<O>>
where
    O::Error: Debug,
{
    turn_in(m, operation, observed, at, &pipeline::Unwitnessed)
}

/// The shared checked turn, with only production execution inside the
/// physical window. Check diagnostics and custody bookkeeping run outside it.
fn turn_in<O: Resumable<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    operation: &mut O,
    observed: bool,
    at: usize,
    window: &W,
) -> Turned<StepOf<O>>
where
    O::Error: Debug,
{
    let (stepped, turn_violation) = quantum_checked(m, |m| {
        let stepped = if observed {
            let (result, violation) = contract_in(m, operation, window);
            Contracted { result, violation }
        } else {
            Contracted {
                result: window.window(|| operation.step(m)),
                violation: None,
            }
        };
        (stepped, false)
    });
    let Contracted {
        result: outcome,
        violation: contract_violation,
    } = stepped;
    let lost = lost(m, at);
    let position_violation = if lost.is_some() {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observed.then(|| rendered(operation))
        })) {
            Ok(position) => position.map(|position| format!("recording lost at {position}")),
            Err(payload) => Some(format!(
                "loss-position observation panicked: {}",
                panic_report(payload.as_ref()),
            )),
        }
    } else {
        None
    };
    let violations: Vec<_> = [contract_violation, turn_violation, position_violation]
        .into_iter()
        .flatten()
        .collect();
    Turned {
        outcome,
        lost,
        violation: (!violations.is_empty()).then(|| violations.join("; ")),
    }
}

/// Observe a checked outcome while retaining it outside the callback's unwind
/// frame. Loss detected by observation stops the schedule before another step.
fn observe_turn<O: Resumable<Limits>>(
    m: &Limits,
    operation: &mut O,
    turned: Turned<StepOf<O>>,
    at: usize,
    after_turn: impl FnOnce(&Limits, &mut O, &mut StepOf<O>),
) -> Result<StepOf<O>, Driven<O>>
where
    O::Error: Debug,
{
    turned
        .observed(m, at, |outcome| after_turn(m, operation, outcome))
        .checked()
}

/// Why a driver's schedule ended short of its goal: the one vocabulary of
/// every execution and cleanup driver here, the operation's own error kept
/// apart from the driver's findings. The driver borrows the operation and
/// its caller owns its destruction; whatever a turn moved out of the
/// operation (a published output) comes back inside the stop, for the
/// caller to own and drop before its run finalizes. `R` is the driver's
/// production outcome of one turn ([`Turned`]), a [`Resumable`] step's by
/// default.
///
/// Owning stops cannot be consumed as detached findings:
/// ```compile_fail
/// use dcbor_test_support::{Finding, Stopped};
/// let stop: Stopped<Vec<u8>, ()> = Stopped::Published(vec![1]);
/// let _: Finding = stop.into();
/// ```
/// Nor can classification discard their publications:
/// ```compile_fail
/// use dcbor_test_support::Stopped;
/// let stop: Stopped<Vec<u8>, ()> = Stopped::Published(vec![1]);
/// let _ = stop.operation();
/// ```
pub enum Stopped<T, E, R = Result<Step<T>, E>> {
    /// The operation's own error, as the operation returned it: terminal, or
    /// a refusal no fresh turn satisfies ([`retryable`]).
    Operation(E),
    /// The run's recording became no evidence at a turn ([`lost`]); that
    /// turn's outcome is kept whole beside it.
    Lost(Lost, R),
    /// The operation published where its schedule admits no publication: a
    /// cancelled or failed operation's cleanup, or a run expected to fail.
    Published(T),
    /// The operation reported `Finished` where its schedule required a
    /// publication or a failure.
    Finished,
    /// A refused unit of work wider than a turn's quantum: no turn can ever
    /// admit it, so the operation is stalled ([`stalled`]). The refused call,
    /// its unit, and the operation's position, rendered from the held
    /// operation at the stall ([`rendered`]) where the driver reads
    /// positions.
    Stalled {
        call: usize,
        values: u64,
        bytes: u64,
        position: Option<String>,
    },
    /// The schedule spent its bound of turns.
    Exceeded(usize),
    /// A check failed while custody remained held. `output` is an earlier
    /// publication when this is a terminal probe; `outcome` is the checked
    /// turn's exact result, absent only if execution unwound before returning.
    /// Recording loss and the violation coexist rather than masking each other.
    Violated {
        output: Option<T>,
        outcome: Option<R>,
        lost: Option<Lost>,
        report: String,
    },
}

/// The stop of a driver of `O` ([`Stopped`]).
pub type Driven<O> = Stopped<<O as Resumable<Limits>>::Output, <O as Resumable<Limits>>::Error>;

impl<T, E> Stopped<T, E> {
    /// Output custody carried by an unexpected publication, a violated
    /// publication or a lost turn.
    pub fn observe_outputs(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved
    where
        T: Custodial<Permit>,
    {
        match self {
            Self::Published(output) | Self::Lost(_, Ok(Step::Complete(output))) => {
                output.observe_custody(sink)
            }
            Self::Violated {
                output, outcome, ..
            } => {
                let first = output.as_mut().map_or(PermitsObserved::Complete, |output| {
                    output.observe_custody(sink)
                });
                let second = match outcome {
                    Some(Ok(Step::Complete(output))) => output.observe_custody(sink),
                    _ => PermitsObserved::Complete,
                };
                dcbor::bounded::observed_all([first, second])
            }
            _ => PermitsObserved::Complete,
        }
    }

    /// The stop with any output it carries moved out: the stop as an
    /// outcome, its turn's outcome rendered ([`Labelled`]) before the output
    /// leaves it, and the output for its holding scope to own and retire
    /// ([`Holding::drive`]), or for a worker to return through its join
    /// ([`RecordedRun::workers`]).
    pub fn detach(self) -> (Stopped<(), E, Rendered>, Publications<T>)
    where
        E: Debug,
    {
        let (stop, first, second) = match self {
            Self::Operation(error) => (Stopped::Operation(error), None, None),
            Self::Lost(lost, outcome) => {
                let rendered = Rendered::of(&outcome);
                let output = match outcome {
                    Ok(Step::Complete(output)) => Some(output),
                    _ => None,
                };
                (Stopped::Lost(lost, rendered), output, None)
            }
            Self::Published(output) => (Stopped::Published(()), Some(output), None),
            Self::Finished => (Stopped::Finished, None, None),
            Self::Stalled {
                call,
                values,
                bytes,
                position,
            } => (
                Stopped::Stalled {
                    call,
                    values,
                    bytes,
                    position,
                },
                None,
                None,
            ),
            Self::Exceeded(turns) => (Stopped::Exceeded(turns), None, None),
            Self::Violated {
                output,
                outcome,
                lost,
                report,
            } => {
                let rendered = outcome.as_ref().map(Rendered::of);
                let second = match outcome {
                    Some(Ok(Step::Complete(output))) => Some(output),
                    _ => None,
                };
                (
                    Stopped::Violated {
                        output: output.as_ref().map(|_| ()),
                        outcome: rendered,
                        lost,
                        report,
                    },
                    output,
                    second,
                )
            }
        };
        (stop, Publications([first, second]))
    }
}

/// A turn and its terminal probe can each publish. Both locations remain
/// observable until the holding retires them, without allocating an arena.
pub struct Publications<T>([Option<T>; 2]);

impl<T: Custodial<Permit>> Custodial<Permit> for Publications<T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        let [first, second] = &mut self.0;
        dcbor::bounded::observed_all([
            first.as_mut().map_or(PermitsObserved::Complete, |value| {
                value.observe_custody(sink)
            }),
            second.as_mut().map_or(PermitsObserved::Complete, |value| {
                value.observe_custody(sink)
            }),
        ])
    }
}

/// A holding scope's stop of `O` ([`Holding::drive`]): the outcome alone,
/// any output it published already held and retired by the scope.
pub type Halt<O> = Stopped<(), <O as Resumable<Limits>>::Error, Rendered>;

impl<E> Stopped<(), E, Rendered> {
    /// The operation's own error, for a caller that expects the operation to
    /// fail and classifies how; any other stop is a finding ([`Finding`]),
    /// with publication custody already retired by its holding.
    pub fn operation(self) -> Result<E, Finding>
    where
        E: Debug,
    {
        match self {
            Self::Operation(error) => Ok(error),
            stopped => Err(stopped.into()),
        }
    }
}

impl<T, E: Debug, R: Labelled> Debug for Stopped<T, E, R> {
    /// A published output need not be printable: it is named, not shown.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Operation(error) => f.debug_tuple("Operation").field(error).finish(),
            Self::Lost(lost, outcome) => f
                .debug_tuple("Lost")
                .field(lost)
                .field(&outcome.label())
                .finish(),
            Self::Published(_) => f.write_str("Published(..)"),
            Self::Finished => f.write_str("Finished"),
            Self::Stalled {
                call,
                values,
                bytes,
                position,
            } => f
                .debug_struct("Stalled")
                .field("call", call)
                .field("values", values)
                .field("bytes", bytes)
                .field("position", position)
                .finish(),
            Self::Exceeded(turns) => f.debug_tuple("Exceeded").field(turns).finish(),
            Self::Violated {
                report,
                outcome,
                lost,
                ..
            } => f
                .debug_struct("Violated")
                .field("report", report)
                .field("outcome", &outcome.as_ref().map(Labelled::label))
                .field("lost", lost)
                .finish_non_exhaustive(),
        }
    }
}

/// A finding a recorded run carries to its finalization as detached data
/// ([`recorded_run`], [`concluded`]): what a fixture's body returns, or
/// records, once it released what it held. A driver's stop becomes one at
/// the holding after it retires publication custody; the recording's loss keeps the recorder's
/// snapshot ([`Lost`]), with diagnostics rendered before custody retires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The run's recording became no evidence ([`Lost`]); `outcome` names
    /// what the turn that found it returned ([`Labelled`]).
    Lost { lost: Lost, outcome: String },
    /// A driver's schedule ended short of its goal otherwise: the
    /// operation's error where its caller required success, a publication or
    /// `Finished` its schedule admits none of, a stall, or the bound spent.
    Driver(String),
    /// A defect the fixture or the run's checkpointing found ([`capture`],
    /// [`RecordedRun::defect`]).
    Defect(String),
}

impl core::fmt::Display for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lost {
                lost:
                    Lost {
                        incomplete,
                        cause,
                        turn,
                    },
                outcome,
            } => {
                write!(
                    f,
                    "the run's recording became no evidence ({incomplete:?}, first by {cause:?}) \
                     at turn {turn}, which returned {outcome}"
                )?;
                f.write_str(": no later turn is evidence, so none is taken")
            }
            Self::Driver(finding) | Self::Defect(finding) => f.write_str(finding),
        }
    }
}

impl From<String> for Finding {
    fn from(finding: String) -> Self {
        Self::Defect(finding)
    }
}

/// Closed vocabulary of outcomes that carry diagnostics but no publication.
trait DetachedOutcome: Labelled {}

/// Non-owning production observations, never permits or published handles.
trait DetachedValue {}
impl DetachedValue for () {}
impl DetachedValue for Reclaimed {}

impl DetachedOutcome for Rendered {}
impl DetachedOutcome for Emission {}
impl<E: Debug> DetachedOutcome for Result<(), E> {}
impl<E: Debug> DetachedOutcome for Result<Reclaimed, E> {}
impl<T: DetachedValue, E: Debug> DetachedOutcome for Result<Step<T>, E> {}

impl<T: DetachedValue, E: Debug, R: DetachedOutcome> From<Stopped<T, E, R>> for Finding {
    fn from(stopped: Stopped<T, E, R>) -> Self {
        Self::from(&stopped)
    }
}

impl<T, E: Debug, R: Labelled> From<&Stopped<T, E, R>> for Finding {
    fn from(stopped: &Stopped<T, E, R>) -> Self {
        match stopped {
            Stopped::Lost(lost, outcome) => Self::Lost {
                lost: lost.clone(),
                outcome: outcome.label(),
            },
            Stopped::Operation(error) => Self::Driver(format!("the operation failed: {error:?}")),
            Stopped::Published(_) => {
                Self::Driver("the operation published where its schedule admits none".to_string())
            }
            Stopped::Finished => Self::Driver(
                "the operation finished where its schedule required a publication or a failure"
                    .to_string(),
            ),
            Stopped::Stalled {
                call,
                values,
                bytes,
                position,
            } => Self::Driver(format!(
                "call {call}: an indivisible unit of {values} values and {bytes} bytes exceeds a \
                 turn's quantum {TURN:?}, so no turn admits it; the operation is stalled at {}",
                position.as_deref().unwrap_or("an unread position")
            )),
            Stopped::Exceeded(turns) => {
                Self::Driver(format!("the schedule exceeded its bound of {turns} turns"))
            }
            Stopped::Violated {
                report,
                outcome,
                lost,
                ..
            } => {
                let outcome = format!(
                    "{:?}; driver diagnostic: {report}",
                    outcome.as_ref().map(Labelled::label),
                );
                match lost {
                    Some(lost) => Self::Lost {
                        lost: lost.clone(),
                        outcome,
                    },
                    None => Self::Defect(outcome),
                }
            }
        }
    }
}

/// After a refusal: when the refused call is a unit of work wider than a
/// turn's quantum, no turn can ever admit it and the operation is stalled
/// ([`Stopped::Stalled`]), returned at once rather than after every turn of
/// the bound is spent retrying it. The position is read only when
/// `observed`.
fn stalled<T, E, O: Resumable<Limits>>(
    m: &Limits,
    operation: &mut O,
    observed: bool,
) -> Option<Stopped<T, E>> {
    match m.trace().last() {
        Some(Admission {
            index,
            call: Call::Work { values, bytes },
            result: Err(LimitRefusal::Work),
            ..
        }) if values > TURN.values || bytes > TURN.bytes => Some(Stopped::Stalled {
            call: index,
            values,
            bytes,
            position: observed.then(|| rendered(operation)),
        }),
        _ => None,
    }
}

/// Whether a fresh turn can satisfy a refused turn's `error`: a refusal the
/// run's fault schedule injected in that turn (the policy's injected count
/// past `injected`, its count before the turn), which the schedule admits on
/// the retry, or an ordinary work refusal, which a fresh quantum admits
/// ([`refused`] fails a unit no quantum holds). Nothing else is retryable:
/// an ordinary storage refusal needs a release no turn makes, an expired
/// deadline stays expired, and an unrecorded grant stays unrecorded. A
/// driver returns those to its caller at once, never spinning on them to its
/// bound.
fn retryable<E: Failure<Refusal = LimitRefusal>>(m: &Limits, error: &E, injected: usize) -> bool {
    m.injected_refusals() > injected || error.class() == Class::Refused(&LimitRefusal::Work)
}

/// Positively identify a non-injected work refusal that a fresh quantum can
/// satisfy. Step-level fixtures use this predicate without treating arbitrary
/// resource failures as retryable progress.
pub fn ordinary_exhaustion<E: Failure<Refusal = LimitRefusal>>(m: &Limits, error: &E) -> bool {
    if error.class() != Class::Refused(&LimitRefusal::Work) {
        return false;
    }
    let refused = m.refused_calls();
    let Some(&(index, LimitRefusal::Work, false)) = refused.last() else {
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

/// The production outcome of one step of `O`.
pub type StepOf<O> =
    Result<Step<<O as Resumable<Limits>>::Output>, <O as Resumable<Limits>>::Error>;

/// Shared execution steps governed by [`Course`]. A boundary
/// controller may stop before a turn; it never owns the operation or any
/// publication. Observation and production execution retain the same
/// boundaries for pipeline and single-operation runs. With repeats, every
/// turn first has its next admission refused that many times
/// ([`repeated_refusal`]), each refusal checked to leave the operation, its
/// work and its storage as they were; a prepaid release, which has no
/// admission to refuse, is that turn's outcome.
struct Execution<S, E> {
    step: S,
    end: E,
}

fn drive_controlled<O: Resumable<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    operation: &mut O,
    course: Course,
    stop_before: impl FnMut(&Limits, &mut O, usize) -> bool,
    after_turn: impl FnMut(&Limits, &mut O, &mut StepOf<O>),
    window: &W,
) -> Result<Option<O::Output>, Driven<O>>
where
    O::Error: Debug,
{
    drive_executed(
        m,
        operation,
        course,
        stop_before,
        after_turn,
        window,
        Execution {
            step: |m: &mut Limits, operation: &mut O, observed, at| {
                turn_in(m, operation, observed, at, window)
            },
            end: |m: &mut Limits, operation: &mut O, observed, at| {
                terminal(m, operation, observed, at, window)
            },
        },
    )
}

fn drive_executed<O: Resumable<Limits>, W: pipeline::Physical, S, E>(
    m: &mut Limits,
    operation: &mut O,
    course: Course,
    mut stop_before: impl FnMut(&Limits, &mut O, usize) -> bool,
    mut after_turn: impl FnMut(&Limits, &mut O, &mut StepOf<O>),
    window: &W,
    mut execution: Execution<S, E>,
) -> Result<Option<O::Output>, Driven<O>>
where
    O::Error: Debug,
    S: FnMut(&mut Limits, &mut O, bool, usize) -> Turned<StepOf<O>>,
    E: FnMut(&mut Limits, &mut O, bool, usize) -> Turned<Option<StepOf<O>>>,
{
    let Course {
        turns,
        fault,
        observed,
        repeats,
    } = course;
    let cancel = match fault {
        Some(fault) => {
            refuse(m, fault.refusal);
            fault.cancel
        }
        None => false,
    };
    let turns = match turns {
        TurnBound::Allowed(turns) => allowed(m, turns),
        TurnBound::Exact(turns) => turns,
    };
    let injected_before = m.injected_refusals();
    for at in 0..turns {
        require_evidence(m, at)?;
        if stop_before(m, operation, at) {
            return Ok(None);
        }
        require_evidence(m, at)?;
        let refused = repeated_refusal(m, operation, repeats, at, |m, operation| {
            let before = operation.position();
            let checked = contract_in(m, operation, window);
            (before, operation.position(), checked)
        })?;
        let injected = m.injected_refusals();
        let turned = match refused {
            Some(outcome) => Turned {
                outcome: Ok(outcome),
                lost: None,
                violation: None,
            },
            None => (execution.step)(m, operation, observed, at),
        };
        let outcome = observe_turn(m, operation, turned, at, &mut after_turn)?;
        match outcome {
            Ok(Step::Complete(output)) => {
                let Turned {
                    outcome,
                    lost,
                    violation,
                } = (execution.end)(m, operation, observed, at + 1);
                if violation.is_some() || lost.is_some() {
                    return Err(Stopped::Violated {
                        output: Some(output),
                        outcome,
                        lost,
                        report: violation
                            .unwrap_or_else(|| "terminal probe lost recording".to_owned()),
                    });
                }
                return Ok(Some(output));
            }
            Ok(Step::Progress) => {}
            Ok(Step::Finished) => return Err(Stopped::Finished),
            Err(error) if error.refused() => {
                if cancel && m.injected_refusals() > injected_before {
                    return Ok(None);
                }
                if !retryable(m, &error, injected) {
                    return Err(Stopped::Operation(error));
                }
                if let Some(stall) = stalled(m, operation, observed) {
                    return Err(stall);
                }
            }
            Err(error) => return Err(Stopped::Operation(error)),
        }
    }
    Err(Stopped::Exceeded(turns))
}

/// The positions bracketing a refusal attempt and its intact checked outcome.
type RefusalAttempt<P, T, E> = (P, P, Checked<Result<Step<T>, E>>);

/// Before the `at`-th turn of a schedule, its next admission refused
/// `repeats` times, each attempt a fresh turn executed by `step` and
/// contract-checked by `step`: each must report the injected work
/// refusal at exactly that admission and leave the operation's position, its
/// work and its storage unchanged. `None` once every refusal held, the turn
/// itself then taken by the schedule. A prepaid release is returned as
/// progress. Every unexpected outcome is retained in the returned stop,
/// alongside contract violations and recording loss. `step` borrows the
/// caller's custody and returns its positions before and after the attempt.
pub fn repeated_refusal<O, P, T, E>(
    m: &mut Limits,
    operation: &mut O,
    repeats: usize,
    at: usize,
    mut step: impl FnMut(&mut Limits, &mut O) -> RefusalAttempt<P, T, E>,
) -> Result<Option<Step<T>>, Stopped<T, E>>
where
    P: PartialEq + Debug,
    E: Failure<Refusal = LimitRefusal> + Debug,
{
    for repeat in 0..repeats {
        require_evidence(m, at)?;
        m.clear_refusal();
        m.turn();
        let index = m.attempts();
        let work = m.used();
        let releases = ReleaseWitness::capture(m);
        refuse(m, pipeline::Refusal::For(index, LimitRefusal::Work));
        let (position, after, (outcome, contract)) = step(m, operation);
        m.fail_call(None);
        let mut violations: Vec<String> = contract.into_iter().collect();
        let prepaid = m.attempts() == index;
        if prepaid {
            if repeat > 0 {
                violations.push(format!(
                    "repeat {repeat}: a refused admission was followed by a step admitting nothing"
                ));
            }
            if !matches!(outcome, Ok(Step::Progress)) {
                violations.push(format!(
                    "a non-admitting step was not release progress: {}",
                    label(&outcome)
                ));
            }
            if m.used() != work {
                violations.push("a non-admitting step charged work".to_owned());
            }
            if !releases.released(m) {
                violations.push("a non-admitting step released no storage".to_owned());
            }
        } else {
            if !matches!(&outcome, Err(error) if error.class() == Class::Refused(&LimitRefusal::Work))
            {
                violations.push(format!(
                    "repeat {repeat}: the targeted admission was not refused: {}",
                    label(&outcome)
                ));
            }
            if m.first_refusal() != Some((index, LimitRefusal::Work)) {
                violations.push(format!(
                    "repeat {repeat}: the refusal fired at {:?}, not {index}",
                    m.first_refusal()
                ));
            }
            if m.attempts() != index + 1 {
                violations.push(format!(
                    "repeat {repeat}: the step continued after its refusal"
                ));
            }
            if after != position {
                violations.push(format!("repeat {repeat}: the refusal moved the operation"));
            }
            if m.used() != work {
                violations.push(format!(
                    "repeat {repeat}: the refusal charged or refunded work"
                ));
            }
            if !releases.unchanged(m) {
                violations.push(format!("repeat {repeat}: the refusal released storage"));
            }
        }
        let lost = lost(m, at);
        if lost.is_some() {
            violations.push(format!("recording lost at {after:?}"));
        }
        if prepaid || lost.is_some() || !violations.is_empty() {
            return Turned {
                outcome,
                lost,
                violation: (!violations.is_empty()).then(|| violations.join("; ")),
            }
            .checked()?
            .map(Some)
            .map_err(Stopped::Operation);
        }
    }
    if repeats > 0 {
        m.clear_refusal();
    }
    Ok(None)
}

/// The one cleanup driver: a cancelled or failed `operation` through its
/// own cleanup to `Finished`, in at most `turns` fresh checked turns, each
/// observed or not ([`turn`]). `after_turn` is given the operation
/// exclusively after each turn whose recording is still evidence, outside
/// it, for fixture witnesses such as a checkpoint ([`Holding::finish`]):
/// it observes custody and never
/// steps or moves out of the operation. Cleanup's own completion rules:
/// `Finished` ends it, checked to admit nothing after ([`ended`]); a
/// publication is a stop, its output returned to the caller
/// ([`Stopped::Published`]); a refusal no fresh turn satisfies and a
/// terminal error are the operation's ([`Stopped::Operation`]); a recording
/// that became no evidence stops at the turn it is found
/// ([`Stopped::Lost`]).
fn wound_by<O: Resumable<Limits>, S, E>(
    m: &mut Limits,
    operation: &mut O,
    turns: usize,
    observed: bool,
    mut after_turn: impl FnMut(&mut O, &mut StepOf<O>),
    mut execution: Execution<S, E>,
) -> (bool, Result<(), Driven<O>>)
where
    O::Error: Debug,
    S: FnMut(&mut Limits, &mut O, bool, usize) -> Turned<StepOf<O>>,
    E: FnMut(&mut Limits, &mut O, bool, usize) -> Turned<Option<StepOf<O>>>,
{
    let mut completed = false;
    let mut first = None;
    let mut first_loss = None;
    let result = (|| {
        for at in 0..turns {
            if first_loss.is_none() {
                first_loss = lost(m, at);
            }
            if let Err(stop) = require_evidence(m, at) {
                first.get_or_insert(stop);
            }
            let injected = m.injected_refusals();
            let turned = (execution.step)(m, operation, observed, at);
            let finished = matches!(&turned.outcome, Ok(Step::Finished));
            let progressing = matches!(&turned.outcome, Ok(Step::Progress))
                || matches!(&turned.outcome, Err(error) if error.refused() && retryable(m, error, injected));
            let turned = if first.is_none() {
                turned.observed(m, at, |outcome| after_turn(operation, outcome))
            } else {
                turned
            };
            if first_loss.is_none() {
                first_loss = turned.lost.clone();
            }
            let outcome = match turned.checked() {
                Ok(outcome) => Some(outcome),
                Err(stop) if finished || progressing => {
                    first.get_or_insert(stop);
                    None
                }
                Err(stop) => return Err(stop),
            };
            if finished {
                completed = true;
                let probe = (execution.end)(m, operation, observed, at + 1);
                let probe = if first.is_none() {
                    probe.observed(m, at + 1, |outcome| {
                        if let Some(outcome) = outcome {
                            after_turn(operation, outcome);
                        }
                    })
                } else {
                    probe
                };
                if probe.violation.is_some() || probe.lost.is_some() {
                    return Err(Stopped::Violated {
                        output: None,
                        outcome: probe.outcome,
                        lost: probe.lost,
                        report: probe
                            .violation
                            .unwrap_or_else(|| "cleanup terminal probe lost recording".to_owned()),
                    });
                }
                return Ok(());
            }
            let Some(outcome) = outcome else { continue };
            match outcome {
                Ok(Step::Progress) => {}
                Ok(Step::Finished) => unreachable!("finished cleanup was probed"),
                Ok(Step::Complete(output)) => return Err(Stopped::Published(output)),
                Err(error) if error.refused() => {
                    if !retryable(m, &error, injected) {
                        return Err(Stopped::Operation(error));
                    }
                    if lost(m, at).is_none()
                        && let Some(stall) = stalled(m, operation, observed)
                    {
                        return Err(stall);
                    }
                }
                Err(error) => return Err(Stopped::Operation(error)),
            }
        }
        Err(Stopped::Exceeded(turns))
    })();
    let result = match (first, result) {
        (None, result) => result,
        (
            Some(Stopped::Violated {
                output,
                outcome,
                lost,
                report,
            }),
            Ok(()),
        ) => Err(Stopped::Violated {
            output,
            outcome,
            lost: first_loss.or(lost),
            report,
        }),
        (Some(first), Ok(())) => Err(first),
        (Some(first), Err(next)) => {
            let report = format!("cleanup continued after {first:?}; subsequent stop: {next:?}");
            let first_loss = first_loss.or_else(|| match &first {
                Stopped::Lost(loss, _)
                | Stopped::Violated {
                    lost: Some(loss), ..
                } => Some(loss.clone()),
                _ => None,
            });
            let (output, outcome, loss) = match next {
                Stopped::Published(output) => (Some(output), None, None),
                Stopped::Lost(loss, outcome) => (None, Some(outcome), Some(loss)),
                Stopped::Violated {
                    output,
                    outcome,
                    lost,
                    ..
                } => (output, outcome, lost),
                Stopped::Operation(error) => (None, Some(Err(error)), None),
                _ => (None, None, None),
            };
            Err(Stopped::Violated {
                output,
                outcome,
                lost: first_loss.or(loss),
                report,
            })
        }
    };
    (completed, result)
}

/// Whether a suspension fixture keeps an externally imposed allowance or
/// renews the standard quantum before every step.
#[derive(Clone, Copy)]
pub enum TurnSchedule {
    Retained,
    Fresh,
}

/// Suspension shares the checked turn and observation boundary with execution.
/// The allowance policy changes; custody and physical attribution do not.
fn suspend_by<O: Resumable<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    operation: &mut O,
    reason: LimitRefusal,
    turns: usize,
    schedule: TurnSchedule,
    mut after_turn: impl FnMut(&Limits, &mut O, &mut StepOf<O>),
    window: &W,
) -> Result<usize, Driven<O>>
where
    O::Error: Debug,
{
    for at in 0..turns {
        require_evidence(m, at)?;
        let turned = match schedule {
            TurnSchedule::Fresh => turn_in(m, operation, true, at, window),
            TurnSchedule::Retained => {
                let (outcome, violation) = contract_in(m, operation, window);
                let lost = lost(m, at);
                Turned {
                    outcome,
                    lost,
                    violation,
                }
            }
        };
        let outcome = observe_turn(m, operation, turned, at, &mut after_turn)?;
        match outcome {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(output)) => return Err(Stopped::Published(output)),
            Ok(Step::Finished) => return Err(Stopped::Finished),
            Err(error) if error.refused() => {
                if matches!(schedule, TurnSchedule::Fresh)
                    && error.class() == Class::Refused(&LimitRefusal::Work)
                    && reason != LimitRefusal::Work
                    && m.injected_refusals() == 0
                {
                    if let Some(stall) = stalled(m, operation, true) {
                        return Err(stall);
                    }
                    continue;
                }
                assert_eq!(error.class(), Class::Refused(&reason));
                let (index, observed) = m.first_refusal().expect("injection never fired");
                assert_eq!(observed, reason);
                return Ok(index);
            }
            Err(error) => return Err(Stopped::Operation(error)),
        }
    }
    Err(Stopped::Exceeded(turns))
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalRun {
    calls: Vec<Call>,
    admitted: Vec<Call>,
    refusals: Vec<(usize, LimitRefusal, bool)>,
    /// The boundary valuations the run's policy recorded.
    reached: Valuations,
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

    /// The boundary valuations the run's policy recorded.
    pub fn reached(&self) -> Valuations {
        self.reached
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

    /// The run of `m`, a recorded policy, read from its session: its calls
    /// since construction or its last `measure`, each answered, against its
    /// own counters ([`corresponds`]), every work call within a turn. A
    /// policy that records nothing has no history to read, and the read
    /// panics ([`Limits::calls`]); so does an invalid session. The whole
    /// run's evidence, every family's observations, is the session's, read
    /// at quiescence ([`recorded_run`]).
    pub fn of(m: &Limits) -> Self {
        let (calls, admitted, refusals) = corresponds(m);
        m.assert_units(TURN);
        Self {
            calls,
            admitted,
            refusals,
            reached: m.reached(),
        }
    }

    /// The run's history is the session's: `observed`, the run's finished
    /// evidence ([`RecordedRun::inspect_evidence`]), holds the run's calls among the calls the
    /// run's policy `by` performed ([`Budget::performer`]), followed by
    /// exactly `followed` more (a drain the run's policy made after the run
    /// was read: its `calls().len()` then, less the run's), each answered as
    /// the run read it: refused at exactly the run's refusal indices, with
    /// the same reason and the same injection, and admitted or granted
    /// everywhere else. The in-flight history and the evidence are one
    /// record; a disagreement names the first call where they differ.
    pub fn recorded_in(&self, observed: &[Observed], by: Performer, followed: usize) {
        let answered: Vec<(Call, Answer)> = observed
            .iter()
            .filter(|observation| observation.by == by)
            .filter_map(|observation| match observation.event {
                Event::Call(call, answer) => Some((call, answer)),
                _ => None,
            })
            .collect();
        let end = answered.len().checked_sub(followed);
        let start = end.and_then(|end| end.checked_sub(self.calls.len()));
        let (Some(start), Some(end)) = (start, end) else {
            panic!(
                "the session holds {} calls of {by:?}, fewer than the run's {} and the {followed} \
                 after it",
                answered.len(),
                self.calls.len()
            )
        };
        let answered = &answered[start..end];
        for (index, ((call, _), expected)) in answered.iter().zip(&self.calls).enumerate() {
            assert_eq!(
                call, expected,
                "call {index}: the session and the run differ"
            );
        }
        let refusals: Vec<(usize, LimitRefusal, bool)> = answered
            .iter()
            .enumerate()
            .filter_map(|(index, (_, answer))| match *answer {
                Answer::Refused { refusal, injected } => Some((index, refusal, injected)),
                Answer::Admitted | Answer::Granted(_) => None,
            })
            .collect();
        assert_eq!(
            refusals, self.refusals,
            "the session's refusals differ from the run's"
        );
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
    let each = run(Fault {
        refusal: pipeline::Refusal::Each,
        cancel: false,
    });
    each.each(&baseline);
    // The cancellations below run in both layers too: the fast layer's
    // runs are the baseline, the one-pass refusal and every cancellation;
    // every run adds the exhaustive layer's refusals of each admission.
    let mut reached = baseline.reached.union(each.reached);
    let mut every = reached;
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
            every = every.union(resumed.reached);
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
        reached = reached.union(stopped.reached);
        every = every.union(stopped.reached);
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
    if rigor == rigor::Rigor::Exhaustive {
        fast_reaches_every(name, reached, every);
    }
    rigor::reached(name, reached);
    baseline
}

/// The fast layer's runs reach every boundary valuation the exhaustive
/// layer's do: `fast`, the union over the runs the fast layer makes,
/// misses nothing of `every`, the union over every run. A valuation missed
/// is named by its record row. The one check of it, for every matrix seam
/// whose layers select different runs.
fn fast_reaches_every(name: &str, fast: Valuations, every: Valuations) {
    let missed: Vec<String> = every
        .missing_from(fast)
        .map(dcbor::bounded::boundary::row)
        .collect();
    assert!(
        missed.is_empty(),
        "{name}: boundary valuations reached by the exhaustive layer and by no run the \
         fast layer makes: {missed:#?}"
    );
}

/// Classification stage shared by resumable refusal matrices. The retained
/// engine resumes every refusal through the same path; only the policy's
/// reported reason differs. Fast checks each reason at the final admission,
/// after all preceding work has been paid. Exhaustive checks that assumption
/// at every admission, and that the final admission's runs reach every
/// boundary valuation the others do. Callers must positively observe the
/// exact reason and compare the resulting trace and outcome with the
/// ordinary refusal run, and return the boundary valuations the run's
/// policy reached (`Limits::reached`).
pub fn reason_matrix(
    name: &str,
    rigor: rigor::Rigor,
    baseline: &[Call],
    reasons: &[LimitRefusal],
    mut run: impl FnMut(usize, LimitRefusal) -> Valuations,
) {
    assert!(!baseline.is_empty(), "{name}: no admission to refuse");
    let last = baseline.len() - 1;
    let start = match rigor {
        rigor::Rigor::Fast => last,
        rigor::Rigor::Exhaustive => 0,
    };
    let mut progress = rigor::Progress::new(format!("{name}: refusal classification"));
    progress.stage(
        "refusal classification",
        (baseline.len() - start) * reasons.len(),
        baseline.len() * reasons.len(),
    );
    let mut fast = Valuations::new();
    let mut every = Valuations::new();
    for (index, call) in baseline.iter().enumerate().skip(start) {
        for &reason in reasons {
            progress.case(format!("{reason:?} at call {index}: {call:?}"));
            let reached = run(index, reason);
            every = every.union(reached);
            if index == last {
                fast = fast.union(reached);
            }
        }
    }
    if rigor == rigor::Rigor::Exhaustive {
        fast_reaches_every(name, fast, every);
    }
    rigor::reached(name, fast);
}

/// Every physical request of an operation `run` performs, failed in a run
/// of its own: `run` is given the request to fail, or none, carries the
/// operation's own oracles for a failed run (the failure observed,
/// classified as physical, everything released), and returns the physical
/// requests the run made and the boundary valuations its policy reached
/// (`Limits::reached`). Every request is failed in both layers: a physical
/// failure ends the run, and no class of the states it can end in is
/// certified. Reports the union of the runs' valuations; returns the
/// unobstructed run's requests.
pub fn physical_matrix(name: &str, run: impl Fn(Option<usize>) -> (usize, Valuations)) -> usize {
    let mut progress = rigor::Progress::new(format!("{name}: physical failures"));
    let (requests, mut reached) = run(None);
    progress.dimension("physical requests", requests);
    assert!(
        requests > 0,
        "{name}: the operation made no physical request"
    );
    physical_stage(&mut progress, requests, |index| {
        reached = reached.union(run(Some(index)).1);
    });
    rigor::reached(name, reached);
    requests
}

/// The physical stage of a matrix: each of `requests` failed in a run of
/// its own by `run`, reported as it runs.
fn physical_stage(progress: &mut rigor::Progress, requests: usize, run: impl FnMut(usize)) {
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
/// in both layers. `run` returns the boundary valuations its policy reached
/// (`Limits::reached`); their union is reported.
pub fn synchronous_matrix(name: &str, attempts: usize, mut run: impl FnMut(usize) -> Valuations) {
    let mut progress = rigor::Progress::new(name);
    assert!(attempts > 0, "{name}: the operation admitted nothing");
    let mut reached = Valuations::new();
    whole_stage(
        &mut progress,
        "each admission refused, ending the operation",
        "admission",
        attempts,
        |index| reached = reached.union(run(index)),
    );
    rigor::reached(name, reached);
}

/// The stop stage of a single operation whose unobstructed run publishes
/// after `boundaries` turns: a stop after each number of turns from none
/// through publication, in a run of its own by `run`, which carries the
/// operation's own oracles for the stopped run and its cleanup and returns
/// the boundary valuations its policy reached (`Limits::reached`); their
/// union is reported. No cleanup class is certified for a single
/// operation's states, so every boundary is stopped at in both layers.
pub fn stop_matrix(name: &str, boundaries: usize, mut run: impl FnMut(usize) -> Valuations) {
    let mut progress = rigor::Progress::new(name);
    let mut reached = Valuations::new();
    whole_stage(
        &mut progress,
        "a stop after each number of turns, through publication",
        "turns",
        boundaries + 1,
        |turn| reached = reached.union(run(turn)),
    );
    rigor::reached(name, reached);
}

/// One fresh checked turn of `writer`. Its chunk borrows the writer.
fn emit_step<'w, I: DecodeInput<Limits>, T: InPlace<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    writer: &'w mut OwnedWriter<'_, I, T, Limits>,
    window: &W,
) -> BoundedResult<OwnedEmitStep<'w>, Limits> {
    // Moving the borrow into the closure lets the chunk outlive its call.
    checked(m, move |m| {
        let writer = writer;
        window.window(|| writer.step(m))
    })
}

/// A turn's diagnostic rendered before its publication leaves the stop.
pub struct Rendered(String);

impl Rendered {
    /// Rendering observes a borrowed outcome. A broken diagnostic formatter
    /// cannot unwind through the output custody that outcome still owns.
    fn of(outcome: &impl Labelled) -> Self {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| outcome.label())) {
            Ok(label) => Self(label),
            Err(payload) => Self(format!(
                "outcome rendering panicked: {}",
                panic_report(payload.as_ref()),
            )),
        }
    }
}

impl Labelled for Rendered {
    fn label(&self) -> String {
        self.0.clone()
    }
}

/// Probe completion, retaining emitted bytes and the exact terminal outcome
/// beside any recording loss or contract violation.
fn emitted<I: DecodeInput<Limits>, T: InPlace<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    writer: &mut OwnedWriter<'_, I, T, Limits>,
    window: &W,
    bytes: &mut Vec<u8>,
    at: usize,
) -> Result<(), Emitted> {
    let attempts = m.attempts();
    let outcome = window.window(|| writer.step(m));
    let lost = lost(m, at);
    let mut violations = Vec::new();
    if !matches!(outcome, Ok(OwnedEmitStep::Finished)) {
        violations.push("a completed emission stepped again");
    }
    if m.attempts() != attempts {
        violations.push("a completed emission admitted work");
    }
    if lost.is_none() && violations.is_empty() {
        return Ok(());
    }
    Turned {
        outcome: Emission {
            step: outcome.map(|step| format!("{step:?}")),
            emitted: core::mem::take(bytes),
        },
        lost,
        violation: (!violations.is_empty()).then(|| violations.join("; ")),
    }
    .checked()
    .map(|_| ())
}

/// An emission turn's outcome as its stop keeps it ([`Stopped::Lost`]),
/// detached at that turn while its chunk's borrow of the writer was still
/// valid ([`emission_turn`]): the exact production step rendered by its own
/// `Debug` (`Progress`, `Chunk` with its bytes, `Complete` and `Finished`
/// each themselves), the emission's error kept typed, and every byte the
/// emission consumed, the turn's chunk once among them. Diagnostic
/// evidence of a lost recording, never a published emission.
#[derive(Debug)]
pub struct Emission {
    pub step: Result<String, BoundedError<LimitRefusal>>,
    pub emitted: Vec<u8>,
}

impl Labelled for Emission {
    fn label(&self) -> String {
        let step = match &self.step {
            Ok(step) => step.clone(),
            Err(error) => format!("Err({error:?})"),
        };
        format!("{step}, {} bytes emitted", self.emitted.len())
    }
}

/// The stop of an emission driver ([`Stopped`]), its turn's outcome an
/// [`Emission`].
pub type Emitted = Stopped<(), BoundedError<LimitRefusal>, Emission>;

/// One fresh checked emission turn of `writer` ([`emit_step`]), the `at`-th
/// of its driver, `injected` the policy's injected refusals before it: the
/// one emission turn of the held writer schedule ([`Holding::emit`]).
/// Its step borrows the writer until its chunk is consumed (`OwnedWriter`'s
/// contract: the sink consumes each chunk before the next step), so the
/// step is classified inside that borrow: a chunk (at most 64 bytes,
/// checked) appended to `bytes` exactly once; the recording's integrity
/// read ([`lost`]), which reads the policy alone; and, lost, the exact step
/// detached there ([`Emission`]) with every byte consumed, never returned as
/// an emission. Once the borrow ends the held writer's position is rendered
/// into the loss diagnostic. Otherwise the step decides: progress and a
/// chunk continue, as a refusal a fresh turn satisfies does ([`retryable`]);
/// completion ends the emission; `Finished` without completion, and any
/// other error, the emission's own, stop it.
fn emission_turn<I: DecodeInput<Limits>, T: InPlace<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    writer: &mut OwnedWriter<'_, I, T, Limits>,
    bytes: &mut Vec<u8>,
    at: usize,
    injected: usize,
    window: &W,
) -> core::ops::ControlFlow<Result<(), Emitted>> {
    use core::ops::ControlFlow::{Break, Continue};
    let flow = {
        let step = emit_step(m, writer, window);
        if let Ok(OwnedEmitStep::Chunk(chunk)) = &step {
            assert!(chunk.len() <= 64, "chunk of {} bytes", chunk.len());
            bytes.extend_from_slice(chunk);
        }
        match lost(m, at) {
            Some(lost) => Break(Err(Stopped::Lost(
                lost,
                Emission {
                    step: step.map(|step| format!("{step:?}")),
                    emitted: core::mem::take(bytes),
                },
            ))),
            None => match step {
                Ok(OwnedEmitStep::Progress | OwnedEmitStep::Chunk(_)) => Continue(()),
                Ok(OwnedEmitStep::Complete) => Break(Ok(())),
                Ok(OwnedEmitStep::Finished) => Break(Err(Stopped::Finished)),
                Err(error) if error.refused() && retryable(m, &error, injected) => Continue(()),
                Err(error) => Break(Err(Stopped::Operation(error))),
            },
        }
    };
    if let Break(Err(Stopped::Lost(lost, outcome))) = flow {
        return Break(Err(Stopped::Violated {
            output: None,
            outcome: Some(outcome),
            lost: Some(lost),
            report: format!("recording lost at {:?}", writer.position()),
        }));
    }
    flow
}

/// The emission schedule shared by held pipelines and writer fixtures.
/// The controller observes custody outside physical windows and may stop before
/// a turn; recording loss prevents both execution and the terminal probe.
fn emit_by<I: DecodeInput<Limits>, T: InPlace<Limits>, W: pipeline::Physical>(
    m: &mut Limits,
    writer: &mut OwnedWriter<'_, I, T, Limits>,
    bytes: &mut Vec<u8>,
    len: usize,
    window: &W,
    mut stop_before: impl FnMut(&Limits, &mut OwnedWriter<'_, I, T, Limits>, usize) -> bool,
) -> Result<bool, Emitted> {
    use core::ops::ControlFlow::{Break, Continue};
    let bound = allowed(m, emit_turns(len));
    for at in 0..bound {
        require_evidence(m, at)?;
        if stop_before(m, writer, at) {
            return Ok(false);
        }
        require_evidence(m, at)?;
        let injected = m.injected_refusals();
        match emission_turn(m, writer, bytes, at, injected, window) {
            Continue(()) => {}
            Break(Ok(())) => {
                require_evidence(m, at + 1)?;
                emitted(m, writer, window, bytes, at + 1)?;
                require_evidence(m, at + 1)?;
                assert_eq!(bytes.len(), len, "emission ended early");
                return Ok(true);
            }
            Break(Err(stop)) => return Err(stop),
        }
    }
    Err(Stopped::Exceeded(bound))
}

impl<I: DecodeInput<Limits>, T: InPlace<Limits>, W: pipeline::Physical>
    Holding<'_, '_, OwnedWriter<'_, I, T, Limits>, W>
{
    /// Emit held writer chunks through the shared schedule, checkpointing before
    /// each boundary controller invocation. False means the controller stopped.
    pub fn emit(
        &mut self,
        policy: PolicyId,
        bytes: &mut Vec<u8>,
        len: usize,
        mut stop_before: impl FnMut(&Limits, &mut OwnedWriter<'_, I, T, Limits>, usize) -> bool,
    ) -> Result<bool, Emitted> {
        let RecordedRun {
            session,
            policies,
            checkpoints,
            defects,
            ..
        } = &mut *self.run;
        let m = policies
            .get_mut(policy.0)
            .expect("a policy handle names a policy of the run that issued it");
        let surrounding = &mut *self.surrounding;
        emit_by(
            m,
            self.value.get(),
            bytes,
            len,
            self.window,
            |m, writer, at| {
                let before = defects.len();
                capture(session, checkpoints, defects, |sink| {
                    dcbor::bounded::observed_all([
                        surrounding.observe_custody(sink),
                        writer.observe_custody(sink),
                    ])
                });
                assert_eq!(
                    defects.len(),
                    before,
                    "custody checkpoint failed; the run retains its observation diagnostics"
                );
                stop_before(m, writer, at)
            },
        )
    }
}

/// A typed operation whose lifecycle position becomes the admission trace's
/// context before each step, so a trace names where every call was made.
pub struct Traced<O>(pub O);

impl<P, O: Custodial<P>> Custodial<P> for Traced<O> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        self.0.observe_custody(sink)
    }
}

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

/// The stop of a scope driver ([`Stopped`]): a scope's initialization, a
/// record acquisition or a drain, each over no [`Resumable`] position and
/// publishing nothing a stop could return, `R` its production step's
/// outcome.
pub type Scoped<R> = Stopped<(), BoundedError<LimitRefusal>, R>;

/// One scope driver's turn as a scheduler receives it ([`Turned`]): its
/// production `outcome`, already taken, then the recording's integrity read
/// ([`lost`]), the `at`-th of its driver: the turn of the scope drivers that
/// stop at a lost recording ([`initialize`], [`acquire`]). The cleanup
/// schedule (`reclamation::reclaim_by`) reads [`lost`] itself, since a drain
/// keeps reclaiming past a loss and returns the loss after.
fn scope_turn<R>(m: &Limits, outcome: R, at: usize) -> Turned<R> {
    let lost = lost(m, at);
    Turned {
        outcome,
        lost,
        violation: None,
    }
}

/// The one initialization schedule ([`Holding::initialize`],
/// [`Worked::initialize`]): `owner` initialized under fresh checked turns,
/// refusals retried ([`retryable`]), `after_turn` observing it after each.
/// Any other error is the initialization's own ([`Stopped::Operation`]), its
/// caller classifying it: after a failed physical allocation the owner holds
/// no scope. A lost recording and the bound spent are the driver's.
fn initialize_by<'s>(
    owner: &mut DecodeOwner<'s, Limits>,
    m: &mut Limits,
    mut after_turn: impl FnMut(&mut DecodeOwner<'s, Limits>),
    mut step: impl FnMut(&mut DecodeOwner<'s, Limits>, &mut Limits) -> BoundedResult<(), Limits>,
) -> Result<(), Scoped<BoundedResult<(), Limits>>> {
    let bound = allowed(
        m,
        turns(
            dcbor::bounded::decode::construction::scope_bound::<Limits, ()>()
                .expect("scope bound fits in u64"),
        ),
    );
    for at in 0..bound {
        require_evidence(m, at)?;
        let injected = m.injected_refusals();
        let step = step(owner, m);
        let outcome = scope_turn(m, step, at)
            .observed(m, at, |_| after_turn(owner))
            .checked()?;
        match outcome {
            Ok(()) => return Ok(()),
            Err(error) if error.refused() && retryable(m, &error, injected) => {}
            Err(error) => return Err(Stopped::Operation(error)),
        }
    }
    Err(Stopped::Exceeded(bound))
}

/// The units one record's acquisition admits (`stable::acquire`, through
/// `DecodeOwner::allocate_step`): its metadata's write, its release, then its
/// allocation, each within a quantum and kept across a refusal, so each
/// needs at most one fresh turn.
const ACQUISITION_UNITS: usize = 3;

/// The production outcome of one record acquisition, including its publication.
type AcquisitionOutcome<'s, T> = BoundedResult<OwnedRecord<'s, T, Limits>, Limits>;

/// A record acquisition's checked schedule outcome; a lost publication remains
/// inside the stop until its holding retires it ([`Holding::acquire`]).
type Acquired<'s, T> = Result<OwnedRecord<'s, T, Limits>, Scoped<AcquisitionOutcome<'s, T>>>;

/// The one record acquisition schedule ([`Holding::acquire`]): a record of
/// `T` acquired by `step` under fresh turns, refusals retried
/// ([`retryable`]), `acquisition` keeping what each refused attempt
/// admitted, and `after_turn` observing it after each turn, beside the
/// record that turn acquired. Any other error is the acquisition's own
/// ([`Stopped::Operation`]); a lost recording and the units spent are the
/// driver's, a record acquired at the turn that lost the recording
/// returned inside the stop.
fn acquire_by<'s, T>(
    acquisition: &mut Acquisition<'s, T, Limits>,
    m: &mut Limits,
    mut after_turn: impl FnMut(&mut Acquisition<'s, T, Limits>, Option<&mut OwnedRecord<'s, T, Limits>>),
    mut step: impl FnMut(&mut Acquisition<'s, T, Limits>, &mut Limits) -> AcquisitionOutcome<'s, T>,
) -> Acquired<'s, T>
where
    T: Reclaim<Limits> + Send + 's,
    T::State: Send,
{
    let units = allowed(m, ACQUISITION_UNITS);
    for at in 0..units {
        require_evidence(m, at)?;
        m.turn();
        let injected = m.injected_refusals();
        let step = step(acquisition, m);
        let outcome = scope_turn(m, step, at)
            .observed(m, at, |outcome| {
                after_turn(acquisition, outcome.as_mut().ok())
            })
            .checked()?;
        match outcome {
            Ok(record) => return Ok(record),
            Err(error) if error.refused() && retryable(m, &error, injected) => {}
            Err(error) => return Err(Stopped::Operation(error)),
        }
    }
    Err(Stopped::Exceeded(units))
}

/// The one drain schedule ([`Holding::drain`]): the scope shut down under
/// fresh turns, refusals retried, `after_turn` observing it after each,
/// every reservation it ever made required released. A scope may contain
/// arbitrary external Reclaim records, whose contract declares no total
/// cleanup bound, so the drain keeps the emergency bound; individual
/// operation cleanup uses its own bound. Each turn's production outcome is
/// kept as the drain step returned it (`Reclaimed`): `Done` ends the drain,
/// `Progress` and `Waiting` continue. Any error no fresh turn satisfies is
/// the drain's own ([`Stopped::Operation`]); a lost recording, with its
/// turn's `Reclaimed`, and the bound spent are the driver's.
fn drain_by<'s>(
    owner: &mut DecodeOwner<'s, Limits>,
    m: &mut Limits,
    mut after_turn: impl FnMut(&mut DecodeOwner<'s, Limits>),
    mut step: impl FnMut(&mut DecodeOwner<'s, Limits>, &mut Limits) -> BoundedResult<Reclaimed, Limits>,
) -> Result<(), Scoped<BoundedResult<Reclaimed, Limits>>> {
    reclamation::reclaim_by(
        owner,
        m,
        TURNS,
        reclamation::Goal::Drained,
        |owner, _, _| after_turn(owner),
        |owner, m| step(owner, m),
    )
}

/// An input whose cleanup is observable: its bytes, its own reservation, and
/// a release counter, each released in its own admitted unit.
pub struct Instrumented {
    /// The input's bytes, in storage its own acquisitions requested through
    /// the production protocol ([`dcbor::bounded::Owned::reserve`]): each
    /// growth bound to an acquisition, its release admitted held and spent
    /// at its grant, its reservation's outcome observed.
    bytes: dcbor::bounded::Owned<u8, Permit>,
    released: Arc<AtomicUsize>,
}

// SAFETY: the bytes are never mutated after initialization.
unsafe impl DecodeInput<Limits> for Instrumented {
    fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
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
    /// The bytes released, their storage freed before its permit.
    BytesReleased,
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

    /// One field released per admitted unit, through the cleanup capability
    /// alone: it admits work and holds permits, and no allocation can be
    /// requested through it ([`Cleanup`]).
    fn reclaim_step(
        mut slot: Slot<'_, Self, InputPhase>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        use dcbor::bounded::decode::construction::in_place::admit;
        let (place, phase) = slot.parts();
        // Each field is released by raw projection alone: the input's bytes
        // may still be read through a document's view of them.
        let raw = place.as_ptr(phase);
        *phase = match *phase {
            InputPhase::Empty | InputPhase::Released => {
                admit(cleanup, 0)?;
                return Ok(Reclaimed::Done);
            }
            InputPhase::Owned => {
                admit(cleanup, size_of::<dcbor::bounded::Owned<u8, Permit>>())?;
                // SAFETY: the phase records the bytes owned and initialized,
                // and they are dropped once, by projection alone: the buffer
                // freed, then its permit released, as `Owned` orders them.
                unsafe { core::ptr::drop_in_place(core::ptr::addr_of_mut!((*raw).bytes)) };
                InputPhase::BytesReleased
            }
            InputPhase::BytesReleased => {
                admit(cleanup, size_of::<Arc<AtomicUsize>>())?;
                // SAFETY: as above, for the release counter, counted first.
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
    fn remaining(mut slot: PeekSlot<'_, Self, InputPhase>) -> Option<u64> {
        Some(match *slot.custody() {
            InputPhase::Empty | InputPhase::Released => 1,
            InputPhase::Owned => 2,
            InputPhase::BytesReleased => 1,
        })
    }

    /// The bytes' permit while they are owned, read by field projection
    /// through the slot observed, reported into the record's open group.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, InputPhase>,
        sink: &mut dyn CustodySink<Permit>,
    ) -> PermitsObserved {
        let (place, phase) = slot.parts();
        if *phase != InputPhase::Owned {
            return PermitsObserved::Complete;
        }
        // SAFETY: the phase records the bytes field initialized; it is
        // reached by raw projection and read shared under the phase's
        // borrow, forming no reference to any other field.
        let bytes = unsafe {
            place
                .project(|input| core::ptr::addr_of_mut!((*input).bytes))
                .get(&*phase)
        };
        if let Some(permit) = bytes.permit() {
            sink.permit(permit, None);
        }
        PermitsObserved::Complete
    }
}

/// An instrumented input holding `wire`, initialized through the custom
/// resource-binding interface: its record acquired in `owner`'s scope, its
/// bytes in storage acquired through the production protocol, its
/// initialization admitted through the route
/// (`in_place::admit`). `released` counts its completed cleanups.
pub fn instrumented<'s>(
    owner: &DecodeOwner<'s, Limits>,
    m: &mut Limits,
    wire: &[u8],
    released: &Arc<AtomicUsize>,
) -> OwnedInitialized<'s, Instrumented, Limits> {
    m.open();
    let mut acquisition = Acquisition::new();
    let mut input = owner
        .allocate_step::<Instrumented>(m, &mut acquisition)
        .expect("input record");
    // The bytes' growths are acquisitions of the record's own owner, the
    // owner its acquisition stored ([`Acquisition::owner`]): the record's
    // group reports the bytes' permit under the owner that acquired it. Each
    // growth holds nothing once it is granted.
    let mut bytes = dcbor::bounded::Owned::new();
    bytes
        .extend_from_slice(
            wire,
            m,
            acquisition
                .owner()
                .expect("a granted record's acquisition made its owner"),
        )
        .expect("input storage");
    drop(acquisition);
    dcbor::bounded::decode::construction::in_place::admit(m, size_of::<Instrumented>())
        .expect("input initialization");
    let mut slot = input.destination();
    let (place, phase) = slot.parts();
    // SAFETY: admitted initialization at the record's final address, which
    // its empty phase says holds nothing; the phase records ownership of
    // every field immediately after.
    unsafe {
        place.write(
            phase,
            Instrumented {
                bytes,
                released: released.clone(),
            },
        );
    }
    *phase = InputPhase::Owned;
    // SAFETY: the value is fully initialized, and its phase describes every
    // resource it owns.
    unsafe { input.publish() }
}

/// A planted binding understating its cleanup: it declares one call but
/// takes one per unit `left`, then its `Done`. The scope must refuse the
/// call beyond the declared one as a defect ([`Reclaim::remaining`]); one
/// definition, planted by every suite that shows the refusal.
pub struct Understated;

/// The cleanup units an [`Understated`] still takes before its `Done`.
pub struct UnderstatedState {
    left: usize,
}

/// The units left are the binding's whole custody.
impl Custody for UnderstatedState {
    type Observation = usize;

    fn observe(&mut self) -> usize {
        self.left
    }
}

// SAFETY: the binding owns nothing; its cleanup only counts down. Its
// declared count deliberately understates, the defect the scope must refuse.
unsafe impl Reclaim<Limits> for Understated {
    type State = UnderstatedState;
    const INITIAL: UnderstatedState = UnderstatedState { left: 0 };

    fn reclaim_step(
        mut slot: Slot<'_, Self, UnderstatedState>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        dcbor::bounded::decode::construction::in_place::step(cleanup)?;
        let state = slot.custody();
        if state.left == 0 {
            return Ok(Reclaimed::Done);
        }
        state.left -= 1;
        Ok(Reclaimed::Progress)
    }

    /// One call, whatever is left: the planted understatement.
    fn remaining(_: PeekSlot<'_, Self, UnderstatedState>) -> Option<u64> {
        Some(1)
    }

    /// The binding owns no permit.
    fn observe_permits(
        _: PeekSlot<'_, Self, UnderstatedState>,
        _: &mut dyn CustodySink<Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// Plant the understatement in a held [`Understated`] record
/// ([`Holding::acquire`]): its cleanup then takes `left` calls beyond the
/// one it declares, then its `Done`. The binding owns nothing; the state is
/// its only custody.
pub fn understate(record: &mut OwnedRecord<'_, Understated, Limits>, left: usize) {
    record.destination().custody().left = left;
}

#[cfg(test)]
mod tests {
    use super::*;
    // The tests request permits directly; the driver above holds and names
    // permits only (`Releasing`), and requests none itself.
    use dcbor::bounded::{Allocator, Budget};

    #[test]
    fn recording_budget_overflow_is_refused_before_allocation() {
        for count in [usize::MAX, usize::MAX / 2] {
            for (events, permits) in [(count, 0), (0, count)] {
                assert!(
                    std::panic::catch_unwind(|| measured(events, permits)).is_err(),
                    "overflowing counts produced a recording capacity"
                );
            }
        }
        let capacity = measured(CAPACITY.events, CAPACITY.permits);
        assert!(capacity.events >= CAPACITY.events);
        assert!(capacity.permits >= CAPACITY.permits);
    }

    /// A short recording is shorter than the default in one dimension and
    /// longer in none: the default itself, and a recording enlarged in
    /// either dimension, are refused before the run begins, naming the
    /// budget authority that alone enlarges one.
    #[test]
    fn a_short_recording_never_enlarges_the_default() {
        for capacity in [
            CAPACITY,
            Capacity {
                events: CAPACITY.events * 2,
                permits: 1,
            },
            Capacity {
                events: 64,
                permits: CAPACITY.permits * 2,
            },
        ] {
            let refused = std::panic::catch_unwind(|| {
                recorded_run_short(capacity, |run| {
                    run.policy(u64::MAX);
                    Ok(())
                })
            })
            .expect_err("a recording not shorter than the default ran");
            assert!(
                panic_report(refused.as_ref()).contains("is not shorter than the default"),
                "{capacity:?}"
            );
        }
        recorded_run_short(
            Capacity {
                events: 64,
                permits: CAPACITY.permits,
            },
            |run| {
                run.policy(u64::MAX);
                Ok(())
            },
        );
    }

    #[test]
    fn joined_batch_collects_every_worker_panic() {
        let mut visited = [false; 3];
        let failures = joined_batch(&mut visited, |worker, visited| {
            *visited = true;
            panic!("planted worker {worker}");
        });
        assert_eq!(visited, [true; 3], "a worker panic skipped another job");
        assert_eq!(failures.len(), 3, "a join discarded a worker panic");
        for (worker, failure) in failures.iter().enumerate() {
            assert!(
                failure
                    .to_string()
                    .contains(&format!("planted worker {worker}")),
                "worker {worker}: {failure}"
            );
        }
    }

    /// The report of a run's failure, caught: the finalization's ([`panic_report`]).
    fn message(payload: Box<dyn std::any::Any + Send>) -> String {
        panic_report(payload.as_ref())
    }

    /// A copy of a 4 KiB input in a fresh scope under a run of `capacity`:
    /// whatever turn makes its recording no evidence, the driver returns
    /// its stop there, naming what first invalidated it, never reaching its
    /// bound or a history read; the body returns it, dropping the scope and
    /// the input, and the run's finalization reports it. The stop the body
    /// returned, as the driver detached it, and the report of the run's
    /// failure.
    fn exhausted_copy(capacity: Capacity) -> (Finding, String) {
        let returned = std::sync::Mutex::new(None);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recorded_run_short(capacity, |run| {
                let policy = run.policy(u64::MAX);
                let copied: Result<(), Finding> = run.holding(
                    DecodeOwner::new(),
                    Retirement::Scope,
                    &pipeline::Unwitnessed,
                    |owner| {
                        owner.initialize(policy)?;
                        owner.copied(policy, &[0x5a; 4096], |_| ())?;
                        owner.drain(policy)
                    },
                );
                if let Err(finding) = &copied {
                    *returned.lock().expect("one body") = Some(finding.clone());
                }
                copied
            });
        }))
        .expect_err("a run exceeding its recording completed");
        let returned = returned
            .into_inner()
            .expect("one body")
            .expect("the body returned the driver's stop");
        (returned, message(failure))
    }

    /// The cause a returned stop names, when it is the recording's loss.
    fn cause(finding: &Finding) -> Option<Option<dcbor::bounded::Invalidation>> {
        match finding {
            Finding::Lost { lost, .. } => Some(lost.cause),
            _ => None,
        }
    }

    /// A run whose events outgrow its session's slots stops at the turn the
    /// slots ran out: the stop returned names `Events`, typed, and the run's
    /// finalization reports it as its one finding beside the recording's
    /// own refusal naming the same cause.
    #[test]
    fn a_driver_stops_at_the_turn_its_recording_runs_out_of_event_slots() {
        let (returned, report) = exhausted_copy(Capacity {
            permits: CAPACITY.permits,
            events: 64,
        });
        assert_eq!(
            cause(&returned),
            Some(Some(dcbor::bounded::Invalidation::Events)),
            "the stop returned is not the recording's loss by Events: {returned:?}"
        );
        assert!(
            report.contains(
                "the run's recording became no evidence (Exhausted, first by Some(Events))"
            ),
            "{report}"
        );
        // The driver's stop is the run's finding, and the mandatory
        // finalization still ran and refused the recording, naming its cause.
        assert!(
            report.contains(&returned.to_string())
                && report.ends_with(
                    "finalization: the recording is no evidence: Exhausted, first by Events"
                ),
            "the run's finalization was skipped: {report}"
        );
    }

    /// A run whose grants outgrow its session's permit records stops at the
    /// turn its grant was refused unrecorded: the stop returned names
    /// `Permits`, not the `Unrecorded` refusal its turn returned (kept
    /// beside it, as that turn's outcome) nor a history read of the invalid
    /// session.
    #[test]
    fn a_driver_stops_at_the_turn_its_recording_runs_out_of_permit_records() {
        let (returned, report) = exhausted_copy(Capacity {
            permits: 2,
            events: CAPACITY.events,
        });
        assert_eq!(
            cause(&returned),
            Some(Some(dcbor::bounded::Invalidation::Permits)),
            "the stop returned is not the recording's loss by Permits: {returned:?}"
        );
        assert!(
            matches!(&returned, Finding::Lost { outcome, .. } if outcome.contains("Unrecorded")),
            "the refused turn's outcome was not kept: {returned:?}"
        );
        assert!(
            report.contains(&returned.to_string())
                && report.ends_with(
                    "finalization: the recording is no evidence: Exhausted, first by Permits"
                ),
            "the run's finalization was skipped: {report}"
        );
    }

    /// Four workers over one shared pool whose session holds eight permit
    /// records, each copying inputs in a scope of its own and returning its
    /// stop as data through its join: the session is invalidated by
    /// whichever worker's grant first completes its invalidation on finding
    /// no record, and every worker that stops returns the recording's loss
    /// naming that kept cause, `Permits`, although every pairing of an owner
    /// of the invalid session that follows invalidates it again as a
    /// foreign pairing. Only a permit claim can begin the invalidation here,
    /// so the kept cause is fixed whatever the schedule. Every worker is
    /// joined, its share of the pool dropped with it, before the body
    /// records each stop as the run's finding; the run's finalization then
    /// refuses the recording naming the same cause.
    #[test]
    fn concurrent_workers_each_name_the_first_invalidation() {
        let stops = std::sync::Mutex::new(Vec::new());
        let finalization = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recorded_run_short(
                Capacity {
                    permits: 8,
                    events: CAPACITY.events,
                },
                |run| {
                    let policy = run.policy(u64::MAX);
                    let shares: Vec<_> = (0..4).map(|_| run.shared_policy(policy)).collect();
                    let result = run.workers(
                        &shares,
                        4,
                        Retirement::Scope,
                        |_| Worked::new(DecodeOwner::<'static, Limits>::new(), 4),
                        |_, fixture, held, m| {
                            if fixture == 0 {
                                held.initialize(m)?;
                            }
                            let source = Copying(&[0x5a; 64]);
                            let turns = source.turns();
                            let operation = source.acquire(&held.scope);
                            held.drive(m, operation, turns)?;
                            Ok(())
                        },
                    );
                    let stopped: Vec<Finding> = run
                        .defects
                        .iter()
                        .chain(result.as_ref().err())
                        .filter(|finding| matches!(finding, Finding::Lost { .. }))
                        .cloned()
                        .collect();
                    stops.lock().expect("one body").clone_from(&stopped);
                    result
                },
            );
        }))
        .expect_err("an invalid recording was finalized as evidence");
        let stops = stops.into_inner().expect("one body");
        assert!(!stops.is_empty(), "no worker found the session exhausted");
        for stop in &stops {
            assert_eq!(
                cause(stop),
                Some(Some(dcbor::bounded::Invalidation::Permits)),
                "a worker returned another stop than the loss by Permits: {stop:?}"
            );
        }
        let finalization = message(finalization);
        for stop in &stops {
            assert!(
                finalization.contains(&stop.to_string()),
                "a worker's stop is missing from the run's findings: {finalization}"
            );
        }
        assert!(
            finalization.ends_with("the recording is no evidence: Exhausted, first by Permits"),
            "{finalization}"
        );
    }

    /// Multiple retained admissions in one step force ordinary exhaustion
    /// before the selected injection. No allocation or engine fixture can
    /// obscure the scheduler's own accounting in this control.
    #[derive(Default)]
    struct RetainedAdmissions(usize);

    impl Custodial<Permit> for RetainedAdmissions {
        fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
            PermitsObserved::Complete
        }
    }

    terminal!(Exhausted: [] RetainedAdmissions);

    /// Storage acquired through the production protocol whose release its
    /// growth prepaid: the first step drops it, admitting nothing; the next
    /// admits its final transition through the route.
    struct PrepaidRelease {
        storage: Option<dcbor::bounded::Owned<u8, Permit>>,
        owner: Identity,
        complete: bool,
    }

    /// The storage's permit while it is held, under the owner its growth was
    /// acquired for.
    impl Custodial<Permit> for PrepaidRelease {
        fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
            sink.begin(Some(self.owner));
            if let Some(permit) = self.storage.as_ref().and_then(|storage| storage.permit()) {
                sink.permit(permit, None);
            }
            sink.end();
            PermitsObserved::Complete
        }
    }

    // Its storage is dropped by the step before it publishes.
    terminal!(Exhausted: [] PrepaidRelease);

    impl Resumable<Limits> for PrepaidRelease {
        type Output = ();
        type Error = BoundedError<LimitRefusal>;
        type Position = (bool, bool);

        fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
            if let Some(storage) = self.storage.take() {
                drop(storage);
                return Ok(Step::Progress);
            }
            if self.complete {
                return Ok(Step::Finished);
            }
            dcbor::bounded::decode::construction::in_place::step(m)?;
            self.complete = true;
            Ok(Step::Complete(()))
        }

        fn position(&mut self) -> Self::Position {
            (self.storage.is_some(), self.complete)
        }
    }

    #[test]
    fn repeated_turn_observes_prepaid_release_without_inventing_a_refusal() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            // The storage's growth is an acquisition of an owner of its own,
            // which holds nothing once the growth is granted. Four elements
            // are one growth from empty (`grown_capacity`), so the storage
            // holds one permit and its drop is the session's only release; a
            // second growth would release the first permit as it replaces it.
            let (storage, owner) = run.with_policy(policy, |m| {
                let owner = m.owner().expect("an owner of the storage");
                let mut storage = dcbor::bounded::Owned::new();
                storage
                    .reserve(4, m, &owner)
                    .map_err(|error| Finding::Driver(format!("the storage's growth: {error:?}")))?;
                m.measure();
                Ok::<_, Finding>((storage, owner.id()))
            })?;
            // Each turn's (live bytes, attempts, injected refusals) after it.
            let mut turns = Vec::new();
            run.holding(
                PrepaidRelease {
                    storage: Some(storage),
                    owner,
                    complete: false,
                },
                Retirement::Released,
                &pipeline::Unwitnessed,
                |operation| {
                    operation.repeated(
                        policy,
                        2,
                        Retirement::Released,
                        3,
                        |m, _| turns.push((m.live_bytes(), m.attempts(), m.injected_refusals())),
                        |_| (),
                    )
                },
            )?;
            // The prepaid release is the first turn's outcome, admitting
            // nothing and inventing no refusal; the completion's admission is
            // refused three times, then admitted.
            assert_eq!(turns, [(0, 0, 0), (0, 4, 3)]);
            let (refusals, by) = run.with_policy(policy, |m| {
                assert_eq!(m.used(), WriteWork::new(1, 0));
                (RefusalRun::of(m), m.performer())
            });
            run.inspect_evidence(move |observed, _| {
                refusals.recorded_in(observed, by, 0);
                // The prepaid release is in the session once, as the
                // storage's own drop, performed by no policy: no refusal
                // stood in for it.
                let releases: Vec<&Observed> = observed
                    .iter()
                    .filter(|observation| matches!(observation.event, Event::Released(_)))
                    .collect();
                assert_eq!(releases.len(), 1, "the prepaid release was recorded once");
                assert_eq!(
                    releases[0].by,
                    Performer::None,
                    "a drop performed by a policy"
                );
            });
            Ok(())
        });
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

        /// Three units admitted through the route, each kept once admitted:
        /// the first two exhaust a fresh turn's quantum before the third.
        fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
            if self.0 == 3 {
                return Ok(Step::Finished);
            }
            for bytes in [64, 16, 1].into_iter().skip(self.0) {
                dcbor::bounded::decode::construction::in_place::admit(m, bytes)?;
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
                recorded_run(|run| {
                    let policy = run.policy(u64::MAX);
                    run.holding(
                        RetainedAdmissions::default(),
                        Retirement::Exhausted,
                        &pipeline::Unwitnessed,
                        |operation| {
                            let result = operation.drive_faulted(
                                policy,
                                4,
                                Retirement::Exhausted,
                                fault,
                                |_, _| {},
                                |_| (),
                            )?;
                            assert_eq!(result.is_none(), fault.cancel);
                            Ok::<_, Finding>(())
                        },
                    )?;
                    let (refusals, by) =
                        run.with_policy(policy, |m| (RefusalRun::of(m), m.performer()));
                    let recorded = refusals.clone();
                    run.inspect_evidence(move |observed, _| recorded.recorded_in(observed, by, 0));
                    Ok(refusals)
                })
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
            recorded_run(|run| {
                let policy = run.policy(u64::MAX);
                let refusals = run.scoped(policy, &pipeline::Unwitnessed, |owner| {
                    owner.copied(policy, &wire, |input| {
                        input.decode::<String, _>(policy, Options::normalizing(8), |value| {
                            value.prepare(policy, |plan| {
                                plan.transfer(
                                    dcbor::bounded::encoding::OwnedPrepared::into_writer,
                                    Retirement::Published,
                                    |writer| {
                                        writer.with_policy(policy, |_, m| {
                                            m.measure();
                                            refuse(m, refusal);
                                        });
                                        let mut bytes = Vec::with_capacity(wire.len());
                                        assert!(writer.emit(
                                            policy,
                                            &mut bytes,
                                            wire.len(),
                                            |_, _, _| false,
                                        )?);
                                        assert_eq!(bytes, wire);
                                        Ok::<_, Finding>(writer.with_policy(policy, |_, m| {
                                            let refusals = RefusalRun::of(m);
                                            m.fail_call(None);
                                            m.clear_refusal();
                                            refusals
                                        }))
                                    },
                                )
                            })?
                        })?
                    })?
                })?;
                let (followed, by) = run.with_policy(policy, |m| {
                    assert_eq!(m.live_bytes(), 0);
                    // The drain's calls follow the emission's in the session.
                    (m.calls().len() - refusals.calls().len(), m.performer())
                });
                let recorded = refusals.clone();
                run.inspect_evidence(move |observed, _| {
                    recorded.recorded_in(observed, by, followed);
                });
                Ok(refusals)
            })
        };
        let baseline = run(pipeline::Refusal::None);
        run(pipeline::Refusal::Each).each(&baseline);
    }

    #[test]
    fn cancellation_waits_for_injected_work_after_ordinary_exhaustion() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                RetainedAdmissions::default(),
                Retirement::Exhausted,
                &pipeline::Unwitnessed,
                |operation| {
                    let mut ordinary = Vec::new();
                    let cancelled = operation.drive_faulted(
                        policy,
                        4,
                        Retirement::Exhausted,
                        Fault {
                            refusal: pipeline::Refusal::For(3, LimitRefusal::Work),
                            cancel: true,
                        },
                        |m, _| {
                            ordinary.push(ordinary_exhaustion(
                                m,
                                &BoundedError::Refused(LimitRefusal::Work),
                            ));
                        },
                        |_| (),
                    )?;
                    assert!(
                        cancelled.is_none(),
                        "the run was not cancelled at its injection"
                    );
                    assert_eq!(ordinary, [true, false]);
                    operation.with_policy(policy, |operation, m| {
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
                    });
                    operation.drive(policy, 1, Retirement::Exhausted, |output| {
                        output.with_policy(policy, |_, m| {
                            assert_eq!(m.used(), WriteWork::new(3, 81))
                        });
                    })?;
                    Ok::<_, Finding>(())
                },
            )?;
            let (refusals, by) = run.with_policy(policy, |m| (RefusalRun::of(m), m.performer()));
            // Both refusals, the ordinary one and the injected one, are in
            // the session as the policy read them.
            run.inspect_evidence(move |observed, _| refusals.recorded_in(observed, by, 0));
            Ok(())
        });
    }

    /// The three admissions of [`RetainedAdmissions`] in a recorded run of
    /// their own, read as the policy recorded them, with its performer.
    fn retained_admissions() -> (RefusalRun, Performer) {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                RetainedAdmissions::default(),
                Retirement::Exhausted,
                &pipeline::Unwitnessed,
                |operation| operation.drive(policy, 4, Retirement::Exhausted, |_| ()),
            )?;
            let (refusals, by) = run.with_policy(policy, |m| (RefusalRun::of(m), m.performer()));
            let recorded = refusals.clone();
            // The unplanted run is the session's: a planted defect below is
            // the run's alone.
            run.inspect_evidence(move |observed, _| recorded.recorded_in(observed, by, 0));
            Ok((refusals, by))
        })
    }

    #[test]
    #[should_panic(expected = "attempt/admission witnesses disagree")]
    fn refusal_accounting_rejects_a_planted_missing_admission() {
        let (mut refusals, _) = retained_admissions();
        refusals.admitted.remove(0);
        refusals.events();
    }

    /// The correspondence's planted defect: a run whose history claims an
    /// injected refusal the session recorded as ordinary is refused, the
    /// in-flight history and the evidence one record.
    #[test]
    #[should_panic(expected = "the session's refusals differ from the run's")]
    fn a_run_disagreeing_with_its_session_is_refused() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                RetainedAdmissions::default(),
                Retirement::Exhausted,
                &pipeline::Unwitnessed,
                |operation| operation.drive(policy, 4, Retirement::Exhausted, |_| ()),
            )?;
            let (mut refusals, by) =
                run.with_policy(policy, |m| (RefusalRun::of(m), m.performer()));
            assert_eq!(refusals.refusals, [(1, LimitRefusal::Work, false)]);
            refusals.refusals[0].2 = true;
            run.inspect_evidence(move |observed, _| refusals.recorded_in(observed, by, 0));
            Ok(())
        });
    }

    #[global_allocator]
    static HEAP: heap::Heap = heap::Heap;

    #[test]
    fn checkpoint_history_retains_edits_instead_of_repeated_custody() {
        let checkpoint = refinement::Checkpoint {
            boundary: 0,
            custody: vec![reporting(
                Identity::new(1, 1),
                &(0..256).map(|id| (id, None)).collect::<Vec<_>>(),
            )],
        };
        let measure = |compressed| {
            let observation = heap::Observation::begin(None);
            let mut history = refinement::History::new();
            let mut snapshots = Vec::new();
            for _ in 0..64 {
                if compressed {
                    history.push(checkpoint.clone());
                } else {
                    snapshots.push(checkpoint.clone());
                }
            }
            observation.stop();
            let retained = observation.snapshot();
            assert!(
                !retained.overflow,
                "live-allocation measurement is incomplete"
            );
            drop(history);
            drop(snapshots);
            assert_eq!(observation.snapshot().live, 0, "checkpoint storage leaked");
            retained.live
        };
        // The former implementation is the negative control of this same
        // live-byte bound, not an RSS or allocator-residency estimate.
        let limit = 32 * 1024;
        assert!(
            measure(false) > limit,
            "full snapshots escaped the memory witness"
        );
        assert!(
            measure(true) <= limit,
            "checkpoint history retains repeated full custody"
        );
    }

    /// Checkpoint storage on changing custody, attributed by the allocator:
    /// four owners' groups, each binding an acquisition, holding obligations
    /// and reporting permits, changed by the refinement crate's fixed edit
    /// sequence (`history.rs`,
    /// `obligation_edits_and_large_reordered_custody_reconstruct_exactly`:
    /// obligation work changed, settled away and newly admitted, permits
    /// rotated and reversed, groups swapped), at a size whose allocations
    /// the heap observer holds whole (`heap.rs`, `CAPACITY`). Only the pushes
    /// are observed, so the live bytes after them are exactly the history's
    /// allocations: they must equal what the history reports it retains
    /// (`History::retained_bytes`, the figure every recorded run's
    /// finalization holds to `History::storage`), every checkpoint must
    /// reconstruct exactly, the storage must be within the checkpoints'
    /// changes, and dropping the history must release every byte.
    #[test]
    fn checkpoint_storage_is_its_edits_on_changing_custody() {
        use refinement::{Checkpoint, Custody, Hold, Identity, Obligation, Reported, WriteWork};
        let hold = |n: u64, values: u64| Hold {
            obligation: [
                Obligation::Release,
                Obligation::Grant,
                Obligation::BucketWindow,
            ][(n % 3) as usize],
            work: WriteWork::new(values, values * 3),
            id: Identity::new(1, 1_000 + n),
            acquisition: Identity::new(1, 100 + n % 7),
        };
        let mut custody: Vec<Custody> = (0..4)
            .map(|g| Custody {
                owner: Identity::new(1, g + 1),
                bound: vec![Identity::new(1, 100 + g)],
                held: (0..8).map(|n| hold(g * 8 + n, 4)).collect(),
                permits: (0..32)
                    .map(|n| Reported {
                        permit: Identity::new(1, 100_000 + g * 32 + n),
                        record: None,
                    })
                    .collect(),
            })
            .collect();
        // xorshift64: the refinement crate's fixed sequence of edits.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % bound as u64).expect("below a usize bound")
        };
        let mut history = refinement::History::new();
        let mut expected = Vec::new();
        let observation = heap::Observation::begin(None);
        observation.stop();
        for turn in 0..48_u64 {
            let g = next(custody.len());
            let group = &mut custody[g];
            match next(6) {
                0 if !group.held.is_empty() => {
                    let at = next(group.held.len());
                    group.held[at].work = WriteWork::new(next(8) as u64, next(64) as u64);
                }
                1 if !group.held.is_empty() => {
                    let at = next(group.held.len());
                    group.held.remove(at);
                }
                2 => {
                    let by = next(group.permits.len());
                    group.permits.rotate_left(by);
                }
                3 => group.permits.reverse(),
                4 => {
                    let other = next(custody.len());
                    custody.swap(g, other);
                }
                _ => group.held.push(hold(10_000 + turn, 1)),
            }
            let boundary = usize::try_from(turn).expect("a turn fits in usize");
            expected.push(Checkpoint {
                boundary,
                custody: custody.clone(),
            });
            observation.window(|| {
                history.push(Checkpoint {
                    boundary,
                    custody: custody.clone(),
                })
            });
        }
        let retained = observation.snapshot();
        assert!(
            !retained.overflow,
            "the live-allocation measurement is incomplete: {retained:?}"
        );
        assert_eq!(
            retained.live,
            history.retained_bytes(),
            "the history's reported storage is not its live allocations"
        );
        assert_eq!(
            history.to_vec(),
            expected,
            "reconstructed checkpoints differ from the checkpoints pushed"
        );
        if let Err(excess) = history.storage() {
            panic!("checkpoint history stores unchanged custody: {excess}");
        }
        drop(history);
        assert_eq!(observation.snapshot().live, 0, "checkpoint storage leaked");
    }

    /// A session's permit records and event slots are each one zeroed
    /// allocation (`policy/record.rs`, `zeroed`): built element by element,
    /// they are allocated uninitialized and written one element at a time.
    #[test]
    fn a_session_allocates_its_records_and_slots_zeroed() {
        let observation = heap::Observation::begin(None);
        let session = Recording::new(CAPACITY);
        observation.stop();
        let stats = observation.snapshot();
        drop(session);
        assert!(!stats.overflow, "the allocation observation is incomplete");
        assert_eq!(
            stats.zeroed, 2,
            "a session's records and slots are not each one zeroed allocation: {stats:?}"
        );
    }

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
            || AllocatingObserver.observe(),
            &Limits::unlimited(),
            &observer,
            "planted observer",
        );
    }

    /// An operation whose one unit of work is a byte wider than a turn's
    /// quantum.
    struct Wide;

    impl Custodial<Permit> for Wide {
        fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
            PermitsObserved::Complete
        }
    }

    terminal!(Exhausted: [] Wide);

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

    /// A unit no turn admits stops the drive at its first refusal, a stall
    /// returned as data naming the call and its unit, instead of being
    /// retried until the turn bound is spent; detached, it names the quantum
    /// it exceeds.
    #[test]
    fn a_unit_wider_than_a_turn_stalls_at_once() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let stop = run
                .holding(
                    Wide,
                    Retirement::Exhausted,
                    &pipeline::Unwitnessed,
                    |operation| operation.drive(policy, TURNS, Retirement::Exhausted, |_| ()),
                )
                .expect_err("a unit no turn admits published");
            assert!(
                matches!(
                    stop,
                    Stopped::Stalled { call: 0, values: 1, bytes, position: Some(ref position) }
                        if bytes == TURN.bytes + 1 && position == "0"
                ),
                "{stop:?}"
            );
            run.with_policy(policy, |m| {
                assert_eq!(m.attempts(), 1, "the stalled unit was retried")
            });
            let finding = Finding::from(stop).to_string();
            assert!(
                finding.starts_with(
                    "call 0: an indivisible unit of 1 values and 65 bytes exceeds a turn's quantum"
                ),
                "{finding}"
            );
            Ok(())
        });
    }

    /// The machine's refusal of a work call admitted without its admission
    /// of `bytes`, at the end of the stream: what a deliberate direct
    /// `traverse` of one value and `bytes` bytes, alone in a run, reaches.
    fn unadmitted(bytes: u64) -> refinement::Divergence {
        refinement::Divergence {
            at: refinement::At::End,
            rule: refinement::Rule::MissingAdmission(WriteWork::new(1, bytes)),
        }
    }

    /// A direct work call bypassing the route, alone in a recorded run.
    #[expect(
        clippy::disallowed_methods,
        reason = "the deliberate unrouted call the finalizer's negative controls refuse"
    )]
    fn unrouted(run: &mut RecordedRun, bytes: u64) {
        let policy = run.policy(u64::MAX);
        run.with_policy(policy, |m| {
            m.traverse(1, bytes).expect("an unlimited policy admits")
        });
    }

    /// An empty complete run refines the protocol.
    #[test]
    fn an_empty_run_is_accepted() {
        recorded_run(|run| {
            run.policy(u64::MAX);
            Ok(())
        });
    }

    #[test]
    fn standalone_consumer_unwind_reclaims_before_finalization() {
        let wire = dcbor::CBOR::from("standalone custody").to_cbor_data();
        let failure = std::panic::catch_unwind(|| {
            construction::<String>(&wire, None, |value| {
                assert_eq!(value, "standalone custody");
                panic!("planted standalone consumer unwind");
            });
        })
        .expect_err("the standalone consumer panic must propagate");
        let report = panic_report(failure.as_ref());
        assert!(
            report.contains("planted standalone consumer unwind"),
            "{report}"
        );
        assert!(
            report.ends_with("finalization: the recording finished and refined the protocol"),
            "standalone unwind did not reclaim before finalization: {report}"
        );
    }

    /// An expected rejection the machine does not make fails the control.
    #[test]
    #[should_panic(expected = "the control unexpectedly refined the protocol")]
    fn an_expected_rejection_of_an_accepted_run_fails() {
        recorded_control(unadmitted(256), |run| {
            run.policy(u64::MAX);
            Ok(())
        });
    }

    /// The machine's exact refusal satisfies a negative control.
    #[test]
    fn an_unrouted_call_is_refused_exactly() {
        recorded_control(unadmitted(256), |run| {
            unrouted(run, 256);
            Ok(())
        });
    }

    /// A refusal at another quantity than expected fails the control.
    #[test]
    #[should_panic(expected = "the control must fail at its intended location and rule")]
    fn a_refusal_other_than_expected_fails() {
        recorded_control(unadmitted(255), |run| {
            unrouted(run, 256);
            Ok(())
        });
    }

    /// A recording a returned value still publishes into is no evidence,
    /// whatever verdict was expected.
    #[test]
    #[should_panic(expected = "the run's recording is no evidence: Live")]
    fn an_incomplete_recording_satisfies_no_expectation() {
        let held = recorded_control(unadmitted(256), |run| {
            unrouted(run, 256);
            let policy = run.policy(u64::MAX);
            let held = run.with_policy(policy, |m| {
                let owner = m.owner().expect("an owner of the held storage");
                let mut bytes = dcbor::bounded::Owned::<u8, Permit>::new();
                bytes
                    .reserve(8, m, &owner)
                    .expect("an unlimited policy grants");
                (owner, bytes)
            });
            Ok(held)
        });
        drop(held);
    }

    /// A defect recorded over a recording that finishes and refines still
    /// fails the run, naming the defect: a successful finalization never
    /// erases it.
    #[test]
    #[should_panic(
        expected = "the run found 1 defect(s): planted finding; finalization: the recording \
                    finished and refined the protocol"
    )]
    fn a_recorded_defect_fails_a_run_whose_recording_refines() {
        recorded_run(|run| {
            run.policy(u64::MAX);
            run.defect("planted finding".to_string());
            Ok(())
        });
    }

    /// A defect recorded beside a leaked capability: the run fails naming
    /// both the defect and the recording's own refusal, neither masking the
    /// other. The leaked owner is forgotten inside the body, as a planted
    /// defect that loses a capability would.
    #[test]
    #[should_panic(
        expected = "the run found 1 defect(s): planted leak; finalization: the recording is no \
                    evidence: Live"
    )]
    fn a_recorded_defect_is_reported_beside_its_recordings_refusal() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let owner = run.with_policy(policy, |m| m.owner().expect("a recorded owner"));
            core::mem::forget(owner);
            run.defect("planted leak".to_string());
            Ok(())
        });
    }

    /// A defect recorded beside a stream the machine refuses: both are
    /// named.
    #[test]
    #[should_panic(
        expected = "the run found 1 defect(s): planted refusal; finalization: the recording \
                    finished and does not refine the protocol"
    )]
    fn a_recorded_defect_is_reported_beside_the_machines_refusal() {
        recorded_run(|run| {
            unrouted(run, 256);
            run.defect("planted refusal".to_string());
            Ok(())
        });
    }

    /// A defect recorded beside a policy whose history cannot be read: the
    /// policy's correspondence fails after the body returns, and finalization
    /// is still attempted, so the run fails naming the defect, the
    /// correspondence finding and the session's own finish result, none
    /// masking another. The history is made unreadable as production makes
    /// it: the run's policy validated against an owner of another session,
    /// which invalidates the run's session, stickily.
    #[test]
    fn a_correspondence_failure_neither_skips_finalization_nor_hides_a_defect() {
        let failure = std::panic::catch_unwind(|| {
            recorded_run(|run| {
                let policy = run.policy(u64::MAX);
                let other = Recording::new(CAPACITY);
                let mut foreign = Limits::recorded_unlimited(&other);
                let owner = foreign
                    .owner()
                    .expect("a recorded owner of another session");
                let refused = run.with_policy(policy, |m| m.validate_owner(&owner));
                assert_eq!(refused, Err(LimitRefusal::Unrecorded));
                drop(owner);
                drop(foreign);
                drop(other);
                run.defect("planted finding".to_string());
                Ok(())
            });
        })
        .expect_err("a run with a defect and a correspondence failure passed");
        let report = failure
            .downcast::<String>()
            .expect("the finalizer names its findings");
        assert!(
            report.starts_with("the run found 1 defect(s): planted finding; "),
            "{report}"
        );
        assert!(
            report.contains(
                "1 correspondence finding(s): policy 0: the policy's history cannot be read: \
                 Session(Exhausted); "
            ),
            "{report}"
        );
        assert!(
            report.ends_with(
                "finalization: the recording is no evidence: Exhausted, first by ForeignOwner"
            ),
            "finalization was not attempted: {report}"
        );
    }

    /// A correspondence failure alone still fails the run, with the
    /// recording's finish result beside it: acceptance stays strict.
    #[test]
    #[should_panic(
        expected = "1 correspondence finding(s): policy 0: the policy's history cannot be read"
    )]
    fn a_correspondence_failure_alone_fails_the_run() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let other = Recording::new(CAPACITY);
            let mut foreign = Limits::recorded_unlimited(&other);
            let owner = foreign
                .owner()
                .expect("a recorded owner of another session");
            let refused = run.with_policy(policy, |m| m.validate_owner(&owner));
            assert_eq!(refused, Err(LimitRefusal::Unrecorded));
            Ok(())
        });
    }

    /// A custody of one owner reporting `permits`, each with its stage.
    fn reporting(
        owner: Identity,
        permits: &[(u64, Option<dcbor::bounded::RecordStage>)],
    ) -> refinement::Custody {
        refinement::Custody {
            owner,
            bound: Vec::new(),
            held: Vec::new(),
            permits: permits
                .iter()
                .map(|&(sequence, record)| refinement::Reported {
                    permit: Identity::new(3, sequence),
                    record,
                })
                .collect(),
        }
    }

    /// The retirement comparison's pass and fail scenarios, one legal
    /// retirement and one planted departure per kind: a wrapper that
    /// released a permit; a published handle whose record was released
    /// instead of queued, and one queued as `Active`; a granted cancellation
    /// that released an initialized record, and one that released nothing;
    /// a handle's reclamation that released a queued record; an active
    /// reclamation whose permit changed owner; and a permit that appeared.
    #[test]
    fn the_retirement_comparison_names_every_departure_from_its_kind() {
        use dcbor::bounded::RecordStage::{Active, Granted, Handle, Queued};
        let owner = Identity::new(1, 1);
        let other = Identity::new(1, 2);
        let permits = |sequences: &[u64]| -> std::collections::BTreeSet<Identity> {
            sequences
                .iter()
                .map(|&sequence| Identity::new(3, sequence))
                .collect()
        };
        // The value reported every permit of `before`.
        let check = |before: &[(u64, _)], after: &[_], kind| {
            let owned = before
                .iter()
                .map(|&(sequence, _)| sequence)
                .collect::<Vec<_>>();
            retirement_violations(
                &[reporting(owner, before)],
                &[reporting(owner, after)],
                &std::collections::BTreeMap::new(),
                &permits(&owned),
                kind,
            )
        };
        // The value reported only the permits `owned` names; the rest are
        // its surroundings.
        let around = |before: &[(u64, _)], after: &[_], owned: &[u64], kind| {
            retirement_violations(
                &[reporting(owner, before)],
                &[reporting(owner, after)],
                &std::collections::BTreeMap::new(),
                &permits(owned),
                kind,
            )
        };
        // The value reported every permit of `before`, record `held` lying,
        // after the retirement, in the payload of record `holder`.
        let nested = |before: &[(u64, _)], after: &[_], held: u64, holder: u64, kind| {
            let owned = before
                .iter()
                .map(|&(sequence, _)| sequence)
                .collect::<Vec<_>>();
            retirement_violations(
                &[reporting(owner, before)],
                &[reporting(owner, after)],
                &std::collections::BTreeMap::from([(
                    Identity::new(3, held),
                    Identity::new(3, holder),
                )]),
                &permits(&owned),
                kind,
            )
        };
        // Legal retirements.
        assert!(around(&[(1, None)], &[(1, None)], &[], Retirement::Exhausted).is_empty());
        assert!(
            check(
                &[(1, Some(Handle)), (2, None)],
                &[(1, Some(Queued)), (2, None)],
                Retirement::Published
            )
            .is_empty()
        );
        assert!(
            check(
                &[(1, Some(Granted)), (2, None)],
                &[(2, None)],
                Retirement::GrantedCancelled
            )
            .is_empty()
        );
        assert!(
            check(
                &[(1, Some(Handle)), (2, None)],
                &[],
                Retirement::HandleReclaimed
            )
            .is_empty()
        );
        assert!(
            check(
                &[(1, Some(Active)), (2, None)],
                &[],
                Retirement::ActiveReclaimed
            )
            .is_empty()
        );
        // Planted departures, each named.
        let named = |violations: Vec<String>, expected: &str| {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "{expected} not named: {violations:?}"
            );
        };
        // A published value whose record holds another handle in its
        // payload: its own record queues, the held handle stays a handle,
        // the queued record's payload.
        assert!(
            nested(
                &[(1, Some(Handle)), (2, Some(Handle))],
                &[(1, Some(Queued)), (2, Some(Handle))],
                2,
                1,
                Retirement::Published,
            )
            .is_empty(),
            "a handle in a queued record's payload is no handle of the value's own"
        );
        // Held in the payload of a record that did not queue: the held
        // handle is the value's own, left unqueued.
        named(
            nested(
                &[(1, Some(Handle)), (2, Some(Handle)), (3, Some(Handle))],
                &[(1, Some(Queued)), (2, Some(Handle)), (3, Some(Handle))],
                2,
                3,
                Retirement::Published,
            ),
            "Identity { family: 3, sequence: 2 } was not queued",
        );
        // The scope's terminal drain releasing a queued record releases the
        // handle its payload holds with it.
        assert!(
            nested(
                &[(1, Some(Queued)), (2, Some(Handle))],
                &[],
                2,
                1,
                Retirement::Scope,
            )
            .is_empty(),
            "a handle in a released record's payload is released with it"
        );
        // Inside a record the retirement may not release: the held handle's
        // release is named beside its container's.
        named(
            nested(
                &[(1, Some(Handle)), (2, Some(Handle))],
                &[],
                2,
                1,
                Retirement::Scope,
            ),
            "Identity { family: 3, sequence: 2 } of stage Some(Handle) released",
        );
        named(
            check(&[(1, None)], &[], Retirement::Exhausted),
            "Exhausted: permit Identity",
        );
        named(
            check(&[(1, Some(Handle))], &[], Retirement::Published),
            "of stage Some(Handle) released",
        );
        named(
            check(
                &[(1, Some(Handle))],
                &[(1, Some(Active))],
                Retirement::Published,
            ),
            "Identity { family: 3, sequence: 1 } was not queued, it is Some(Active)",
        );
        named(
            check(&[(1, Some(Handle))], &[], Retirement::GrantedCancelled),
            "of stage Some(Handle) released",
        );
        named(
            check(
                &[(1, Some(Granted))],
                &[(1, Some(Granted))],
                Retirement::GrantedCancelled,
            ),
            "no Granted record released",
        );
        named(
            check(&[(1, Some(Queued))], &[], Retirement::HandleReclaimed),
            "of stage Some(Queued) released",
        );
        named(
            retirement_violations(
                &[reporting(owner, &[(1, Some(Active)), (2, None)])],
                &[reporting(other, &[(2, None)])],
                &std::collections::BTreeMap::new(),
                &permits(&[1, 2]),
                Retirement::ActiveReclaimed,
            ),
            "moved from owner",
        );
        named(
            around(&[(1, None)], &[(1, None)], &[1], Retirement::Exhausted),
            "the wrapper held permits",
        );
        // The value's own Handle must queue; a surrounding Handle need not.
        named(
            around(
                &[(1, Some(Handle)), (2, Some(Granted))],
                &[(1, Some(Handle))],
                &[1, 2],
                Retirement::Stopped,
            ),
            "the value's Handle record",
        );
        assert!(
            around(
                &[(1, Some(Handle)), (2, Some(Granted))],
                &[(1, Some(Handle))],
                &[2],
                Retirement::Stopped,
            )
            .is_empty(),
            "a surrounding live handle is no part of the stopped value"
        );
        // Surrounding custody is never released or restaged.
        named(
            around(
                &[(1, None), (2, Some(Granted))],
                &[],
                &[2],
                Retirement::Stopped,
            ),
            "surrounding permit Identity",
        );
        named(
            around(
                &[(1, Some(Handle)), (2, Some(Handle))],
                &[(1, Some(Queued)), (2, Some(Queued))],
                &[2],
                Retirement::Published,
            ),
            "Published: surrounding permit",
        );
        named(
            check(&[], &[(4, None)], Retirement::Exhausted),
            "appeared under",
        );
        named(
            check(
                &[(1, Some(Handle))],
                &[(1, Some(Handle))],
                Retirement::Published,
            ),
            "no Handle record queued",
        );
        named(
            check(&[(1, Some(Handle))], &[], Retirement::Stopped),
            "of stage Some(Handle) released",
        );
        assert!(
            check(
                &[(1, Some(Granted)), (2, Some(Handle)), (3, None)],
                &[(2, Some(Queued)), (3, None)],
                Retirement::Stopped,
            )
            .is_empty()
        );
    }

    /// A published value retired through the one retirement entry point: its
    /// record moves from its handle to the scope queue, nothing released;
    /// both checkpoints refine, and the scope's drain then releases it.
    #[test]
    fn a_published_value_retires_to_the_queue_through_the_orchestration() {
        let wire = dcbor::CBOR::from("abc").to_cbor_data();
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                DecodeOwner::new(),
                Retirement::Scope,
                &pipeline::Unwitnessed,
                |owner| {
                    owner.initialize(policy)?;
                    owner.decoder::<_, String, _, _>(
                        policy,
                        Copying(&wire),
                        Options::normalizing(8),
                        &pipeline::Unwitnessed,
                        |decoder| {
                            decoder.drive(
                                policy,
                                typed_turns::<String>(wire.len()),
                                Retirement::Published,
                                |_| (),
                            )
                        },
                    )??;
                    owner.drain(policy)
                },
            )
        });
    }

    /// A typed decode stopped in production while it holds records of its
    /// own beside its input's, retired through the one orchestration as
    /// `Stopped`: every record it held moves from its handle to the scope
    /// queue, `Handle` to `Queued`, under the same owner; nothing of the
    /// scope is released; both checkpoints refine, and the drain then
    /// releases what was queued. Planted control
    /// (`tests/data/controls/retirement-record-left-unqueued.patch`): the
    /// record links into the queue with its custody still `Handle`, which
    /// the comparison names as the value's Handle record not queued.
    #[test]
    fn a_stopped_decoder_queues_every_record_it_held() {
        use dcbor::bounded::RecordStage;
        let wire = dcbor::CBOR::from("abc").to_cbor_data();
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            // The records the decoder's own custody holds as handles: its
            // input's, then the ones its stages allocate.
            let handles = |decoder: &mut TypedDecoder<'_, ByteString, String, Limits>| {
                collect(|sink| decoder.observe_custody(sink)).map(|custody| {
                    custody
                        .iter()
                        .flat_map(|group| &group.permits)
                        .filter(|reported| reported.record == Some(RecordStage::Handle))
                        .count()
                })
            };
            run.holding(
                DecodeOwner::new(),
                Retirement::Scope,
                &pipeline::Unwitnessed,
                |owner| {
                    owner.initialize(policy)?;
                    let published = owner.decoder::<_, String, _, _>(
                        policy,
                        Copying(&wire),
                        Options::normalizing(8),
                        &pipeline::Unwitnessed,
                        |decoder| {
                            decoder.controlled(
                                policy,
                                typed_turns::<String>(wire.len()),
                                Retirement::Published,
                                true,
                                |_, decoder, _| {
                                    handles(decoder).expect("the decoder reports whole custody")
                                        >= 2
                                },
                                |_| (),
                            )
                        },
                    )??;
                    assert!(
                        published.is_none(),
                        "the decode published before holding a record beside its input's"
                    );
                    owner.drain(policy)
                },
            )
        });
    }

    #[test]
    fn retirement_uses_one_capture_per_side_and_finalizes_after_destructor_panic() {
        struct PanickingDestructor;

        impl Drop for PanickingDestructor {
            fn drop(&mut self) {
                panic!("planted retirement panic");
            }
        }

        let observations = std::cell::Cell::new(0);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recorded_run(|run| {
                retired(
                    &run.session,
                    &mut run.checkpoints,
                    &mut run.defects,
                    Retirement::Exhausted,
                    PanickingDestructor,
                    |value, _| {
                        // The checkpointed observation with the value, the
                        // surroundings' classifying read beside it, then the
                        // checkpointed observation after the destruction.
                        let index = observations.get();
                        assert_eq!(value.is_some(), index == 0);
                        observations.set(index + 1);
                        PermitsObserved::Complete
                    },
                    &pipeline::Unwitnessed,
                );
                assert_eq!(
                    run.checkpoints.len(),
                    2,
                    "both exact captures are checkpoints"
                );
                Ok(())
            });
        }))
        .expect_err("a destructor panic must fail the recorded run");
        assert_eq!(
            observations.get(),
            3,
            "each side is captured once, beside one classifying read of the surroundings"
        );
        let report = panic_report(failure.as_ref());
        assert!(
            report.contains("retirement destructor panicked: planted retirement panic"),
            "{report}"
        );
        assert!(
            report.ends_with("finalization: the recording finished and refined the protocol"),
            "{report}"
        );
    }

    /// The orchestration's planted defect: the same published value
    /// declared a granted cancellation fails the run naming its departure.
    #[test]
    #[should_panic(expected = "GrantedCancelled: no Granted record released")]
    fn a_retirement_declared_as_the_wrong_kind_fails_the_run() {
        let wire = dcbor::CBOR::from("abc").to_cbor_data();
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                DecodeOwner::new(),
                Retirement::Scope,
                &pipeline::Unwitnessed,
                |owner| {
                    owner.initialize(policy)?;
                    owner.decoder::<_, String, _, _>(
                        policy,
                        Copying(&wire),
                        Options::normalizing(8),
                        &pipeline::Unwitnessed,
                        |decoder| {
                            decoder.drive(
                                policy,
                                typed_turns::<String>(wire.len()),
                                Retirement::GrantedCancelled,
                                |_| (),
                            )
                        },
                    )??;
                    owner.drain(policy)
                },
            )
        });
    }

    /// A text encoding: its output publishes a permit the operation no
    /// longer holds.
    type Encoder =
        dcbor::bounded::text_cursor::TextEncoder<'static, Permit, dcbor::bounded::Family>;

    const TEXT: &str = "published";

    #[test]
    fn threaded_turns_join_before_parent_retirement_and_preserve_panics() {
        struct WorkerOperation {
            parent: std::thread::ThreadId,
            turns: Arc<std::sync::Mutex<Vec<std::thread::ThreadId>>>,
            retired: Arc<AtomicUsize>,
            panic: bool,
            published: bool,
        }

        impl Custodial<Permit> for WorkerOperation {
            fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
                assert_eq!(std::thread::current().id(), self.parent);
                PermitsObserved::Complete
            }
        }

        // It reports no custody at any step.
        terminal!(Exhausted: [] WorkerOperation);

        impl Drop for WorkerOperation {
            fn drop(&mut self) {
                assert_eq!(std::thread::current().id(), self.parent);
                self.retired.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl Resumable<Limits> for WorkerOperation {
            type Output = ();
            type Error = BoundedError<LimitRefusal>;
            type Position = bool;

            fn step(&mut self, _: &mut Limits) -> Result<Step<()>, Self::Error> {
                let thread = std::thread::current().id();
                assert_ne!(thread, self.parent, "a worker turn executed in the parent");
                self.turns.lock().expect("turn witness lock").push(thread);
                assert!(!self.panic, "planted threaded production panic");
                if self.published {
                    Ok(Step::Finished)
                } else {
                    self.published = true;
                    Ok(Step::Complete(()))
                }
            }

            fn position(&mut self) -> bool {
                self.published
            }
        }

        for panic in [false, true] {
            let parent = std::thread::current().id();
            let turns = Arc::new(std::sync::Mutex::new(Vec::new()));
            let retired = Arc::new(AtomicUsize::new(0));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                recorded_run(|run| {
                    let policy = run.policy(u64::MAX);
                    run.holding(
                        WorkerOperation {
                            parent,
                            turns: Arc::clone(&turns),
                            retired: Arc::clone(&retired),
                            panic,
                            published: false,
                        },
                        Retirement::Released,
                        &pipeline::Unwitnessed,
                        |operation| {
                            operation.drive_threaded(
                                policy,
                                1,
                                Retirement::Released,
                                |_, _| {},
                                |_| {
                                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                                    let turns = turns.lock().expect("turn witness lock");
                                    assert_eq!(turns.len(), 2, "publication and terminal probe");
                                    assert_ne!(turns[0], turns[1], "turns reused a worker");
                                },
                            )
                        },
                    )?;
                    Ok(())
                });
            }));
            assert_eq!(retired.load(Ordering::SeqCst), 1, "retirement count");
            match (panic, result) {
                (false, Ok(())) => {}
                (true, Err(payload)) => {
                    assert_eq!(turns.lock().expect("turn witness lock").len(), 1);
                    let report = panic_report(payload.as_ref());
                    assert!(
                        report.contains("planted threaded production panic"),
                        "{report}"
                    );
                    assert!(
                        report.ends_with(
                            "finalization: the recording finished and refined the protocol"
                        ),
                        "{report}"
                    );
                }
                (_, result) => panic!("unexpected threaded run outcome: {result:?}"),
            }
        }
    }

    #[test]
    fn worker_panic_returns_custody_for_parent_retirement_after_all_joins() {
        struct Returned {
            parent: std::thread::ThreadId,
            joined_work: Arc<AtomicUsize>,
            retired: Arc<AtomicUsize>,
            observed: bool,
        }

        impl Custodial<Permit> for Returned {
            fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
                self.observed = true;
                PermitsObserved::Complete
            }
        }

        impl Drop for Returned {
            fn drop(&mut self) {
                assert_eq!(std::thread::current().id(), self.parent);
                assert_eq!(self.joined_work.load(Ordering::SeqCst), 2);
                assert!(self.observed, "worker custody retired without observation");
                self.retired.fetch_add(1, Ordering::SeqCst);
            }
        }

        let parent = std::thread::current().id();
        let joined_work = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicUsize::new(0));
        recorded_run(|run| {
            let policies = [run.policy(1024), run.policy(1024)];
            let result = run.workers(
                &policies,
                1,
                Retirement::Released,
                |_| Returned {
                    parent,
                    joined_work: Arc::clone(&joined_work),
                    retired: Arc::clone(&retired),
                    observed: false,
                },
                |worker, _, _, _| {
                    joined_work.fetch_add(1, Ordering::SeqCst);
                    if worker == 0 {
                        panic!("planted worker custody panic");
                    }
                    Ok(())
                },
            );
            assert!(
                matches!(result, Err(Finding::Defect(ref report))
                    if report.contains("worker 0, fixture 0: planted worker custody panic")),
                "{result:?}"
            );
            assert_eq!(retired.load(Ordering::SeqCst), 2);
            Ok(())
        });
    }

    #[test]
    fn violated_turn_observes_publication_and_preserves_observer_failure() {
        struct Publication<'a>(&'a std::cell::Cell<bool>);

        impl Drop for Publication<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        struct Publisher<'a>(&'a std::cell::Cell<bool>);

        impl<'a> Resumable<Limits> for Publisher<'a> {
            type Output = Publication<'a>;
            type Error = BoundedError<LimitRefusal>;
            type Position = ();

            fn step(&mut self, _: &mut Limits) -> Result<Step<Self::Output>, Self::Error> {
                panic!("observation must not execute another turn");
            }

            fn position(&mut self) {}
        }

        let retired = std::cell::Cell::new(false);
        let observed = std::cell::Cell::new(false);
        let m = Limits::unlimited();
        let mut publisher = Publisher(&retired);
        let publication = Publication(publisher.0);
        let result = observe_turn(
            &m,
            &mut publisher,
            Turned {
                outcome: Ok(Step::Complete(publication)),
                lost: None,
                violation: Some("planted contract failure".to_owned()),
            },
            0,
            |_, _, outcome| {
                assert!(matches!(outcome, Ok(Step::Complete(_))));
                assert!(!retired.get(), "publication retired before observation");
                observed.set(true);
                panic!("planted observer failure");
            },
        );
        assert!(
            observed.get(),
            "contract failure bypassed custody observation"
        );
        assert!(!retired.get(), "observer unwind destroyed publication");
        match result {
            Err(Stopped::Violated {
                outcome: Some(Ok(Step::Complete(publication))),
                report,
                ..
            }) => {
                assert!(report.contains("planted contract failure"), "{report}");
                assert!(report.contains("planted observer failure"), "{report}");
                drop(publication);
            }
            _ => panic!("observation discarded the publication or contract failure"),
        }
        assert!(retired.get(), "returned publication was not retired");
    }

    #[test]
    fn lost_turn_skips_history_observation_and_retains_its_publication() {
        use std::cell::Cell;

        struct Publication<'a>(&'a Cell<bool>);
        impl Drop for Publication<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let retired = Cell::new(false);
        let checked = Cell::new(false);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recorded_run(|run| {
                let policy = run.policy(u64::MAX);
                run.with_policy(policy, |m| {
                    assert_eq!(
                        m.validate_owner(&dcbor::bounded::Owner::unobserved()),
                        Err(LimitRefusal::Unrecorded),
                    );
                    let first = lost(m, 7).expect("the pairing invalidated the recording");
                    let outcome: Result<Publication<'_>, BoundedError<LimitRefusal>> =
                        Ok(Publication(&retired));
                    let stopped = Turned {
                        outcome,
                        lost: Some(first.clone()),
                        violation: None,
                    }
                    .observed(m, 8, |_| panic!("invalid history reached the observer"))
                    .checked::<(), BoundedError<LimitRefusal>>();
                    assert!(!retired.get(), "loss destroyed the publication");
                    match stopped {
                        Err(Stopped::Lost(actual, Ok(publication))) => {
                            assert_eq!(actual, first, "observation replaced failure-time evidence");
                            drop(publication);
                        }
                        _ => panic!("loss discarded its exact outcome"),
                    }
                    checked.set(true);
                });
                Ok(())
            });
        }))
        .expect_err("recording loss must fail finalization");
        assert!(checked.get(), "loss check did not complete");
        assert!(retired.get(), "retained publication was not retired");
        assert!(panic_report(failure.as_ref()).contains("ForeignOwner"));
    }

    #[test]
    fn observer_invalidation_and_unwind_retain_the_acquired_outcome() {
        use std::cell::Cell;

        for panic in [false, true] {
            let checked = Cell::new(false);
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                recorded_run(|run| {
                    let policy = run.policy(u64::MAX);
                    let mut invalidator = recorded_policy(&run.session, u64::MAX, false);
                    run.with_policy(policy, |m| {
                        let outcome: Result<usize, BoundedError<LimitRefusal>> = Ok(73);
                        let stopped = scope_turn(m, outcome, 4)
                            .observed(m, 4, |outcome| {
                                assert_eq!(*outcome, Ok(73));
                                assert_eq!(
                                    invalidator
                                        .validate_owner(&dcbor::bounded::Owner::unobserved()),
                                    Err(LimitRefusal::Unrecorded),
                                );
                                if panic {
                                    panic!("planted acquisition observer unwind");
                                }
                            })
                            .checked::<(), BoundedError<LimitRefusal>>();
                        match stopped {
                            Err(Stopped::Lost(lost, Ok(73))) if !panic => {
                                assert_eq!(lost.turn, 4);
                            }
                            Err(Stopped::Violated {
                                outcome: Some(Ok(73)),
                                lost: Some(lost),
                                report,
                                ..
                            }) if panic => {
                                assert_eq!(lost.turn, 4);
                                assert!(report.contains("planted acquisition observer unwind"));
                            }
                            _ => panic!("observer failure discarded acquisition evidence"),
                        }
                        checked.set(true);
                    });
                    Ok(())
                });
            }))
            .expect_err("observer invalidation must fail finalization");
            assert!(checked.get(), "observer check did not complete");
            assert!(panic_report(failure.as_ref()).contains("ForeignOwner"));
        }
    }

    /// Publication and its illegal second publication must both reach the
    /// holding's observer before either destructor runs.
    #[test]
    fn terminal_probe_retains_both_publications_for_observed_retirement() {
        use std::cell::Cell;

        struct Publication<'a> {
            index: usize,
            observed: &'a Cell<[bool; 2]>,
            retired: &'a Cell<[bool; 2]>,
        }

        impl Custodial<Permit> for Publication<'_> {
            fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
                let mut observed = self.observed.get();
                observed[self.index] = true;
                self.observed.set(observed);
                PermitsObserved::Complete
            }
        }

        impl Drop for Publication<'_> {
            fn drop(&mut self) {
                let mut retired = self.retired.get();
                retired[self.index] = self.observed.get()[self.index];
                self.retired.set(retired);
            }
        }

        struct Twice<'a> {
            next: usize,
            observed: &'a Cell<[bool; 2]>,
            retired: &'a Cell<[bool; 2]>,
        }

        impl Custodial<Permit> for Twice<'_> {
            fn observe_custody(&mut self, _: &mut dyn CustodySink<Permit>) -> PermitsObserved {
                PermitsObserved::Complete
            }
        }

        // It reports no custody at any step.
        terminal!(Exhausted: [] Twice<'_>);

        impl<'a> Resumable<Limits> for Twice<'a> {
            type Output = Publication<'a>;
            type Error = BoundedError<LimitRefusal>;
            type Position = usize;

            fn step(&mut self, _: &mut Limits) -> Result<Step<Self::Output>, Self::Error> {
                let index = self.next;
                self.next += 1;
                assert!(
                    index < 2,
                    "execution continued after the terminal violation"
                );
                Ok(Step::Complete(Publication {
                    index,
                    observed: self.observed,
                    retired: self.retired,
                }))
            }

            fn position(&mut self) -> usize {
                self.next
            }
        }

        let observed = Cell::new([false; 2]);
        let retired = Cell::new([false; 2]);
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                Twice {
                    next: 0,
                    observed: &observed,
                    retired: &retired,
                },
                Retirement::Released,
                &pipeline::Unwitnessed,
                |operation| {
                    let result = operation.drive(policy, 1, Retirement::Released, |_| {
                        panic!("a violated publication reached the consumer")
                    });
                    match result {
                        Err(Stopped::Violated {
                            output: Some(()),
                            outcome: Some(outcome),
                            report,
                            ..
                        }) => {
                            assert_eq!(outcome.label(), "Complete");
                            assert!(
                                report.contains("a finished operation stepped to Complete"),
                                "{report}"
                            );
                        }
                        other => panic!("both publications were not retained: {other:?}"),
                    }
                    assert_eq!(operation.value().next, 2);
                },
            );
            Ok(())
        });
        assert_eq!(observed.get(), [true; 2]);
        assert_eq!(
            retired.get(),
            [true; 2],
            "a publication dropped before observed retirement"
        );
    }

    /// A held operation's cleanup that publishes stops there, the
    /// publication checkpointed beside the operation at its turn, then held
    /// and retired by the holding before the stop is returned
    /// ([`Holding::finish`]): the stop carries no custody.
    #[test]
    fn cleanup_checkpoints_an_unexpected_publication_before_returning_it() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                Encoder::new(TEXT),
                Retirement::Released,
                &pipeline::Unwitnessed,
                |encoder| match encoder.finish(policy, normalize_turns(TEXT), Retirement::Released)
                {
                    Err(Stopped::Published(())) => Ok(()),
                    other => Err(Finding::Driver(format!(
                        "cleanup did not stop at its unexpected publication: {other:?}"
                    ))),
                },
            )
        });
    }

    #[test]
    fn operation_cleanup_retains_first_loss_after_observer_failure() {
        struct Cleanup(usize);
        impl Resumable<Limits> for Cleanup {
            type Output = ();
            type Error = BoundedError<LimitRefusal>;
            type Position = usize;

            fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
                if self.0 == 1 {
                    assert_eq!(
                        m.validate_owner(&dcbor::bounded::Owner::unobserved()),
                        Err(LimitRefusal::Unrecorded)
                    );
                }
                self.0 += 1;
                Ok(if self.0 == 3 {
                    Step::Finished
                } else {
                    Step::Progress
                })
            }

            fn position(&mut self) -> usize {
                self.0
            }
        }

        for turns in [2, 3] {
            let session = Recording::new(CAPACITY);
            let mut m = recorded_policy(&session, u64::MAX, false);
            let mut operation = Cleanup(0);
            let mut snapshot = None;
            let (completed, result) = wound_by(
                &mut m,
                &mut operation,
                turns,
                false,
                |_, _| panic!("planted operation cleanup observer failure"),
                Execution {
                    step: |m: &mut Limits, operation: &mut Cleanup, _, at| {
                        let outcome = operation.step(m);
                        let loss = lost(m, at);
                        if snapshot.is_none() {
                            snapshot = loss.clone();
                        }
                        Turned {
                            outcome,
                            lost: loss,
                            violation: None,
                        }
                    },
                    end: |m: &mut Limits, _: &mut Cleanup, _, at| Turned {
                        outcome: Some(Ok(Step::Finished)),
                        lost: lost(m, at),
                        violation: None,
                    },
                },
            );
            assert_eq!(completed, turns == 3);
            assert_eq!(operation.0, turns, "failure interrupted physical cleanup");
            match result {
                Err(Stopped::Violated {
                    lost: Some(loss),
                    report,
                    ..
                }) => {
                    assert_eq!(loss.turn, 1, "cleanup replaced its first loss");
                    assert_eq!(Some(loss), snapshot);
                    assert!(report.contains("planted operation cleanup observer failure"));
                }
                other => panic!("cleanup discarded failure evidence: {other:?}"),
            }
        }
    }

    #[test]
    fn cleanup_terminal_probe_runs_in_the_supplied_window() {
        struct Finished<'a>(&'a std::cell::Cell<bool>);
        impl Resumable<Limits> for Finished<'_> {
            type Output = ();
            type Error = BoundedError<LimitRefusal>;
            type Position = ();

            fn step(&mut self, _: &mut Limits) -> Result<Step<()>, Self::Error> {
                assert!(self.0.get(), "cleanup terminal probe escaped its window");
                Ok(Step::Finished)
            }

            fn position(&mut self) {}
        }
        let inside = std::cell::Cell::new(false);
        let windows = std::cell::Cell::new(0);
        let mut observations = 0;
        let mut m = Limits::unlimited();
        wound_by(
            &mut m,
            &mut Finished(&inside),
            1,
            true,
            |_, _| {
                assert!(!inside.get(), "checkpoint ran inside the physical window");
                observations += 1;
            },
            Execution {
                step: |m: &mut Limits, operation: &mut Finished<'_>, observed, at| {
                    inside.set(true);
                    windows.set(windows.get() + 1);
                    let result = turn(m, operation, observed, at);
                    inside.set(false);
                    result
                },
                end: |m: &mut Limits, operation: &mut Finished<'_>, observed, at| {
                    inside.set(true);
                    windows.set(windows.get() + 1);
                    let result = terminal(m, operation, observed, at, &pipeline::Unwitnessed);
                    inside.set(false);
                    result
                },
            },
        )
        .1
        .expect("finished cleanup and its probe succeed");
        assert_eq!(
            windows.get(),
            2,
            "cleanup and its terminal probe each use a window"
        );
        assert_eq!(
            observations, 2,
            "both outcomes are observed outside their windows"
        );
    }

    /// How a completion checkpoint reports the published output: once, not
    /// at all, or twice.
    #[derive(Clone, Copy)]
    enum Output {
        Once,
        Omitted,
        Twice,
        /// The output's observation panics: no capture of it is stored.
        Panics,
    }

    /// A text encoder whose publication reports its custody as `output`
    /// plants it ([`Reported`]): the operation the completion-checkpoint
    /// controls drive.
    struct Planted {
        encoder: Encoder,
        output: Output,
    }

    /// A published encoding whose custody is reported as `output` plants
    /// it: once, the encoding's own traversal; omitted, nothing; twice, its
    /// traversal repeated.
    struct Reported<E> {
        encoding: E,
        output: Output,
    }

    impl<E: Custodial<Permit>> Custodial<Permit> for Reported<E> {
        fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
            match self.output {
                Output::Once => self.encoding.observe_custody(sink),
                Output::Omitted => PermitsObserved::Complete,
                Output::Twice => dcbor::bounded::observed_all([
                    self.encoding.observe_custody(sink),
                    self.encoding.observe_custody(sink),
                ]),
                Output::Panics => panic!("planted output observation failure"),
            }
        }
    }

    /// The encoder's own custody, unplanted.
    impl Custodial<Permit> for Planted {
        fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
            self.encoder.observe_custody(sink)
        }
    }

    // The plant wraps only the encoder's output.
    terminal!(Wraps: [] Planted => Encoder);

    /// The encoder's steps, its publication wrapped as planted.
    impl Resumable<Limits> for Planted {
        type Output = Reported<<Encoder as Resumable<Limits>>::Output>;
        type Error = <Encoder as Resumable<Limits>>::Error;
        type Position = <Encoder as Resumable<Limits>>::Position;

        fn step(&mut self, m: &mut Limits) -> Result<Step<Self::Output>, Self::Error> {
            let output = self.output;
            Ok(match self.encoder.step(m)? {
                Step::Progress => Step::Progress,
                Step::Finished => Step::Finished,
                Step::Complete(encoding) => Step::Complete(Reported { encoding, output }),
            })
        }

        fn position(&mut self) -> Self::Position {
            self.encoder.position()
        }
    }

    /// One recorded text encoding, held by the run and driven by the
    /// holding schedule ([`Holding::drive`]), a checkpoint after every turn
    /// observing the encoder and, at its completion, the published encoding
    /// as `output` plants it; the exhausted encoder then retired beside it,
    /// and the encoding retired as released storage.
    /// Returns the index of the completion's checkpoint, the encoding's
    /// owner and its permit's identity, detached, or the drive's stop as the
    /// run's finding.
    fn encode_checkpointed(
        run: &mut RecordedRun,
        output: Output,
    ) -> Result<(usize, Identity, Identity), Finding> {
        let policy = run.policy(u64::MAX);
        run.holding(
            Planted {
                encoder: Encoder::new(TEXT),
                output,
            },
            Retirement::Released,
            &pipeline::Unwitnessed,
            |encoder| {
                encoder
                    .drive(
                        policy,
                        normalize_turns(TEXT),
                        Retirement::Released,
                        |encoded| {
                            let completion = encoded
                                .publication()
                                .expect("a schedule's publication names its checkpoint")
                                .index();
                            let encoding = &encoded.value().encoding;
                            (
                                completion,
                                encoding.owner(),
                                <Limits as Releasing>::permit_identity(encoding.permit()),
                            )
                        },
                    )
                    .map_err(Finding::from)
            },
        )
    }

    /// A published output's permit is reported at its completion
    /// checkpoint, under its owner, and the run refines the protocol.
    #[test]
    fn a_completion_checkpoint_reports_the_published_output() {
        recorded_run(|run| encode_checkpointed(run, Output::Once));
    }

    /// Whether the checkpoint `id` of `run` reports `permit`.
    fn reports(run: &RecordedRun, id: CheckpointId, permit: Identity) -> bool {
        run.checkpoints
            .get(id.index())
            .expect("a captured checkpoint")
            .custody
            .iter()
            .flat_map(|group| &group.permits)
            .any(|reported| reported.permit == permit)
    }

    /// A publication made inside another publication's consumer names its
    /// own publishing checkpoint, and the outer output keeps naming its
    /// own: each holding carries the checkpoint its own publishing turn
    /// stored, which reports that output's permit; the inner one is later,
    /// and the outer's is unchanged once the inner consumer returns.
    #[test]
    fn nested_publications_each_name_their_own_publishing_checkpoint() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                Encoder::new(TEXT),
                Retirement::Released,
                &pipeline::Unwitnessed,
                |outer| {
                    outer
                        .drive(
                            policy,
                            normalize_turns(TEXT),
                            Retirement::Released,
                            |first| {
                                let first_at = first
                                    .publication()
                                    .expect("a schedule's publication names its checkpoint");
                                let first_permit =
                                    <Limits as Releasing>::permit_identity(first.value().permit());
                                assert!(
                                    reports(first.run, first_at, first_permit),
                                    "the outer publishing checkpoint does not report its output"
                                );
                                let second_at = first.holding(
                                    Encoder::new(TEXT),
                                    Retirement::Released,
                                    |inner| {
                                        inner.drive(
                                            policy,
                                            normalize_turns(TEXT),
                                            Retirement::Released,
                                            |second| {
                                                let at = second.publication().expect(
                                                    "a schedule's publication names its checkpoint",
                                                );
                                                let permit = <Limits as Releasing>::permit_identity(
                                                    second.value().permit(),
                                                );
                                                assert!(
                                                    reports(second.run, at, permit),
                                                    "the inner publishing checkpoint does not \
                                                 report its output"
                                                );
                                                at
                                            },
                                        )
                                    },
                                );
                                let second_at = second_at.map_err(Finding::from)?;
                                assert!(
                                    second_at.index() > first_at.index(),
                                    "the inner publication is not after the outer"
                                );
                                assert_eq!(
                                    first.publication(),
                                    Some(first_at),
                                    "the inner publication replaced the outer's identity"
                                );
                                Ok::<_, Finding>(())
                            },
                        )
                        .map_err(Finding::from)?
                },
            )
        });
    }

    /// A publishing turn whose checkpoint fails to capture (its output's
    /// observation panics) publishes nothing to a consumer: the turn is the
    /// drive's violation, the output retired by the holding, and the run
    /// fails naming the capture's failure. No publication identity is ever
    /// named for a checkpoint that was not stored.
    #[test]
    #[should_panic(expected = "a checkpoint's observation panicked: planted output observation")]
    fn a_publishing_turn_whose_capture_fails_reaches_no_consumer() {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let mut consumed = false;
            let driven = run.holding(
                Planted {
                    encoder: Encoder::new(TEXT),
                    output: Output::Panics,
                },
                Retirement::Released,
                &pipeline::Unwitnessed,
                |encoder| {
                    encoder.drive(policy, normalize_turns(TEXT), Retirement::Released, |_| {
                        consumed = true;
                    })
                },
            );
            assert!(
                !consumed,
                "a publication reached its consumer past a failed capture"
            );
            assert!(
                matches!(driven, Err(Stopped::Violated { .. })),
                "the failed capture was not the drive's violation: {driven:?}"
            );
            Ok(())
        });
    }

    /// A completion checkpoint that omits only the published output is
    /// refused by the machine at that checkpoint, the permit missing under
    /// its owner. The identities are the session's own, deterministic: the
    /// accepted run of the same operations names them.
    #[test]
    fn a_completion_checkpoint_missing_its_output_is_refused() {
        let (index, owner, permit) = recorded_run(|run| encode_checkpointed(run, Output::Once));
        recorded_control(
            refinement::Divergence {
                at: refinement::At::Checkpoint(index),
                rule: refinement::Rule::MissingPermit { owner, permit },
            },
            |run| encode_checkpointed(run, Output::Omitted),
        );
    }

    /// A published permit reported twice is refused by the collector before
    /// any checkpoint is stored.
    #[test]
    #[should_panic(expected = "a checkpoint's custody is no observation: DuplicatePermit")]
    fn a_completion_checkpoint_reporting_its_output_twice_is_refused() {
        recorded_run(|run| encode_checkpointed(run, Output::Twice));
    }

    /// A construction operation and its published value are observed
    /// through their exclusive (`&mut self`) traversals at every turn,
    /// beside the scope's authority, and the run refines the protocol.
    #[test]
    fn a_construction_and_its_published_value_are_observed_exclusively() {
        let wire = dcbor::CBOR::from("abc").to_cbor_data();
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.scoped(policy, &pipeline::Unwitnessed, |owner| {
                owner.copied(policy, &wire, |input| {
                    input.decode::<String, _>(policy, Options::normalizing(8), |value| {
                        assert_eq!(value.value().value(), "abc");
                        value.checkpoint();
                    })
                })?
            })
        });
    }

    /// Two owners and three permits of distinct recorded identities, for the
    /// collector's controls; the session and its policy kept beside them.
    fn fixture() -> (Recording, Limits, [Permit; 3]) {
        let session = Recording::new(CAPACITY);
        let mut m = recorded_policy(&session, u64::MAX, false);
        let permits = [
            m.allocate(8).expect("an unlimited policy grants"),
            m.allocate(8).expect("an unlimited policy grants"),
            m.allocate(8).expect("an unlimited policy grants"),
        ];
        (session, m, permits)
    }

    const PARENT: Identity = Identity::new(7, 1);
    const CHILD: Identity = Identity::new(7, 2);

    fn hold(sequence: u64) -> Hold {
        Hold {
            obligation: dcbor::bounded::Obligation::Release,
            work: WriteWork::new(1, 16),
            id: Identity::new(9, sequence),
            acquisition: Identity::new(9, 100),
        }
    }

    fn id(permit: &Permit) -> Identity {
        <Limits as Releasing>::permit_identity(permit)
    }

    /// `permit` as a checkpoint reports it, with its record stage.
    fn reported(
        permit: &Permit,
        record: Option<dcbor::bounded::RecordStage>,
    ) -> refinement::Reported {
        refinement::Reported {
            permit: id(permit),
            record,
        }
    }

    /// Items belong to the innermost open group, a closed child restoring
    /// its parent; each owner's groups are combined into one entry; a
    /// record block's stage is kept with its permit, an ordinary permit's
    /// none.
    #[test]
    fn nested_groups_attribute_each_item_to_its_innermost_owner() {
        use dcbor::bounded::RecordStage::Handle;
        let (_session, _m, [first, second, third]) = fixture();
        let custody = collect(|sink| {
            sink.begin(Some(PARENT));
            sink.bound(hold(1).acquisition);
            sink.held(hold(1));
            sink.begin(Some(CHILD));
            sink.permit(&first, Some(Handle));
            sink.end();
            sink.permit(&second, None);
            sink.end();
            sink.begin(Some(PARENT));
            sink.permit(&third, None);
            sink.end();
            PermitsObserved::Complete
        })
        .expect("a well-formed observation");
        assert_eq!(
            custody,
            [
                refinement::Custody {
                    owner: PARENT,
                    bound: vec![hold(1).acquisition],
                    held: vec![hold(1)],
                    permits: vec![reported(&second, None), reported(&third, None)],
                },
                refinement::Custody {
                    owner: CHILD,
                    bound: Vec::new(),
                    held: Vec::new(),
                    permits: vec![reported(&first, Some(Handle))],
                },
            ]
        );
    }

    /// An initialized owner holding nothing stays represented; a deferred
    /// one holding nothing contributes nothing, and may hold an initialized
    /// child group.
    #[test]
    fn empty_initialized_owners_stay_and_empty_deferred_ones_vanish() {
        let (_session, _m, [first, ..]) = fixture();
        let custody = collect(|sink| {
            sink.begin(Some(PARENT));
            sink.end();
            sink.begin(None);
            sink.end();
            sink.begin(None);
            sink.begin(Some(CHILD));
            sink.permit(&first, None);
            sink.end();
            sink.end();
            PermitsObserved::Complete
        })
        .expect("a well-formed observation");
        assert_eq!(
            custody,
            [
                refinement::Custody {
                    owner: PARENT,
                    bound: Vec::new(),
                    held: Vec::new(),
                    permits: Vec::new(),
                },
                refinement::Custody {
                    owner: CHILD,
                    bound: Vec::new(),
                    held: Vec::new(),
                    permits: vec![reported(&first, None)],
                },
            ]
        );
    }

    /// Custody no stored owner names is refused, a held obligation and a
    /// permit alike.
    #[test]
    fn a_deferred_group_holding_an_item_directly_is_refused() {
        let (_session, _m, [first, ..]) = fixture();
        let held = collect(|sink| {
            sink.begin(None);
            sink.held(hold(1));
            sink.end();
            PermitsObserved::Complete
        });
        assert_eq!(held, Err(Unobserved::Unowned));
        let permit = collect(|sink| {
            sink.begin(None);
            sink.permit(&first, None);
            sink.end();
            PermitsObserved::Complete
        });
        assert_eq!(permit, Err(Unobserved::Unowned));
    }

    /// Malformed grouping is no observation: an item outside every group,
    /// an end without its begin, a begin without its end.
    #[test]
    fn malformed_grouping_is_refused() {
        assert_eq!(
            collect(|sink| {
                sink.held(hold(1));
                PermitsObserved::Complete
            }),
            Err(Unobserved::OutsideGroup)
        );
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                sink.end();
                sink.end();
                PermitsObserved::Complete
            }),
            Err(Unobserved::UnmatchedEnd)
        );
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                PermitsObserved::Complete
            }),
            Err(Unobserved::UnclosedGroup)
        );
    }

    /// One identity reported twice, in one owner's groups or two, is
    /// refused, never combined.
    #[test]
    fn an_identity_reported_twice_is_refused() {
        let (_session, _m, [first, ..]) = fixture();
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                sink.held(hold(1));
                sink.end();
                sink.begin(Some(CHILD));
                sink.held(hold(1));
                sink.end();
                PermitsObserved::Complete
            }),
            Err(Unobserved::DuplicateHeld(hold(1).id))
        );
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                sink.permit(&first, None);
                sink.permit(&first, None);
                sink.end();
                PermitsObserved::Complete
            }),
            Err(Unobserved::DuplicatePermit(id(&first)))
        );
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                sink.bound(hold(1).acquisition);
                sink.end();
                sink.begin(Some(CHILD));
                sink.bound(hold(1).acquisition);
                sink.end();
                PermitsObserved::Complete
            }),
            Err(Unobserved::DuplicateBound(hold(1).acquisition))
        );
        assert_eq!(
            collect(|sink| {
                sink.begin(None);
                sink.bound(hold(1).acquisition);
                sink.end();
                PermitsObserved::Complete
            }),
            Err(Unobserved::Unowned),
            "a binding no stored owner names"
        );
    }

    /// Contention after groups were emitted refuses the whole capture.
    #[test]
    fn contention_after_partial_emission_refuses_the_capture() {
        let (_session, _m, [first, ..]) = fixture();
        assert_eq!(
            collect(|sink| {
                sink.begin(Some(PARENT));
                sink.permit(&first, None);
                sink.end();
                PermitsObserved::Contended
            }),
            Err(Unobserved::Contended)
        );
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
    /// A run records into the default capacity ([`CAPACITY`]); a fixture
    /// that outgrows it runs through its measured budget
    /// ([`crate::budgets::Budgets::encode_checked`]), never a capacity a
    /// schedule states.
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

    /// What witnesses a run's physical allocations: its policy, and the
    /// observation of the engine's physical requests around each step.
    /// Two witnesses, each defined once: the heap guard
    /// ([`heap::Observation`]), which matches every physical request to an
    /// admission, fails a selected one, and checks that nothing outside an
    /// engine step allocates; and [`Unwitnessed`], the admission oracle
    /// alone, for a run inside a model checker, whose runtime allocates on
    /// the observed thread among the engine's own requests, where no global
    /// observer can tell them apart. A run under it records its physical
    /// figures as absent, never as zero.
    pub trait Physical: Sized {
        /// The run's policy, recorded in `session`: the admission oracle's
        /// with what this witness adds to it ([`super::recorded_policy`]).
        fn policy(session: &Recording) -> Limits;
        /// The witness of a run failing physical request `fail_at`, unarmed.
        fn begin(fail_at: Option<usize>) -> Self;
        /// Begin measured requests and fault injection, retaining setup custody.
        fn measure(&self, fail_at: Option<usize>);
        /// `f` run with the engine's physical requests witnessed.
        fn window<R>(&self, f: impl FnOnce() -> R) -> R;
        /// Witness nothing until the next window.
        fn stop(&self);
        /// The physical requests witnessed so far.
        fn requests(&self) -> Option<usize>;
        /// The run's physical requests and denials, once it has drained:
        /// every request admitted, the record complete.
        fn finish(&self) -> (Option<usize>, Option<usize>);
    }

    /// The heap guard: the observed policy reports each admitted allocation
    /// ([`super::recorded_policy`]), and an armed observation matches each
    /// physical request against one.
    impl Physical for heap::Observation {
        fn policy(session: &Recording) -> Limits {
            super::recorded_policy(session, u64::MAX, true)
        }

        fn begin(fail_at: Option<usize>) -> Self {
            let observation = heap::Observation::begin(fail_at);
            observation.stop();
            observation
        }

        fn window<R>(&self, f: impl FnOnce() -> R) -> R {
            heap::Observation::window(self, f)
        }

        fn measure(&self, fail_at: Option<usize>) {
            heap::Observation::measure(self, fail_at);
        }

        fn stop(&self) {
            heap::Observation::stop(self);
        }

        fn requests(&self) -> Option<usize> {
            Some(self.snapshot().calls)
        }

        fn finish(&self) -> (Option<usize>, Option<usize>) {
            let stats = self.snapshot();
            assert_eq!(stats.unadmitted, 0, "physical allocation without admission");
            assert!(!stats.overflow, "heap observation incomplete");
            (Some(stats.calls), Some(stats.denied))
        }
    }

    /// The admission oracle alone ([`Physical`]): physical admission is
    /// checked natively and under Miri, where the heap guard's attribution
    /// holds; a run under this witness asserts every admission-level fact
    /// and records no physical figure.
    pub struct Unwitnessed;

    impl Physical for Unwitnessed {
        fn policy(session: &Recording) -> Limits {
            super::recorded_policy(session, u64::MAX, false)
        }

        fn begin(fail_at: Option<usize>) -> Self {
            assert_eq!(
                fail_at, None,
                "a physical failure is injected only where physical requests are witnessed"
            );
            Self
        }

        fn window<R>(&self, f: impl FnOnce() -> R) -> R {
            f()
        }

        fn measure(&self, fail_at: Option<usize>) {
            assert_eq!(
                fail_at, None,
                "an unwitnessed run cannot inject physical failure"
            );
        }

        fn stop(&self) {}

        fn requests(&self) -> Option<usize> {
            None
        }

        fn finish(&self) -> (Option<usize>, Option<usize>) {
            (None, None)
        }
    }

    /// One observed boundary, a possible stop: its phase, its turn in the
    /// phase, and the cleanup class of the state it reached, when one is
    /// certified ([`classes`]).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Boundary {
        pub phase: Phase,
        pub turn: usize,
        pub class: Option<Class>,
        /// Policy and physical cursors at the boundary, used to resolve
        /// replay indices to their phase and occurrence without
        /// interpreting Debug; the physical one absent where nothing
        /// physical is witnessed ([`Physical`]).
        pub attempts: usize,
        pub physical: Option<usize>,
    }

    struct Context<'r, P> {
        policy: PolicyId,
        heap: &'r P,
        boundaries: std::cell::RefCell<Vec<Boundary>>,
        /// The turn bound each phase was driven under, before its refusal
        /// allowance ([`Report::bounds`]).
        bounds: std::cell::RefCell<Vec<(Phase, usize)>>,
        stop: Option<(Phase, usize, Stop)>,
        /// The schedule's refusals, applied when the measured part of the
        /// run begins ([`Self::arm`]).
        refusal: Refusal,
        physical: Option<usize>,
        armed: std::cell::Cell<bool>,
        /// The admitted calls made before the selected stop: the stop's
        /// cleanup is every call after them.
        stopped_at: std::cell::Cell<Option<usize>>,
        /// Positions are read ([`Schedule::observed`]).
        observed: bool,
    }

    /// Classification and cancellation of an operation already held by the run.
    struct PhaseContract<C, X> {
        classify: C,
        cancel: X,
    }

    impl<P: Physical> Context<'_, P> {
        /// Record boundary `turn` of `phase`, the state there of cleanup
        /// class `class`, and what the consumer does there: unwinding
        /// happens here; retirement and cancellation are returned for the
        /// caller to perform.
        fn boundary(
            &self,
            m: &Limits,
            phase: Phase,
            turn: usize,
            class: Option<Class>,
        ) -> Option<Stop> {
            self.boundaries.borrow_mut().push(Boundary {
                phase,
                turn,
                class,
                attempts: m.attempts(),
                physical: self.heap.requests(),
            });
            match self.stop {
                Some((at, stop_turn, stop)) if at == phase && stop_turn == turn => {
                    self.stopped_at.set(Some(m.admitted_calls().len()));
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
        fn arm<T: Custodial<Permit>>(&self, holding: &mut Holding<'_, '_, T, P>) {
            assert!(!self.armed.replace(true), "a run is armed once");
            self.heap.measure(self.physical);
            holding.with_policy(self.policy, |_, m| refuse(m, self.refusal));
        }

        /// Schedule a held operation and consume its publication while held.
        /// The shared holding driver owns observation, unexpected outputs,
        /// publisher retirement and unwind containment.
        fn phase<O: Resumable<Limits> + Custodial<Permit> + Terminal, R>(
            &self,
            operation: &mut Holding<'_, '_, O, P>,
            phase: Phase,
            turns: usize,
            contract: PhaseContract<impl Fn(&O::Position) -> Option<Class>, impl FnOnce(&mut O)>,
            consume: impl FnOnce(&mut Holding<'_, '_, O::Output, P>) -> R,
        ) -> Result<R, Reached>
        where
            O::Error: Debug,
            O::Output: Custodial<Permit>,
        {
            let PhaseContract { classify, cancel } = contract;
            let mut cancel = Some(cancel);
            self.bounds.borrow_mut().push((phase, turns));
            operation.checkpoint();
            let mut cancelled = false;
            let result = operation.controlled(
                self.policy,
                turns,
                Retirement::Published,
                self.observed,
                |m, operation, at| {
                    let class = self
                        .observed
                        .then(|| classify(&operation.position()))
                        .flatten();
                    match self.boundary(m, phase, at, class) {
                        Some(stop) => {
                            if stop == Stop::Cancel {
                                cancelled = true;
                                cancel.take().expect("a phase cancels once")(operation);
                            }
                            true
                        }
                        _ => false,
                    }
                },
                consume,
            );
            let reached = match result {
                Ok(Some(output)) => return Ok(output),
                Ok(None) if !cancelled => return Err(Reached::Stopped),
                Ok(None) => Reached::Stopped,
                Err(Stopped::Operation(error))
                    if error.class() == dcbor::bounded::Class::Allocation =>
                {
                    Reached::Failed
                }
                Err(Stopped::Operation(error))
                    if error.class() == dcbor::bounded::Class::Invalid =>
                {
                    match phase {
                        Phase::Inspect | Phase::Decode => Reached::Invalid,
                        _ => Reached::Found(Finding::Defect(format!(
                            "{phase:?} rejected an already accepted value: {error:?}"
                        ))),
                    }
                }
                Err(stop) => return Err(Reached::Found(stop.into())),
            };
            let calls = self.heap.requests();
            if let Err(stop) = operation.cleanup(
                self.policy,
                turns,
                Retirement::Published,
                self.observed,
                |_| {},
            ) {
                if let Reached::Found(finding) = reached {
                    operation.run.defects.push(finding);
                }
                return Err(Reached::Found(stop.into()));
            }
            assert_eq!(self.heap.requests(), calls, "{phase:?} cleanup allocated");
            Err(reached)
        }
    }

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
        /// A driver stopped short of its goal ([`super::Stopped`]), detached
        /// as the run's finding, everything the phase held dropped.
        Found(Finding),
    }

    /// Acquire the input and enter its continuation without releasing custody.
    fn acquired<'s, P: Physical, R>(
        context: &Context<P>,
        owner: &mut Holding<'_, '_, DecodeOwner<'s, Limits>, P>,
        wire: &[u8],
        input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
        consume: impl FnOnce(&mut Holding<'_, '_, OwnedInitialized<'s, ByteString, Limits>, P>) -> R,
    ) -> Result<R, Reached> {
        context.arm(owner);
        if owner.with_policy(context.policy, |_, m| {
            context.boundary(m, Phase::Scope, 0, None).is_some()
        }) {
            return Err(Reached::Stopped);
        }
        match owner.initialize(context.policy) {
            Ok(()) => {}
            Err(Stopped::Operation(BoundedError::Allocation { .. })) => {
                return Err(Reached::Failed);
            }
            Err(stop) => return Err(Reached::Found(stop.into())),
        }
        let source = Copying(wire);
        let bound = source.turns();
        owner.acquiring(source, |acquisition| {
            context.phase(
                acquisition,
                Phase::Input,
                bound,
                PhaseContract {
                    classify: input,
                    cancel:
                        |operation: &mut dcbor::bounded::decode::construction::InputAcquisition<
                            '_,
                            's,
                            Limits,
                        >| operation.cancel(),
                },
                |input| {
                    assert_eq!(input.value().value().data(), wire, "the copy differs");
                    consume(input)
                },
            )
        })
    }

    /// Acquisition alone: the copied input is retired once published.
    fn acquisition<P: Physical>(
        context: &Context<P>,
        owner: &mut Holding<'_, '_, DecodeOwner<'_, Limits>, P>,
        wire: &[u8],
        classes: &Classes<()>,
    ) -> Reached {
        acquired(context, owner, wire, classes.input, |_| Reached::Complete)
            .unwrap_or_else(|reached| reached)
    }

    /// Acquisition, then the parsed document inspected in place without
    /// allocating, then retired.
    fn inspection<P: Physical>(
        context: &Context<P>,
        owner: &mut Holding<'_, '_, DecodeOwner<'_, Limits>, P>,
        wire: &[u8],
        classes: &Classes<()>,
    ) -> Reached {
        let bound = dcbor::bounded::decode::construction::parse_bound::<ByteString, Limits, ()>(
            wire.len() as u64,
            OPTIONS,
        )
        .expect("the parse bound of an input held in memory fits in u64");
        acquired(context, owner, wire, classes.input, |input| {
            let calls = context.heap.requests();
            input.transfer(
                |input| DocumentDecoder::parse(input, OPTIONS),
                Retirement::Stopped,
                |parsing| {
                    assert_eq!(
                        context.heap.requests(),
                        calls,
                        "parse constructor allocated"
                    );
                    context
                        .phase(
                            parsing,
                            Phase::Inspect,
                            super::turns(bound),
                            PhaseContract {
                                classify: classes.parse,
                                cancel: |operation: &mut DocumentDecoder<
                                    '_,
                                    ByteString,
                                    Limits,
                                >| { operation.cancel() },
                            },
                            |document| {
                                let calls = context.heap.requests();
                                context.heap.window(|| {
                                    let document = document.value();
                                    document.with_document(|view| {
                                        assert_eq!(view.root().encoded(), wire)
                                    });
                                    assert_eq!(document.root().encoded(), wire);
                                    assert_eq!(document.bytes(), wire);
                                });
                                assert_eq!(context.heap.requests(), calls, "inspection allocated");
                                Reached::Complete
                            },
                        )
                        .unwrap_or_else(|reached| reached)
                },
            )
        })
        .unwrap_or_else(|reached| reached)
    }

    /// Acquisition, typed decoding of `T`, owned preparation and emission,
    /// the emitted chunks appended to `output`.
    fn encoding<T, P: Physical>(
        context: &Context<P>,
        owner: &mut Holding<'_, '_, DecodeOwner<'_, Limits>, P>,
        wire: &[u8],
        output: &mut Vec<u8>,
        classes: &Classes<Typed<T>>,
        inspect: impl FnOnce(&T),
    ) -> Reached
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        let bound =
            dcbor::bounded::decode::construction::typed_decode_bound::<ByteString, T, Limits, ()>(
                wire.len() as u64,
                OPTIONS,
            )
            .expect("the typed decode bound of an input held in memory fits in u64");
        acquired(context, owner, wire, classes.input, |input| {
            let calls = context.heap.requests();
            input.transfer(
                |input| TypedDecoder::<_, T, Limits>::new(input, OPTIONS),
                Retirement::Stopped,
                |decoding| {
                    assert_eq!(context.heap.requests(), calls, "decode constructor allocated");
                    context.phase(
                        decoding,
                        Phase::Decode,
                        super::turns(bound),
                        PhaseContract {
                            classify: classes.decode,
                            cancel: |operation: &mut TypedDecoder<'_, ByteString, T, Limits>| {
                                operation.cancel()
                            },
                        },
                        |value| {
                            inspect(value.value().value());
                            let shape = super::shape(value.value().value());
                            let bound = dcbor::bounded::encoding::owned_prepare_bound::<
                                ByteString, T, Limits, (),
                            >(shape).expect("the preparation bound fits in u64");
                            let calls = context.heap.requests();
                            value.transfer(
                                OwnedPreparation::prepare,
                                Retirement::Stopped,
                                |preparing| {
                                    assert_eq!(context.heap.requests(), calls, "preparation constructor allocated");
                                    context.phase(
                                        preparing,
                                        Phase::Prepare,
                                        super::turns(bound),
                                        PhaseContract {
                                            classify: classes.prepare,
                                            cancel: |operation: &mut OwnedPreparation<'_, ByteString, T, Limits>| {
                                                operation.cancel()
                                            },
                                        },
                                        |plan| {
                                            assert_eq!(plan.value().len(), wire.len());
                                            plan.checkpoint();
                                            if plan.with_policy(context.policy, |_, m| {
                                                context.boundary(m, Phase::Plan, 0, None).is_some()
                                            }) {
                                                return Reached::Stopped;
                                            }
                                            let calls = context.heap.requests();
                                            plan.transfer(
                                                dcbor::bounded::encoding::OwnedPrepared::into_writer,
                                                Retirement::Published,
                                                |writer| {
                                                    assert_eq!(context.heap.requests(), calls, "writer constructor allocated");
                                                    // The emission's bound, as `emit_by` drives it.
                                                    context.bounds.borrow_mut().push((Phase::Emit, super::emit_turns(wire.len())));
                                                    match writer.emit(
                                                        context.policy,
                                                        output,
                                                        wire.len(),
                                                        |m, writer, turn| {
                                                            let class = context.observed
                                                                .then(|| (classes.emit)(&writer.position())).flatten();
                                                            context.boundary(m, Phase::Emit, turn, class).is_some()
                                                        },
                                                    ) {
                                                        Ok(true) => Reached::Complete,
                                                        Ok(false) => Reached::Stopped,
                                                        Err(stop) => Reached::Found(stop.into()),
                                                    }
                                                },
                                            )
                                        },
                                    ).unwrap_or_else(|reached| reached)
                                },
                            )
                        },
                    ).unwrap_or_else(|reached| reached)
                },
            )
        }).unwrap_or_else(|reached| reached)
    }

    /// A custom input installed through the public resource-binding
    /// interface ([`instrumented`]), then decoded as `T` under `options`,
    /// its boundaries classed by `classes`; the published value, whose
    /// address moving its handle never changes, is given to `inspect` and
    /// retired. The scope and the input are setup the pipeline does not put
    /// under test: they run before the measured part begins, and the
    /// schedule's refusals and failures reach the decode alone. Neither
    /// publication nor retirement releases the input.
    fn decoding<T: Transferable<Limits> + 'static, P: Physical>(
        context: &Context<P>,
        owner: &mut Holding<'_, '_, DecodeOwner<'static, Limits>, P>,
        wire: &[u8],
        options: Options,
        classes: &Classes<Typed<T>>,
        released: &Arc<AtomicUsize>,
        inspect: impl FnOnce(&T),
    ) -> Reached {
        if let Err(stop) = owner.initialize(context.policy) {
            return Reached::Found(stop.into());
        }
        let input = owner.with_policy(context.policy, |owner, m| {
            instrumented(owner, m, wire, released)
        });
        let bound = dcbor::bounded::decode::construction::typed_decode_bound::<
            Instrumented,
            T,
            Limits,
            (),
        >(wire.len() as u64, options)
        .expect("the typed decode bound of an input held in memory fits in u64");
        let (reached, before_retirement) = owner.holding(input, Retirement::Published, |input| {
            input.with_policy(context.policy, |_, m| m.measure());
            context.arm(input);
            let calls = context.heap.requests();
            input.transfer(
                |input| TypedDecoder::<_, T, Limits>::new(input, options),
                Retirement::Stopped,
                |decoding| {
                    assert_eq!(
                        context.heap.requests(),
                        calls,
                        "decode constructor allocated"
                    );
                    let reached = context
                        .phase(
                            decoding,
                            Phase::Decode,
                            super::turns(bound),
                            PhaseContract {
                                classify: classes.decode,
                                cancel: |operation: &mut TypedDecoder<
                                    '_,
                                    Instrumented,
                                    T,
                                    Limits,
                                >| { operation.cancel() },
                            },
                            |value| {
                                assert_eq!(
                                    released.load(Ordering::SeqCst),
                                    0,
                                    "publication released the input"
                                );
                                let address = std::ptr::from_ref(value.value().value());
                                value.checkpoint();
                                value.transfer(
                                    core::convert::identity,
                                    Retirement::Published,
                                    |value| {
                                        value.checkpoint();
                                        assert_eq!(
                                            std::ptr::from_ref(value.value().value()),
                                            address,
                                            "moving the handle moved the value"
                                        );
                                        inspect(value.value().value());
                                    },
                                );
                                Reached::Complete
                            },
                        )
                        .unwrap_or_else(|reached| reached);
                    // A stopped, rejected or failed decode's own cleanup has
                    // reclaimed the input it consumed in place
                    // ([`Context::phase`]); a published one's value is
                    // retired to the queue. What the decoder's retirement and
                    // every retirement after it release is compared against
                    // this count.
                    (reached, released.load(Ordering::SeqCst))
                },
            )
        });
        assert_eq!(
            released.load(Ordering::SeqCst),
            before_retirement,
            "retirement ran input destruction"
        );
        reached
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
        /// The physical requests and denials the run's witness saw, absent
        /// where nothing physical is witnessed ([`Physical`]).
        pub physical: Option<usize>,
        pub denied: Option<usize>,
        /// Every observed boundary, in order: each is a possible stop.
        pub boundaries: Vec<Boundary>,
        /// The turn bound each phase the run entered was driven under, in
        /// order, before its refusal allowance ([`allowed`]): the bound its
        /// own driver enforces, a phase past it the run's stop. A phase's
        /// turns taken are its [`Self::boundaries`], one before each turn.
        pub bounds: Vec<(Phase, usize)>,
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
        /// Every boundary predicate valuation the run reached, its drain
        /// included, as its policy recorded them through the seam
        /// (`bounded::boundary`).
        pub reached: Valuations,
        /// The run's recording session, finished once the scope is drained
        /// and its owner and policy are gone, and refined: every observation
        /// of every family in its one order, drops and terminal settlements
        /// included, the stream the refinement machine accepted.
        pub observed: Vec<Observed>,
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
            let witnessed = |boundary: &Boundary| {
                boundary
                    .physical
                    .expect("a physical request is named only in a run that witnesses them")
            };
            let boundary = self
                .boundaries
                .iter()
                .rev()
                .find(|boundary| witnessed(boundary) <= index)
                .expect("a measured physical request has a pipeline boundary");
            let first = self
                .boundaries
                .iter()
                .find(|candidate| candidate.phase == boundary.phase)
                .expect("the phase has an initial boundary");
            format!(
                "{:?} physical request {}, turn {}, class {:?} (replay {index})",
                boundary.phase,
                index - witnessed(first),
                boundary.turn,
                boundary.class
            )
        }
    }

    /// Run `body` in one scope under observation, recorded into `capacity`,
    /// injecting what `schedule` names, then drain the scope: draining
    /// allocates nothing and recovers every reservation, every admission fits
    /// one quantum, and, where `P` witnesses physical requests, none was
    /// unadmitted.
    fn observe<P: Physical>(
        wire: &[u8],
        schedule: &Schedule,
        capacity: Capacity,
        body: impl FnOnce(
            &Context<P>,
            &mut Holding<'_, '_, DecodeOwner<'static, Limits>, P>,
            &mut Vec<u8>,
        ) -> Reached,
    ) -> Report {
        let stop = schedule.stop;
        let (mut report, observed) =
            recorded_evidence(capacity, ExpectedVerdict::Accepted, |run| {
                let policy = run.witnessed_policy::<P>();
                let heap = P::begin(None);
                let context = Context {
                    policy,
                    heap: &heap,
                    boundaries: std::cell::RefCell::new(Vec::new()),
                    bounds: std::cell::RefCell::new(Vec::new()),
                    stop,
                    refusal: schedule.refusal,
                    physical: schedule.physical,
                    armed: std::cell::Cell::new(false),
                    stopped_at: std::cell::Cell::new(None),
                    observed: schedule.observed,
                };
                let mut output = Vec::with_capacity(wire.len());
                let (reached, drain_attempt, accounting, metrics) = run.holding(
                    DecodeOwner::<'static, Limits>::new(),
                    Retirement::Scope,
                    &heap,
                    |owner| {
                        owner.checkpoint();
                        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            body(&context, owner, &mut output)
                        }));
                        let reached = match outcome {
                            Ok(reached) => reached,
                            Err(payload)
                                if matches!(stop, Some((_, _, Stop::Unwind)))
                                    && payload.is::<ConsumerUnwind>() =>
                            {
                                assert!(
                                    context.stopped_at.get().is_some(),
                                    "unwind boundary was not reached"
                                );
                                Reached::Stopped
                            }
                            Err(payload) => {
                                return Err(Finding::Defect(panic_report(payload.as_ref())));
                            }
                        };
                        if let Reached::Found(finding) = reached {
                            return Err(finding);
                        }
                        owner.with_policy(policy, |_, m| {
                            require_evidence::<(), BoundedError<LimitRefusal>, Rendered>(
                                m,
                                context.boundaries.borrow().len(),
                            )
                            .map_err(Finding::from)
                        })?;
                        let calls = heap.requests();
                        let drain_attempt = owner.with_policy(policy, |_, m| m.attempts());
                        owner.checkpoint();
                        owner.drain(policy)?;
                        assert_eq!(heap.requests(), calls, "drain allocated");
                        let (accounting, metrics) = owner.with_policy(policy, |_, m| {
                            assert_eq!(m.live_bytes(), 0);
                            (
                                RefusalRun::of(m),
                                (
                                    m.attempts(),
                                    m.refusals(),
                                    m.injected_refusals(),
                                    m.reached(),
                                ),
                            )
                        });
                        Ok((reached, drain_attempt, accounting, metrics))
                    },
                )?;
                let (physical, denied) = heap.finish();
                let complete = matches!(reached, Reached::Complete);
                let cleanup = context
                    .stopped_at
                    .get()
                    .map_or_else(Vec::new, |at| accounting.admitted()[at..].to_vec());
                let (attempts, refusals, refused, valuations) = metrics;
                Ok(Report {
                    accounting,
                    attempts,
                    refusals,
                    refused,
                    physical,
                    denied,
                    boundaries: context.boundaries.into_inner(),
                    bounds: context.bounds.into_inner(),
                    cleanup,
                    complete,
                    invalid: matches!(reached, Reached::Invalid),
                    stopped: matches!(reached, Reached::Stopped),
                    failed: matches!(reached, Reached::Failed),
                    drain_attempt,
                    reached: valuations,
                    observed: Vec::new(),
                })
            });
        report.observed = observed;
        report
    }

    /// The pipeline's runs under the physical witness `P` ([`Physical`]).
    /// The module's free functions are these under the heap guard.
    pub struct Under<P>(core::marker::PhantomData<P>);

    impl<P: Physical> Under<P> {
        /// Copy `wire`, which may be any bytes, into a scope, observed
        /// (`observe`), its boundaries classed by `classes`; complete once
        /// the published copy equals it.
        pub fn acquire(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
            observe::<P>(wire, schedule, CAPACITY, |context, owner, _| {
                acquisition(context, owner, wire, classes)
            })
        }

        /// Copy `wire` and parse it to a document inspected in place,
        /// observed (`observe`), its boundaries classed by `classes`;
        /// complete once the document's root is the input.
        pub fn inspect(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
            observe::<P>(wire, schedule, CAPACITY, |context, owner, _| {
                inspection(context, owner, wire, classes)
            })
        }

        /// Copy `wire`, decode it as `T`, prepare the value's encoding owned
        /// and emit it, observed (`observe`), its boundaries classed by
        /// `classes`; complete once the emitted bytes are the input, as
        /// every canonical input's are.
        pub fn encode<T>(wire: &[u8], schedule: &Schedule, classes: &Classes<Typed<T>>) -> Report
        where
            T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
        {
            Self::encode_checked::<T>(wire, schedule, classes, |_| ())
        }

        /// The owned encoding pipeline with a semantic oracle over its held
        /// decoded value, before transfer into preparation.
        pub fn encode_checked<T>(
            wire: &[u8],
            schedule: &Schedule,
            classes: &Classes<Typed<T>>,
            inspect: impl FnOnce(&T),
        ) -> Report
        where
            T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
        {
            Self::encode_checked_in::<T>(wire, schedule, classes, CAPACITY, inspect)
        }

        /// [`Self::encode_checked`] recorded into `capacity`: the budget
        /// authority's alone ([`crate::budgets::Budgets::encode_checked`]).
        pub(crate) fn encode_checked_in<T>(
            wire: &[u8],
            schedule: &Schedule,
            classes: &Classes<Typed<T>>,
            capacity: Capacity,
            inspect: impl FnOnce(&T),
        ) -> Report
        where
            T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
        {
            observe::<P>(wire, schedule, capacity, |context, owner, output| {
                let reached = encoding::<T, P>(context, owner, wire, output, classes, inspect);
                if matches!(reached, Reached::Complete) {
                    assert_eq!(output.as_slice(), wire, "emission diverged from the input");
                }
                reached
            })
        }

        /// Decode `wire`, which may be any bytes, as `T` under `options` from
        /// a custom input (`decoding`), observed (`observe`), its
        /// boundaries classed by `classes`, a published value given to
        /// `inspect`. The drain releases the input exactly once.
        pub fn decode<T: Transferable<Limits> + 'static>(
            wire: &[u8],
            options: Options,
            schedule: &Schedule,
            classes: &Classes<Typed<T>>,
            inspect: impl FnOnce(&T),
        ) -> Report {
            let released = Arc::new(AtomicUsize::new(0));
            let report = observe::<P>(wire, schedule, CAPACITY, |context, owner, _| {
                decoding::<T, P>(context, owner, wire, options, classes, &released, inspect)
            });
            assert_eq!(
                released.load(Ordering::SeqCst),
                1,
                "the drain did not release the input exactly once"
            );
            report
        }
    }

    /// `wire`, a canonical encoding, round-tripped through the owned encoding
    /// pipeline unobstructed ([`Under::encode_checked`], admission oracle
    /// alone), its decoded value read by `check`, recorded into the default
    /// capacity: the run's report, complete, or the run fails.
    pub fn round_trip<T>(wire: &[u8], check: impl FnOnce(&T)) -> Report
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        round_trip_in(wire, CAPACITY, check)
    }

    /// [`round_trip`] recorded into `capacity`: the budget authority's alone
    /// ([`crate::budgets::Budgets::encode_checked`]).
    pub(crate) fn round_trip_in<T>(
        wire: &[u8],
        capacity: Capacity,
        check: impl FnOnce(&T),
    ) -> Report
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        let report = Under::<Unwitnessed>::encode_checked_in::<T>(
            wire,
            &Schedule::BASELINE,
            &Classes::none(),
            capacity,
            check,
        );
        assert!(report.complete, "the canonical round trip did not complete");
        report
    }

    /// [`Under::acquire`] under the heap guard.
    pub fn acquire(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
        Under::<heap::Observation>::acquire(wire, schedule, classes)
    }

    /// [`Under::inspect`] under the heap guard.
    pub fn inspect(wire: &[u8], schedule: &Schedule, classes: &Classes<()>) -> Report {
        Under::<heap::Observation>::inspect(wire, schedule, classes)
    }

    /// [`Under::encode`] under the heap guard.
    pub fn encode<T>(wire: &[u8], schedule: &Schedule, classes: &Classes<Typed<T>>) -> Report
    where
        T: Transferable<Limits> + dcbor::bounded::encoding::TransferableSchema + 'static,
    {
        Under::<heap::Observation>::encode::<T>(wire, schedule, classes)
    }

    /// [`Under::decode`] under the heap guard.
    pub fn decode<T: Transferable<Limits> + 'static>(
        wire: &[u8],
        options: Options,
        schedule: &Schedule,
        classes: &Classes<Typed<T>>,
        inspect: impl FnOnce(&T),
    ) -> Report {
        Under::<heap::Observation>::decode::<T>(wire, options, schedule, classes, inspect)
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
        assert_eq!(
            unobserved.reached, observed.reached,
            "{at}: observing positions changed the boundary valuations reached"
        );
        assert_eq!(
            unobserved.observed, observed.observed,
            "{at}: observing positions changed the recorded observations"
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
    /// - observation without effect (`unaffected`): a schedule run again
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
        let requests = baseline
            .physical
            .expect("the fault matrix runs where physical requests are witnessed");
        progress.dimension("physical requests", requests);
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
        // The boundary valuations reached by the runs the fast layer makes,
        // and by every run the matrix makes: under the exhaustive layer they
        // must be equal, the evidence that one stop per certified class
        // passes every boundary predicate edge its class's members pass.
        let fast_reached = std::cell::Cell::new(baseline.reached);
        let every_reached = std::cell::Cell::new(baseline.reached);
        let fast = |report: &Report| {
            fast_reached.set(fast_reached.get().union(report.reached));
            every_reached.set(every_reached.get().union(report.reached));
        };
        let every = |report: &Report| every_reached.set(every_reached.get().union(report.reached));
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
        fast(&refused);
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
                every(&resumed);
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
        super::physical_stage(&mut progress, requests, |index| {
            let at = baseline.physical_name(index);
            eprintln!("[{name}] {at}");
            let schedule = Schedule {
                physical: Some(index),
                ..Schedule::BASELINE
            };
            let failed = run(&schedule);
            // Every physical request is failed in both layers.
            fast(&failed);
            assert_eq!(failed.denied, Some(1), "{at}: failure unobserved");
            assert!(failed.failed, "{at}: failure misclassified");
            assert!(!failed.complete, "{at}: published after failure");
            if exhaustive {
                unaffected(&run, &schedule, &failed, &at);
            }
        });
        // The fast layer's stops: the first boundary of each certified class
        // and every unclassified one. The exhaustive layer stops at every
        // boundary, each marked whether the fast layer would.
        let mut first = std::collections::BTreeSet::new();
        let in_fast: Vec<bool> = baseline
            .boundaries
            .iter()
            .map(|boundary| match &boundary.class {
                None => true,
                Some(class) => first.insert(class.clone()),
            })
            .collect();
        let selected: Vec<(&Boundary, bool)> = baseline
            .boundaries
            .iter()
            .zip(in_fast)
            .filter(|&(_, in_fast)| in_fast || rigor == Rigor::Exhaustive)
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
        for (boundary, in_fast) in selected {
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
                if in_fast {
                    fast(&stopped);
                } else {
                    every(&stopped);
                }
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
        if exhaustive {
            fast_reaches_every(name, fast_reached.get(), every_reached.get());
        }
        // What the fast layer reaches is what every layer, Miri's included,
        // runs: the gate compares it across witness sizes and runners.
        crate::rigor::reached(name, fast_reached.get());
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
    mod reach_tests {
        use super::*;
        use dcbor::bounded::boundary::{Boundary, Predicate, Valuation};

        fn reached(boundaries: &[Boundary]) -> Valuations {
            let mut reached = Valuations::new();
            for &boundary in boundaries {
                reached.insert(boundary);
            }
            reached
        }

        const PAST: Boundary = Boundary {
            predicate: Predicate::ArenaLength,
            valuation: Valuation::Past,
        };
        const TOMBSTONE: Boundary = Boundary {
            predicate: Predicate::Buckets,
            valuation: Valuation::Tombstone,
        };

        /// The comparator's pass scenario: a fast layer reaching everything
        /// the exhaustive one does, and more, passes.
        #[test]
        fn a_fast_layer_reaching_every_valuation_passes() {
            fast_reaches_every("control", reached(&[PAST, TOMBSTONE]), reached(&[PAST]));
        }

        /// The comparator's planted defect: a valuation only the exhaustive
        /// layer reached is named.
        #[test]
        #[should_panic(expected = "buckets\\ttombstone")]
        fn a_valuation_only_the_exhaustive_layer_reached_is_named() {
            fast_reaches_every("planted", reached(&[PAST]), reached(&[PAST, TOMBSTONE]));
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
            observe::<heap::Observation>(
                &[],
                &Schedule {
                    stop: Some((Phase::Scope, 0, Stop::Unwind)),
                    ..Schedule::BASELINE
                },
                CAPACITY,
                |_, _, _| panic!("unexpected production panic"),
            );
        }
    }
}
