//! The suite's policy, its fixture runner, and its preparation drivers. The
//! preparation and physical matrices are the support crate's single-operation
//! matrices ([`super::support::refusal_matrix`],
//! [`super::support::physical_matrix`]) over a preparation run; they are
//! compiled exactly where a registered group calls them: the map and schema
//! groups, under `derive`, `hashbrown` or the standard library's collections.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use super::heap::Observation;
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use super::support::{Fault, Stopped, physical_matrix, refusal_matrix, rigor::rigor};
use super::support::{Finding, Retirement, Worked};
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use super::support::{prepare_turns, shape};
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use dcbor::bounded::boundary::{Boundary, Predicate, Reached, Valuation};
use dcbor::bounded::encoding::Prepared;
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use dcbor::bounded::encoding::{Instruction, Preparation, Schema};
use dcbor::bounded::text_cursor::pipeline::PreparedText;
use dcbor::bounded::{BoundedError, Custodial};
pub use dcbor::bounded::{Budget, Call, LimitRefusal, Limits, Reservation, TURN};
#[cfg(any(feature = "derive", feature = "hashbrown"))]
use dcbor::bounded::{Class, Failure};

pub use super::support::{
    decode_turns, emit_turns, normalize_turns, string_turns, text_emit_turns, typed_turns,
};

/// The resumable suite's live-storage pool: 32 MiB, each policy's capacity
/// in a recorded run ([`suite`], and fixtures making several policies of
/// one run through [`super::support::recorded_run`]).
pub const POOL: u64 = 32 * 1024 * 1024;

#[cfg(feature = "hashbrown")]
pub type Enumeration = (
    dcbor::bounded::encoding::buckets::BucketPosition,
    Option<dcbor::bounded::Retained<dcbor::bounded::Family>>,
    Option<dcbor::bounded::Acquisition<dcbor::bounded::Family>>,
);

/// The cursor's window and acquisition stay with their immutable owner
/// through refusal, completion and observed retirement.
#[cfg(feature = "hashbrown")]
pub struct EnumerationCustody {
    pub enumeration: Enumeration,
    pub owner: dcbor::bounded::Owner,
}

#[cfg(feature = "hashbrown")]
impl dcbor::bounded::Custodial<Reservation> for EnumerationCustody {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        sink.begin(Some(self.owner.id()));
        let (position, window, acquisition) = &mut self.enumeration;
        dcbor::bounded::encoding::buckets::BucketCursor::new(position, window, acquisition)
            .observe_window(sink);
        sink.end();
        dcbor::bounded::PermitsObserved::Complete
    }
}

#[cfg(feature = "hashbrown")]
impl Drop for EnumerationCustody {
    fn drop(&mut self) {
        let (position, window, acquisition) = &mut self.enumeration;
        dcbor::bounded::encoding::buckets::BucketCursor::new(position, window, acquisition).end(
            dcbor::bounded::Performer::None,
            dcbor::bounded::Forfeit::Cancelled,
        );
    }
}

/// An arena component held independently of a production continuation.
/// Its production traversal remains the only enumeration of its custody.
pub struct ArenaCustody<T>(
    pub dcbor::bounded::decode::storage::Storage<T, Reservation, dcbor::bounded::Family>,
);

impl<T> dcbor::bounded::Custodial<Reservation> for ArenaCustody<T> {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        self.0.observe_custody(sink)
    }
}

/// A settled allocation detached from its arena, retaining its acquisition owner.
pub struct PublishedArena<T> {
    pub storage: dcbor::bounded::Owned<T, Reservation>,
    pub owner: Option<dcbor::bounded::Identity>,
}

impl<T> dcbor::bounded::Custodial<Reservation> for PublishedArena<T> {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        sink.begin(self.owner);
        if let Some(permit) = self.storage.permit() {
            sink.permit(permit, None);
        }
        sink.end();
        dcbor::bounded::PermitsObserved::Complete
    }
}

/// Hold an empty arena before setup or assertions can unwind. The consumer
/// borrows its storage; the run observes and retires it on every exit.
pub fn arena_case<T, R>(
    body: impl FnOnce(
        &mut dcbor::bounded::decode::storage::Storage<T, Reservation, dcbor::bounded::Family>,
        &mut Limits,
    ) -> Result<R, Finding>,
) -> R {
    use super::support::{Retirement, pipeline::Unwitnessed};
    suite(|run, policy| {
        let result = run.holding(
            ArenaCustody(dcbor::bounded::decode::storage::Storage::new()),
            Retirement::Released,
            &Unwitnessed,
            |arena| arena.with_policy(policy, |arena, m| body(&mut arena.0, m)),
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(result)
    })
}

/// Custody returned by the synchronous APIs: documents and encodings own
/// ordinary buffers; `decode_typed` returns the last handle of its private
/// scope, whose terminal drain reclaims its records.
pub trait SynchronousOutput: Custodial<Reservation> {
    const RETIREMENT: Retirement;
}

impl SynchronousOutput for dcbor::bounded::decode::Document<'_, Reservation> {
    const RETIREMENT: Retirement = Retirement::Released;
}

impl SynchronousOutput for dcbor::bounded::Encoded<Reservation> {
    const RETIREMENT: Retirement = Retirement::Released;
}

impl<T: dcbor::bounded::decode::construction::in_place::Transferable<Limits> + 'static>
    SynchronousOutput
    for dcbor::bounded::decode::construction::TypedValue<'static, dcbor::ByteString, T, Limits>
{
    const RETIREMENT: Retirement = Retirement::LastReference;
}

/// A synchronous publication enters a holding before its consumer runs.
/// Unexpected success follows the same retirement path as expected success.
pub fn synchronous_case<T, E, R>(
    produce: impl FnOnce(&mut Limits) -> Result<T, E>,
    inspect: impl FnOnce(Result<&mut T, E>, &mut Limits) -> R,
) -> R
where
    T: SynchronousOutput,
{
    use super::support::pipeline::Unwitnessed;

    suite(|run, policy| {
        let outcome = run.with_policy(policy, produce);
        let result = match outcome {
            Ok(value) => run.holding(value, T::RETIREMENT, &Unwitnessed, |value| {
                value.with_policy(policy, |value, m| inspect(Ok(value), m))
            }),
            Err(error) => run.with_policy(policy, |m| inspect(Err(error), m)),
        };
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(result)
    })
}

/// Run one retained operation's refusal schedule with custody held through
/// publication or cancellation, the publisher retired as its type declares
/// ([`super::support::Terminal`]). The fixture checks the published value;
/// the run retires both holders before inspecting final storage accounting.
pub fn retained_case<O>(
    operation: O,
    turns: usize,
    fault: super::support::Fault,
    check: impl FnOnce(&mut O::Output, &Limits),
) -> super::support::RefusalRun
where
    O: dcbor::bounded::Resumable<Limits>
        + dcbor::bounded::Custodial<Reservation>
        + super::support::Terminal,
    O::Output: dcbor::bounded::Custodial<Reservation>,
    O::Error: std::fmt::Debug,
{
    use super::support::pipeline::Unwitnessed;

    super::support::recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        run.holding(operation, Retirement::Released, &Unwitnessed, |operation| {
            operation.drive_faulted(
                policy,
                turns,
                Retirement::Released,
                fault,
                |_, _| {},
                |output| {
                    output.with_policy(policy, |output, m| {
                        check(output, m);
                        m.assert_units(TURN);
                    });
                },
            )?;
            Ok::<_, Finding>(())
        })?;
        Ok(run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            super::support::RefusalRun::of(m)
        }))
    })
}

/// The one rejection scenario of a decode: `operation` held by its run;
/// `before` brings it to the boundary under test (nothing, a scripted
/// prefix, a suspension), under the run's policy; then it is driven to its
/// terminal rejection as invalid input ([`Holding::drive`]), a publication
/// or any other end the run's finding; then its own cleanup is stepped to
/// its end ([`Holding::finish`]) under a share of the same policy, its own
/// trace over the policy's storage; and afterwards the run holds nothing.
/// Returns the policy's boundary valuations.
///
/// [`Holding::drive`]: super::support::Holding::drive
/// [`Holding::finish`]: super::support::Holding::finish
pub fn rejected_case<O>(
    operation: O,
    turns: usize,
    before: impl FnOnce(
        &mut super::support::Holding<'_, '_, O, super::support::pipeline::Unwitnessed>,
        super::support::PolicyId,
    ) -> Result<(), Finding>,
) -> dcbor::bounded::boundary::Reached
where
    O: dcbor::bounded::Resumable<Limits, Error = dcbor::bounded::decode::DecodeError<LimitRefusal>>
        + dcbor::bounded::Custodial<Reservation>
        + super::support::Terminal,
    O::Output: dcbor::bounded::Custodial<Reservation>,
{
    use super::support::{Retirement, Stopped, pipeline::Unwitnessed};

    suite(|run, policy| {
        let cleanup = run.shared_policy(policy);
        run.holding(operation, Retirement::Released, &Unwitnessed, |operation| {
            before(operation, policy)?;
            match operation.drive(policy, turns, Retirement::Released, |_| ()) {
                Err(Stopped::Operation(dcbor::bounded::decode::DecodeError::Invalid(_))) => {}
                Err(stop) => return Err(Finding::from(stop)),
                Ok(()) => {
                    return Err(Finding::Defect("an invalid input was published".to_owned()));
                }
            }
            operation.with_policy(policy, |_, m| m.assert_units(TURN));
            operation.finish(cleanup, turns, Retirement::Released)?;
            Ok(())
        })?;
        Ok(run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            m.reached()
        }))
    })
}

/// One recorded run of the suite ([`super::support::recorded_run`]): its
/// policy a 32 MiB pool, every call recorded and strict, admitted
/// allocations reported to the heap observer. `body` receives the run and
/// that policy and holds every custody it makes in the run's holdings
/// ([`super::support::RecordedRun::holding`]), which retire it before the
/// run finalizes; it returns only detached data: its result, or the finding
/// that stopped it ([`Finding`]).
pub fn suite<R>(
    body: impl FnOnce(&mut super::support::RecordedRun, super::support::PolicyId) -> Result<R, Finding>,
) -> R {
    suite_with(POOL, body)
}

/// [`suite`] over a policy of `capacity` live bytes, recorded into the
/// default capacity ([`super::support::CAPACITY`]).
pub fn suite_with<R>(
    capacity: u64,
    body: impl FnOnce(&mut super::support::RecordedRun, super::support::PolicyId) -> Result<R, Finding>,
) -> R {
    super::support::recorded_run(pooled(capacity, body))
}

/// [`suite_with`] as fixture `key` of the budget family `budgets`: recorded
/// into the capacity its record states, and measured
/// ([`super::support::budgets::Budgets::run`]).
pub fn budget_suite<R>(
    budgets: &mut super::support::budgets::Budgets,
    key: &str,
    capacity: u64,
    body: impl FnOnce(&mut super::support::RecordedRun, super::support::PolicyId) -> Result<R, Finding>,
) -> R {
    budgets.run(key, pooled(capacity, body))
}

/// The body of a suite's recorded run: its policy of `capacity` live bytes
/// made first, the admission oracle's with the heap observer's feed
/// (`observed_policy`), a no-op unless an observation is armed, so one entry
/// serves physical witnesses and admission-only fixtures alike; then `body`.
fn pooled<R>(
    capacity: u64,
    body: impl FnOnce(&mut super::support::RecordedRun, super::support::PolicyId) -> Result<R, Finding>,
) -> impl FnOnce(&mut super::support::RecordedRun) -> Result<R, Finding> {
    move |run| {
        let policy = run.observed_policy(capacity);
        body(run, policy)
    }
}

/// The budget family `family` of the fixtures `keys` under this build's
/// representation ([`variant`]) and this run's selection.
pub fn budgets(family: &str, keys: &[&str]) -> super::support::budgets::Budgets {
    super::support::budgets::Budgets::new(
        family,
        variant!(),
        keys.iter().map(|key| (*key).to_owned()).collect(),
    )
}

/// Another tenant of a pool: four elements of `K` bytes, which the growth
/// rule reserves in one acquisition from empty (`grown_capacity`, four from
/// empty), so its one permit holds exactly `4 * K` bytes and no replaced
/// allocation is held beside it.
pub struct Tenant<const K: usize> {
    storage: dcbor::bounded::Owned<[u8; K], Reservation>,
    owner: dcbor::bounded::Identity,
}

impl<const K: usize> dcbor::bounded::Custodial<Reservation> for Tenant<K> {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        sink.begin(Some(self.owner));
        if let Some(permit) = self.storage.permit() {
            sink.permit(permit, None);
        }
        sink.end();
        dcbor::bounded::PermitsObserved::Complete
    }
}

/// `4 * K` bytes of `m`'s pool taken by one acquisition of `owner` through
/// the production protocol (`Owned::reserve`: the acquisition bound, its
/// release admitted held and spent at the grant, its effect published), never
/// by a direct grant, which a recorded run refuses.
pub fn occupy<const K: usize>(m: &mut Limits, owner: &dcbor::bounded::Owner) -> Tenant<K> {
    let mut tenant = dcbor::bounded::Owned::<[u8; K], Reservation>::new();
    tenant
        .reserve(4, m, owner)
        .expect("the pool grants the tenant's capacity");
    Tenant {
        storage: tenant,
        owner: owner.id(),
    }
}

/// `m`'s pool is full: one byte more is refused for storage, through the
/// same protocol.
pub fn refuses_more(m: &mut Limits, owner: &dcbor::bounded::Owner) {
    let mut beyond = dcbor::bounded::Owned::<u8, Reservation>::new();
    assert_eq!(
        beyond.reserve(1, m, owner),
        Err(dcbor::bounded::BoundedError::Refused(LimitRefusal::Storage)),
        "a full pool granted more"
    );
}

/// Run every one of `count` fixtures or stress repetitions, never a
/// selection of them, even while some fail: catching an assertion does not
/// pass the test, and all failures are returned together, so the first
/// failing fixture cannot hide later ones. A fixture fails by its assertion
/// or by the finding it returns ([`Finding`]); each failure is named by its
/// fixture's index. A lost recording is no fixture's failure: every later
/// fixture would run against a session that is no evidence, so it ends the
/// loop at once, kept as it is beside every failure found before it. Fault
/// schedules are not fixtures: they run through the support crate's
/// matrices.
pub fn every_fixture(
    count: usize,
    mut case: impl FnMut(usize) -> Result<(), Finding>,
) -> Result<(), Vec<Finding>> {
    assert!(count > 0, "no fixture");
    let mut findings = Vec::new();
    for index in 0..count {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| case(index))) {
            Ok(Ok(())) => {}
            Ok(Err(lost @ Finding::Lost { .. })) => {
                findings.push(lost);
                break;
            }
            Ok(Err(finding)) => {
                findings.push(Finding::Defect(format!("fixture {index}: {finding}")));
            }
            Err(panic) => findings.push(Finding::Defect(format!(
                "fixture {index}: {}",
                super::support::panic_report(panic.as_ref())
            ))),
        }
    }
    if findings.is_empty() {
        Ok(())
    } else {
        Err(findings)
    }
}

/// The one concurrent string-decode scenario: `cases` dealt in turn to
/// `workers` workers of a pool of four `K`-byte elements, each worker under
/// a share of the pool ([`super::support::RecordedRun::workers`]), each case
/// under a share of its worker's, its refused call (`Some`) refused for work
/// and resumed; every decode of `wire` publishes `expected`, then `check`
/// reads the case's policy. Every worker keeps each decoder, each published
/// string and each stop's publications in the custody it returns through its
/// join, retired by the parent once every worker has joined; a worker stops
/// at its first finding, a lost recording before any further case. Then the
/// whole capacity is free again, and no more than it.
pub fn concurrent_string_decodes<const K: usize>(
    run: &mut super::support::RecordedRun,
    workers: usize,
    wire: &[u8],
    cases: &[Option<usize>],
    expected: &str,
    check: impl Fn(&Limits, Option<usize>) + Sync,
) -> Result<(), Finding> {
    use super::support::{Retirement, pipeline::Unwitnessed};
    let pool = run.policy(4 * K as u64);
    let shares: Vec<_> = (0..workers).map(|_| run.shared_policy(pool)).collect();
    let per_worker = cases.len().div_ceil(workers);
    run.workers(
        &shares,
        per_worker,
        Retirement::Released,
        |_| Worked::new((), per_worker),
        |worker, fixture, held, worker_policy| {
            let Some(&case) = cases.iter().skip(worker).step_by(workers).nth(fixture) else {
                return Ok(());
            };
            let mut m = worker_policy.share();
            if let Some(stop) = case {
                super::support::refuse(
                    &mut m,
                    super::support::pipeline::Refusal::For(stop, LimitRefusal::Work),
                );
            }
            let output = held.drive(
                &mut m,
                super::bindings::string_decoder(wire),
                string_turns(wire.len()),
            )?;
            assert_eq!(output.value(), expected);
            check(&m, case);
            Ok(())
        },
    )?;
    run.with_policy(pool, |pool| assert_eq!(pool.live_bytes(), 0));
    let owner = run.with_policy(pool, |pool| pool.owner().expect("a recorded owner"));
    let all = run.with_policy(pool, |pool| occupy::<K>(pool, &owner));
    run.holding(all, Retirement::Released, &Unwitnessed, |all| {
        all.with_policy(pool, |_, pool| refuses_more(pool, &owner));
    });
    run.with_policy(pool, |pool| assert_eq!(pool.live_bytes(), 0));
    Ok(())
}

/// One worker's case of the aggregation witnesses below: `copy` copies
/// 4 KiB into the worker's own scope ([`Worked`]) under a session of 64
/// event slots, which that copy outgrows, so the worker's recording is lost
/// there.
fn copy_case(
    held: &mut Worked<
        dcbor::bounded::decode::construction::DecodeOwner<'static, Limits>,
        dcbor::bounded::decode::construction::InputAcquisition<'static, 'static, Limits>,
    >,
    m: &mut Limits,
) -> Result<(), Finding> {
    use super::support::Source;
    held.initialize(m)?;
    let source = super::support::Copying(&[0x5a; 4096]);
    let turns = source.turns();
    let copy = source.acquire(&held.scope);
    held.drive(m, copy, turns)?;
    Ok(())
}

/// The run of 64 event slots both aggregation witnesses lose, its
/// finalization's report: `task` run by `workers` workers of three fixtures
/// each ([`super::support::RecordedRun::workers`]), each worker holding a
/// scope of its own, returned through its join and retired by the parent.
fn aggregated(
    workers: usize,
    task: impl Fn(
        usize,
        usize,
        &mut Worked<
            dcbor::bounded::decode::construction::DecodeOwner<'static, Limits>,
            dcbor::bounded::decode::construction::InputAcquisition<'static, 'static, Limits>,
        >,
        &mut Limits,
    ) -> Result<(), Finding>
    + Sync,
) -> String {
    let finalization = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::support::recorded_run_short(
            dcbor::bounded::Capacity {
                permits: super::support::CAPACITY.permits,
                events: 64,
            },
            |run| {
                let policy = run.policy(POOL);
                let shares: Vec<_> = (0..workers).map(|_| run.shared_policy(policy)).collect();
                run.workers(
                    &shares,
                    3,
                    super::support::Retirement::Scope,
                    |_| Worked::new(dcbor::bounded::decode::construction::DecodeOwner::new(), 1),
                    task,
                )
            },
        );
    }))
    .expect_err("a run whose recording was lost was finalized as evidence");
    super::support::panic_report(finalization.as_ref())
}

/// The aggregation contract of [`super::support::RecordedRun::workers`]
/// under a real recording loss, in concurrent workers: each worker's
/// fixture 0 fails, its fixture 1 loses the recording ([`copy_case`]), and
/// its fixture 2 records that it ran. Every worker returns its earlier
/// failure beside the loss, runs no fixture after the loss, and is joined,
/// its custody retired by the parent; the run's one finalization then
/// reports all of them and refuses the recording. Planted control
/// `tests/data/controls/fixture-loss-drops-findings.patch` (the loss
/// returned alone) drops the earlier failures, which this test names.
#[test]
fn an_earlier_fixture_failure_and_a_recording_loss_both_reach_finalization() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    const WORKERS: usize = 2;
    let after = AtomicUsize::new(0);
    // Every worker begins its first fixture before any can lose the
    // recording: a worker reads the loss before each fixture.
    let started = std::sync::Barrier::new(WORKERS);
    let report = aggregated(WORKERS, |_, fixture, held, m| match fixture {
        0 => {
            started.wait();
            Err(Finding::Defect(
                "a planted failure before the loss".to_owned(),
            ))
        }
        1 => copy_case(held, m),
        _ => {
            after.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    assert_eq!(
        after.load(Ordering::SeqCst),
        0,
        "a fixture ran after the recording was lost"
    );
    for worker in 0..WORKERS {
        let earlier = format!("worker {worker}, fixture 0: a planted failure before the loss");
        assert_eq!(
            report.matches(&earlier).count(),
            1,
            "each worker returns its earlier failure beside the loss; missing or duplicated {earlier}: {report}"
        );
    }
    assert_eq!(
        report
            .matches("the run's recording became no evidence")
            .count(),
        WORKERS,
        "each worker returns its loss once: {report}"
    );
    assert!(
        report.ends_with("the recording is no evidence: Exhausted, first by Events"),
        "the run's finalization was skipped: {report}"
    );
}

/// A worker's panic cannot discard another worker's fixture failure or
/// recording loss, and cannot bypass the last worker or the sole finalizer:
/// worker 0 panics at its first fixture, worker 1 fails then loses the
/// recording, worker 2 returns a failure; every one is joined and named.
#[test]
fn worker_panic_fixture_failure_and_recording_loss_reach_finalization() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let later_returned = AtomicBool::new(false);
    // Every worker begins its first fixture before any can lose the
    // recording: a worker reads the loss before each fixture.
    let started = std::sync::Barrier::new(3);
    let report = aggregated(3, |worker, fixture, held, m| {
        if fixture == 0 {
            started.wait();
        }
        match (worker, fixture) {
            (0, 0) => panic!("planted worker panic"),
            (1, 0) => Err(Finding::Defect("prior fixture failure".to_owned())),
            (1, 1) => copy_case(held, m),
            (1, _) => panic!("scheduled execution continued after recording loss"),
            (2, 0) => {
                later_returned.store(true, Ordering::SeqCst);
                Err(Finding::Defect("last worker returned".to_owned()))
            }
            _ => Ok(()),
        }
    });
    assert!(later_returned.load(Ordering::SeqCst));
    for expected in [
        "worker 0, fixture 0: planted worker panic",
        "worker 1, fixture 0: prior fixture failure",
        "worker 2, fixture 0: last worker returned",
        "the run's recording became no evidence",
    ] {
        assert!(report.contains(expected), "missing {expected}: {report}");
    }
    assert!(
        !report.contains("scheduled execution continued after recording loss"),
        "a fixture ran after the recording was lost: {report}"
    );
    assert!(
        report.ends_with("the recording is no evidence: Exhausted, first by Events"),
        "finalization was bypassed: {report}"
    );
}

pub use super::support::failed;

/// A prepared plan the held emission schedule emits ([`emit_held`]): the
/// encoding's ([`Prepared`]) and the text pipeline's ([`PreparedText`]), each
/// written through its own writer within its own bound of turns.
pub trait Plan: Custodial<Reservation> {
    /// The writer of the plan into a destination of its length.
    // Named by path: in scope, the trait's `position(&mut self)` would take
    // precedence over the plans' and operations' inherent readers.
    type Writer<'p, 'o>: dcbor::bounded::Resumable<Limits, Output = (), Error = BoundedError<LimitRefusal>>
        + Custodial<Reservation>
        + super::support::Terminal
    where
        Self: 'p;

    /// The plan's encoded length.
    fn length(&self) -> usize;

    /// The writer of the plan into `output`.
    fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> Self::Writer<'p, 'o>;

    /// The bytes `writer` has emitted so far.
    fn emitted<'w>(writer: &'w Self::Writer<'_, '_>) -> &'w [u8];

    /// The turns emitting `len` bytes of the plan takes.
    fn turns(len: usize) -> usize;
}

impl Plan for Prepared<Reservation> {
    type Writer<'p, 'o> = dcbor::bounded::encoding::Writer<'p, 'o, Reservation>;

    fn length(&self) -> usize {
        self.len()
    }

    fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> Self::Writer<'p, 'o> {
        Prepared::writer(self, output)
    }

    fn emitted<'w>(writer: &'w Self::Writer<'_, '_>) -> &'w [u8] {
        writer.emitted_prefix()
    }

    fn turns(len: usize) -> usize {
        emit_turns(len)
    }
}

impl Plan for PreparedText<Reservation> {
    type Writer<'p, 'o> = dcbor::bounded::text_cursor::pipeline::TextWriter<'p, 'o, Reservation>;

    fn length(&self) -> usize {
        usize::try_from(self.len()).expect("a prepared text held in memory fits in usize")
    }

    fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> Self::Writer<'p, 'o> {
        PreparedText::writer(self, output)
    }

    fn emitted<'w>(writer: &'w Self::Writer<'_, '_>) -> &'w [u8] {
        writer.emitted_prefix()
    }

    fn turns(len: usize) -> usize {
        text_emit_turns(len)
    }
}

/// Emit the held `plan`, whose storage `storage`'s family holds, under
/// `policy` into a guarded destination of `expected`'s length within its
/// bound of turns ([`Plan::turns`]), `fault` applied to the emission
/// ([`super::support::Holding::drive_faulted`]): a refusal resumed, or the
/// emission cancelled at its injected refusal when the fault cancels. After
/// every turn the emitted bytes are a prefix of `expected` and the plan's
/// storage is unchanged; a refused step moves nothing, the turn contract
/// holding it. A completed emission is the literal bytes; no emission
/// writes outside its destination or requests allocation. The one emission
/// schedule of every plan; the emission's stop is the run's finding.
pub fn emit_held<T: Plan, W: super::support::pipeline::Physical>(
    plan: &mut super::support::Holding<'_, '_, T, W>,
    storage: super::support::PolicyId,
    policy: super::support::PolicyId,
    expected: &[u8],
    fault: super::support::Fault,
) -> Result<(), Finding>
where
    for<'v> &'v T: Custodial<Reservation>,
{
    use super::support::Retirement;
    assert_eq!(plan.value().length(), expected.len());
    let mut bytes = vec![0xee; expected.len() + 2];
    let requests = plan.with_policy(policy, |_, m| m.requests());
    // A share of the plan's family, which admits nothing: a view of the
    // plan's storage while the emission steps.
    let pool = plan.with_policy(storage, |_, m| m.share());
    let live = pool.live_bytes();
    let completed = plan.lending(
        Retirement::Released,
        |plan| plan.writer(&mut bytes[1..=expected.len()]),
        |writer| {
            let emitted = writer.drive_faulted(
                policy,
                T::turns(expected.len()),
                Retirement::Released,
                fault,
                |_, writer| {
                    let prefix = T::emitted(writer);
                    assert_eq!(prefix, &expected[..prefix.len()], "emission diverged");
                    assert_eq!(
                        pool.live_bytes(),
                        live,
                        "emission changed the plan's storage"
                    );
                },
                |_| (),
            )?;
            Ok::<_, Finding>(emitted.is_some())
        },
    )?;
    if completed {
        assert_eq!(&bytes[1..=expected.len()], expected);
    }
    assert_eq!(
        (bytes[0], bytes[expected.len() + 1]),
        (0xee, 0xee),
        "emission wrote outside its destination"
    );
    plan.with_policy(policy, |_, m| {
        assert_eq!(m.requests(), requests, "emission requested allocation");
    });
    Ok(())
}

/// What preparing a source must reach: its literal encoding, or the terminal
/// rejection of an invalid source.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub type Expected<'e> = Result<&'e [u8], BoundedError<LimitRefusal>>;

/// The fault matrix of preparing `source` ([`refusal_matrix`]): every
/// refusal resumed without replay, and a cancellation at every call, which
/// ends the trace there. Named by the source shape and declared outcome;
/// libtest supplies the surrounding semantic test identity.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_matrix(source: &dyn Schema, expected: Expected<'_>) {
    prepare_matrix_bounded(source, expected, shape(source));
}

/// A fixture-supplied structural upper bound for sources rejected by the
/// shape walk itself. The actual preparation must still reach the exact
/// declared error under every shared refusal and cancellation schedule.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_matrix_bounded(
    source: &dyn Schema,
    expected: Expected<'_>,
    bound: dcbor::bounded::encoding::Shape,
) {
    let name = format!("prepare {bound:?}, expected {expected:?}");
    refusal_matrix(&name, rigor(), |fault| {
        prepare_run(source, &expected, fault, bound)
    });
}

/// A map key compared with its immediate predecessor, where the source
/// claims canonical order, and found equal after numeric reduction: a
/// collision (`dynamic.rs` `Verify`). Its one caller, the schema group's
/// ordered path, is registered under `derive`.
#[cfg(feature = "derive")]
pub const KEY_COLLISION: Boundary = Boundary {
    predicate: Predicate::KeyOrder,
    valuation: Valuation::At,
};

/// A map key compared with its immediate predecessor and found strictly
/// after it. Its one caller is registered under `derive`, as
/// [`KEY_COLLISION`]'s.
#[cfg(feature = "derive")]
pub const KEY_AFTER: Boundary = Boundary {
    predicate: Predicate::KeyOrder,
    valuation: Valuation::Past,
};

/// Two runs' merge candidate keys found equal after numeric reduction: a
/// collision (`maps/order.rs`).
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub const MERGE_COLLISION: Boundary = Boundary {
    predicate: Predicate::MergeOrder,
    valuation: Valuation::At,
};

/// The later run's merge candidate key found strictly after the earlier
/// run's.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub const MERGE_AFTER: Boundary = Boundary {
    predicate: Predicate::MergeOrder,
    valuation: Valuation::Past,
};

/// A map key whose values are distinct as Rust values but whose canonical
/// encodings can coincide: an integer, or a float, which numeric reduction
/// encodes as the integer when it is integral (`10.0` as `10`, `-0.0` as
/// `0`). Each variant delegates to the crate's own `i64` and `f64` schemas
/// (`src/bounded/encoding/values.rs`, `numbers!`), so the engine reduces it,
/// never the fixture. Equality, hashing and order are by variant, then by
/// the value's bits: an integer orders before every float.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
#[derive(Clone, Copy, Debug)]
pub enum Number {
    Integer(i64),
    Float(f64),
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl Number {
    /// The variant and the value's bits: what equality, hashing and order
    /// compare.
    fn identity(self) -> (u8, u64) {
        match self {
            Self::Integer(value) => (0, value as u64),
            Self::Float(value) => (1, value.to_bits()),
        }
    }
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl Eq for Number {}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl std::hash::Hash for Number {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl Ord for Number {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity().cmp(&other.identity())
    }
}

#[cfg(any(feature = "derive", feature = "hashbrown"))]
impl Schema for Number {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match self {
            Self::Integer(value) => value.instruction(index),
            Self::Float(value) => value.instruction(index),
        }
    }
}

/// Prepare `source` once under the suite's policy within its shape's bound,
/// refusals resumed, and require `expected`: its literal encoding, emitted
/// under a policy of its own, or its rejection, which is an invalid input
/// ([`Class::Invalid`]) after which the preparation admits nothing. Every
/// reservation is released. Returns the boundary valuations the
/// preparation's policy reached.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn key_order(source: &dyn Schema, expected: Expected<'_>) -> Reached {
    if let Err(error) = &expected {
        assert!(
            matches!(error.class(), Class::Invalid),
            "{error:?} is not an invalid input"
        );
    }
    prepare_run(source, &expected, Fault::NONE, shape(source)).reached()
}

/// Preparation, optional refusal cancellation, and guarded emission share
/// one custody schedule. Emission has its own policy in the same recording;
/// a rejected preparation's own cleanup is stepped to its end under a share
/// of the preparation's policy, its own trace over the same storage, as every
/// rejection's is ([`rejected_case`]), so the preparation's calls end at its
/// rejection. Returns the preparation's attempted calls and boundary
/// valuations after every holding retires and the recording finalizes.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_run(
    source: &dyn Schema,
    expected: &Expected<'_>,
    fault: Fault,
    bound: dcbor::bounded::encoding::Shape,
) -> super::support::RefusalRun {
    use super::support::{Retirement, pipeline::Unwitnessed};

    super::support::recorded_run(|run| {
        let preparing = run.policy(POOL);
        let emitting = run.policy(POOL);
        let cleanup = run.shared_policy(preparing);
        run.holding(
            Preparation::new(source),
            Retirement::Released,
            &Unwitnessed,
            |operation| match operation.drive_faulted(
                preparing,
                prepare_turns(bound),
                Retirement::Released,
                fault,
                |_, _| {},
                |plan| {
                    plan.with_policy(preparing, |_, m| assert!(m.live_bytes() > 0));
                    let expected = expected
                        .as_ref()
                        .copied()
                        .expect("a published plan's source was expected to publish");
                    emit_held(plan, preparing, emitting, expected, Fault::NONE)
                },
            ) {
                Ok(Some(result)) => result,
                Ok(None) => Ok(()),
                Err(Stopped::Operation(error)) => {
                    assert_eq!(
                        expected.as_ref().err(),
                        Some(&error),
                        "unexpected rejection at {:?}",
                        operation.value().position()
                    );
                    operation.finish(cleanup, prepare_turns(bound), Retirement::Released)?;
                    Ok(())
                }
                Err(stop) => Err(Finding::from(stop)),
            },
        )?;
        Ok(run.with_policy(preparing, |m| {
            assert_eq!(m.live_bytes(), 0);
            super::support::RefusalRun::of(m)
        }))
    })
}

/// Prepare `source` under the heap observer, failing physical request
/// `failure`. Observed storage stays within reservations, every request was
/// admitted, and failure or completion releases every byte and reservation.
/// Returns the physical requests made and the boundary valuations the
/// preparation reached.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_physically(
    source: &dyn Schema,
    failure: Option<usize>,
) -> (usize, dcbor::bounded::boundary::Reached) {
    use super::support::Retirement;

    let turns = prepare_turns(shape(source));
    super::support::recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        let observation = Observation::begin(failure);
        observation.stop();
        let failed = run.holding(
            Preparation::new(source),
            Retirement::Released,
            &observation,
            |operation| match operation.drive_observed(
                policy,
                turns,
                Retirement::Released,
                |m, _| assert!(observation.snapshot().live <= m.live_bytes() as usize),
                |plan| plan.with_policy(policy, |_, m| assert!(m.live_bytes() > 0)),
            ) {
                Ok(()) => Ok(false),
                Err(Stopped::Operation(BoundedError::Allocation { .. })) => {
                    // The preparation's own cleanup, each turn inside the
                    // observer's window.
                    operation.finish(policy, turns, Retirement::Released)?;
                    Ok(true)
                }
                Err(stop) => Err(Finding::from(stop)),
            },
        )?;
        assert_eq!(failed, failure.is_some());
        let stats = observation.snapshot();
        assert_eq!(stats.denied, usize::from(failure.is_some()));
        assert_eq!(stats.unadmitted, 0);
        assert!(!stats.overflow);
        assert_eq!(stats.live, 0);
        run.with_policy(policy, |m| {
            assert!(stats.peak <= m.peak_bytes() as usize);
            assert_eq!(m.live_bytes(), 0);
            Ok((stats.calls, m.reached()))
        })
    })
}

/// Every physical allocation of preparing `source`, failed in a run of its
/// own ([`physical_matrix`]). Named by the source shape within its test.
#[cfg(any(feature = "derive", feature = "hashbrown"))]
pub fn prepare_physical_matrix(source: &dyn Schema) {
    let name = format!("prepare {:?}", shape(source));
    physical_matrix(&name, |failure| prepare_physically(source, failure));
}

pub fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut wire = match n {
        0..24 => vec![0x60 | n as u8],
        24..256 => vec![0x78, n as u8],
        256..65536 => vec![0x79, (n >> 8) as u8, n as u8],
        _ => {
            let mut v = vec![0x7a];
            v.extend(u32::try_from(n).unwrap().to_be_bytes());
            v
        }
    };
    wire.extend(text.as_bytes());
    wire
}
