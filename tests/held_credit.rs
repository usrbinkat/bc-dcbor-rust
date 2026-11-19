//! A construction's held credit ([`Standalone::held_credit`], the checked
//! fold of its one custody traversal, [`Standalone::observe_custody`]) is
//! the credit its policy records as held, `A - C - F` ([`Credits`]), at every
//! step of every run of a refusal matrix: one container of each class built
//! from its document's root, each run refusing one attempted call (an
//! admission or an allocation request), retrying it, then building to `Done`
//! and cleaning up; and each run cancelled at that refusal, cleaned up from
//! there. Each run has a policy of its own, so its ledgers hold its events
//! alone. Conservation is read after every step, every step being quiescent
//! on this thread. Cleanup ends holding nothing, every credit spent or
//! forfeited.
#![cfg(feature = "std")]

// The observed construction driver witnesses physical storage.
#[global_allocator]
static HEAP: dcbor_test_support::heap::Heap = dcbor_test_support::heap::Heap;

use dcbor::bounded::decode::construction::Standalone;
use dcbor::bounded::decode::construction::in_place::{Built, InPlace, StableOption};
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::{DecodeError, decode};
use dcbor::bounded::{
    BoundedError, Custodial, Identity, Limits, PermitsObserved, WriteWork, bound_of,
};
use std::mem::MaybeUninit;

/// The ledgers of `m` with `held`, the state's held credit: `A = C + F + H`,
/// no update refused.
fn conserved(m: &Limits, held: Option<WriteWork>, what: &str) {
    let credits = m.credits();
    let held = held.unwrap_or_else(|| panic!("{what}: held credit beyond u64"));
    assert_eq!(
        credits.conserved_with(held),
        Some(true),
        "{what}: {credits:?} against held {held:?}"
    );
}

/// What one run did: the attempts of its policy when it ended.
struct Run {
    attempts: usize,
}

/// One run of `T` from `wire`: refusing attempted call `refuse` once, if
/// any; at that refusal, cancelled when `cancel` and it falls in
/// construction, otherwise retried; built to `Done`, the value `built`
/// accepts, unless cancelled, then cleaned up to `Done`. Conservation is
/// checked after every step, refused ones included, and cleanup's `Done`
/// holds nothing.
fn run<T: InPlace<Limits>>(
    name: &str,
    wire: &[u8],
    built: &dyn Fn(&T) -> bool,
    refuse: Option<usize>,
    cancel: bool,
) -> Run {
    let what = format!("{name}, refusing {refuse:?}, cancelled {cancel}");
    let mut parser = Limits::unlimited();
    let document = decode(wire, 8, &mut parser).expect("the fixture decodes");
    let mut m = Limits::unlimited().refusing(refuse);
    let mut value = MaybeUninit::<T>::uninit();
    let mut driver = Standalone::<T, Limits>::new(&document, &mut value);
    conserved(&m, driver.held_credit(), &format!("{what}: initial"));
    let mut cancelled = false;
    for step in 0..4096 {
        match driver.build_step(&mut m) {
            Ok(Built::Done) => {
                conserved(&m, driver.held_credit(), &format!("{what}: built"));
                break;
            }
            Ok(Built::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(_))) if cancel => {
                conserved(&m, driver.held_credit(), &format!("{what}: refused"));
                cancelled = true;
                break;
            }
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Err(other) => panic!("{what}: step {step}: {other:?}"),
        }
        conserved(
            &m,
            driver.held_credit(),
            &format!("{what}: build step {step}"),
        );
    }
    assert!(
        cancelled || driver.value().is_some_and(built),
        "{what}: construction did not complete to the expected value"
    );
    // A refused cleanup unit changes nothing and is not counted: it is
    // retried, as a refused build step is.
    let declared = driver
        .remaining()
        .expect("a fixture's cleanup count fits in u64");
    let mut taken = 0u64;
    loop {
        assert!(
            taken < declared,
            "{what}: cleanup beyond its declared {declared} calls"
        );
        match driver.reclaim_step(&mut m) {
            Ok(reclaimed) => {
                conserved(
                    &m,
                    driver.held_credit(),
                    &format!("{what}: cleanup step {taken}"),
                );
                taken += 1;
                if reclaimed == Reclaimed::Done {
                    break;
                }
            }
            Err(BoundedError::Refused(_)) => {
                conserved(
                    &m,
                    driver.held_credit(),
                    &format!("{what}: refused cleanup"),
                );
            }
            Err(other) => panic!("{what}: cleanup step {taken}: {other:?}"),
        }
    }
    assert_eq!(
        driver.held_credit(),
        Some(WriteWork::default()),
        "{what}: cleanup ended holding credit"
    );
    assert_eq!(m.live_bytes(), 0, "{what}: storage kept");
    Run {
        attempts: m.attempts(),
    }
}

/// The refusal matrix of `T` from `wire`, built to the value `built`
/// accepts: the unrefused run, then every attempted call it made refused
/// once, retried and cancelled.
fn matrix<T: InPlace<Limits>>(name: &str, wire: &[u8], built: impl Fn(&T) -> bool) {
    let attempts = run::<T>(name, wire, &built, None, false).attempts;
    assert!(attempts > 0, "{name}: no admission");
    for at in 0..attempts {
        run::<T>(name, wire, &built, Some(at), false);
        run::<T>(name, wire, &built, Some(at), true);
    }
}

/// A CBOR array of the integers `0..count`.
fn integers(count: u8) -> Vec<u8> {
    let mut wire = vec![0x80 | count];
    wire.extend(0..count);
    wire
}

/// Sequences: a vector, whose payload's release and every element record's
/// admissions are held across a refused request; an array, inline.
#[test]
fn a_sequences_held_credit_is_its_ledgers_held() {
    matrix::<Vec<u64>>("Vec<u64>", &integers(3), |v| v == &[0, 1, 2]);
    matrix::<[u64; 2]>("[u64; 2]", &integers(2), |v| v == &[0, 1]);
    matrix::<Vec<Vec<u64>>>("Vec<Vec<u64>>", &[0x82, 0x81, 0x01, 0x80], |v| {
        v == &[vec![1], vec![]]
    });
}

/// Byte buffers: a text, a stabilized text and a minimal big integer's
/// magnitude, each holding its payload's release from its admission to its
/// grant.
#[test]
fn a_buffers_held_credit_is_its_ledgers_held() {
    matrix::<String>("String", &[0x63, b'a', b'b', b'c'], |v| v == "abc");
    matrix::<dcbor::StabilizedText>("StabilizedText", &[0x62, b'a', b'b'], |v| {
        v.as_str() == "ab"
    });
    // A bignum whose magnitude fits an integer is not minimal; 2^64 is.
    let mut bignum = vec![0xc2, 0x49, 0x01];
    bignum.extend([0; 8]);
    matrix::<dcbor::MinimalBigInt>("MinimalBigInt", &bignum, |v| {
        dcbor::CBOR::from(v) == dcbor::CBOR::try_from_data(&bignum).unwrap()
    });
}

/// Options: a native option and a stable option, each present over a held
/// payload and null.
#[test]
fn an_options_held_credit_is_its_ledgers_held() {
    matrix::<Option<String>>("Option<String>", &[0x61, b'a'], |v| {
        v.as_deref() == Some("a")
    });
    matrix::<Option<String>>("Option<String> null", &[0xf6], Option::is_none);
    matrix::<StableOption<Vec<u64>, Limits>>("StableOption<Vec<u64>>", &integers(2), |v| {
        v.as_ref().is_some_and(|v| v == &[0, 1])
    });
    matrix::<StableOption<Vec<u64>, Limits>>("StableOption<Vec<u64>> null", &[0xf6], |v| {
        !v.is_some()
    });
}

/// A tree: its metadata block's admissions, each node's grant and release
/// held across a refused request, and every entry's own.
#[cfg(feature = "custom-std-collections")]
#[test]
fn a_trees_held_credit_is_its_ledgers_held() {
    use std::collections::BTreeMap;
    // Twelve entries: a root over two leaves, three node allocations.
    let mut wire = vec![0xac];
    for key in 0..12u8 {
        wire.extend_from_slice(&[key, 0x61, b'a' + key]);
    }
    matrix::<BTreeMap<u64, String>>("BTreeMap<u64, String>", &wire, |v| {
        v.len() == 12
            && v.iter().all(|(key, value)| {
                u8::try_from(*key).is_ok_and(|key| value.as_bytes() == [b'a' + key])
            })
    });
}

/// Derived schemas: a record's fields (its field records' admissions and
/// each field's own), an enum's selected payload, and a tagged newtype's
/// payload.
#[cfg(feature = "derive")]
#[test]
fn a_derived_schemas_held_credit_is_its_ledgers_held() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Record {
        #[cbor(n = 1)]
        name: String,
        #[cbor(n = 2)]
        values: Vec<u64>,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    #[repr(u8)]
    enum Choice {
        #[cbor(n = 0)]
        Text(String),
        #[cbor(n = 1)]
        Empty,
    }
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged(Vec<u64>);
    // {1: "a", 2: [1]}
    matrix::<Record>("Record", &[0xa2, 0x01, 0x61, b'a', 0x02, 0x81, 0x01], |v| {
        v.name == "a" && v.values == [1]
    });
    // [0, "a"], then 1
    matrix::<Choice>(
        "Choice",
        &[0x82, 0x00, 0x61, b'a'],
        |v| matches!(v, Choice::Text(text) if text == "a"),
    );
    matrix::<Choice>("Choice empty", &[0x01], |v| matches!(v, Choice::Empty));
    // 42([1, 2])
    matrix::<Tagged>("Tagged", &[0xd8, 0x2a, 0x82, 0x01, 0x02], |v| v.0 == [1, 2]);
}

/// The custody cross-check, through the refinement machine: a text whose
/// metadata block's first request is refused, its write and its release
/// admitted held in the construction's pending across the refusal
/// (`stable::acquire`), checkpointed after that refused step and after every
/// later one (`dcbor_test_support::construction_requests`), every checkpoint
/// compared at finalization with the custody the stream before it reaches,
/// owner by owner. The refused request is shown, not assumed
/// (`RefusalRun::request_refusals`); the retry is granted and the text built
/// and cleaned up. A traversal that leaves out a held release fails here as
/// a missing held obligation of the pending's owner.
#[test]
fn a_refused_requests_held_obligations_are_each_checkpointed_under_their_owner() {
    let (built, accounting) =
        dcbor_test_support::construction_requests::<String>(&[0x61, b'a'], None, 1, |text| {
            assert_eq!(text, "a")
        });
    assert!(
        built.built,
        "the text was not built after its refused request"
    );
    accounting.request_refusals(1);
}

/// The driver's bound acquisitions, as its custody reports them
/// ([`bound_of`] over [`Standalone::observe_custody`]), the observation
/// whole.
fn bound<T: InPlace<Limits>>(driver: &mut Standalone<'_, '_, '_, T, Limits>) -> Vec<Identity> {
    let mut bound = Vec::new();
    let observed = bound_of(|sink| driver.observe_custody(sink), &mut |acquisition| {
        bound.push(acquisition)
    });
    assert_eq!(observed, PermitsObserved::Complete, "the custody is whole");
    bound
}

/// The observation cross-check: a buffer whose metadata's acquisition is
/// bound and then refused keeps its progress unallocated and initial, the
/// binding reported by the construction's custody alone, one acquisition;
/// the credit the driver holds is that acquisition's, its write admitted and
/// held in the construction's pending, which the state itself never holds.
/// The granted retry ends the acquisition: nothing bound, nothing held.
#[test]
fn an_unallocated_states_pending_acquisition_holds_its_admitted_write() {
    use dcbor::bounded::decode::construction::in_place::{BufferObservation, SessionObservation};
    let mut parser = Limits::unlimited();
    let document = decode(&[0x61, b'a'], 1, &mut parser).unwrap();
    // The bind unit admitted; the metadata's write admitted, its release
    // refused: one obligation held.
    let mut m = Limits::unlimited().refusing(Some(2));
    let mut value = MaybeUninit::<String>::uninit();
    let mut driver = Standalone::<String, Limits>::new(&document, &mut value);
    assert_eq!(driver.build_step(&mut m).unwrap(), Built::Progress);
    assert!(matches!(
        driver.build_step(&mut m),
        Err(DecodeError::Resource(BoundedError::Refused(_)))
    ));
    let SessionObservation {
        inner: BufferObservation::Unallocated,
        ..
    } = driver.observe()
    else {
        panic!("the metadata was acquired through a refused release");
    };
    assert_eq!(
        bound(&mut driver).len(),
        1,
        "the metadata's acquisition is not reported bound by the custody"
    );
    let held = driver.held_credit().unwrap();
    assert_ne!(held, WriteWork::default(), "the admitted write is held");
    conserved(&m, Some(held), "a refused release");
    // The retry admits the release and is granted, ending the acquisition:
    // nothing bound, nothing held.
    assert_eq!(driver.build_step(&mut m).unwrap(), Built::Progress);
    assert_eq!(
        bound(&mut driver),
        Vec::new(),
        "the granted acquisition is still reported bound"
    );
    assert_eq!(driver.held_credit(), Some(WriteWork::default()));
    conserved(&m, driver.held_credit(), "the granted metadata");
    for _ in 0..8 {
        if driver.reclaim_step(&mut m).unwrap() == Reclaimed::Done {
            break;
        }
    }
    conserved(&m, driver.held_credit(), "cleaned up");
    assert_eq!(m.live_bytes(), 0);
}

/// Preparation keeps a credit-free window binding across repeated refusals,
/// admits it under another family, and settles it under a third. All custody
/// observations go through the recorded runner's refinement checkpoints.
#[cfg(feature = "hashbrown")]
fn preparation_window_lifecycle(refusals: usize, cancel: bool) {
    use dcbor::bounded::encoding::Preparation;
    use dcbor::bounded::{
        Budget, Credit, Event, Family, Forfeit, Obligation, Origin, Reservation, Step,
    };
    use dcbor_test_support::{collect, recorded_run};

    // Identity hashes put adjacent entries in adjacent buckets, leaving
    // credit after the first entry instead of exhausting its window.
    let mut table = hashbrown::HashTable::with_capacity(128);
    for key in 0..32u64 {
        table.insert_unique(key, (key, key), |pair| pair.0);
    }
    recorded_run(|run| {
        let setup = run.policy(u64::MAX);
        let mint = run.policy(u64::MAX);
        let admit = run.policy(u64::MAX);
        let settle = run.policy(u64::MAX);
        let mut preparation = Preparation::<Reservation, Family>::new(&table);
        let bound = dcbor_test_support::prepare_turns(dcbor_test_support::shape(&table));
        let mut target = None;
        for _ in 0..bound {
            let before = preparation.position();
            let result = run.with_policy(mint, |policy| {
                policy.clear_refusal();
                policy.refuse_next();
                preparation.step(policy)
            });
            run.checkpoint(|sink| preparation.observe_custody(sink));
            let custody = collect(|sink| preparation.observe_custody(sink)).unwrap();
            // The stored preparation owner names windows alone; nested
            // arena owners may also have credit-free acquisitions.
            let candidate = custody.iter().find(|owner| {
                Some(owner.owner) == preparation.owner_id()
                    && owner.bound.len() == 1
                    && owner.held.is_empty()
                    && owner.permits.is_empty()
            });
            if let Some(owner) = candidate {
                assert!(matches!(result, Err(BoundedError::Refused(_))));
                assert_eq!(preparation.position(), before);
                target = Some((owner.owner, owner.bound[0]));
                break;
            }
            match result {
                Err(BoundedError::Refused(_)) => {
                    run.with_policy(setup, |policy| {
                        assert!(matches!(preparation.step(policy), Ok(Step::Progress)));
                    });
                    run.checkpoint(|sink| preparation.observe_custody(sink));
                }
                Ok(Step::Progress) => {}
                Err(error) => panic!("window acquisition not reached: {error:?}"),
                Ok(_) => panic!("preparation ended before the window acquisition"),
            }
        }
        let (owner, acquisition) = target.expect("a credit-free window refusal was reached");
        let position = preparation.position();
        let custody = collect(|sink| preparation.observe_custody(sink)).unwrap();
        let baseline = run.with_policy(mint, |policy| (policy.attempts(), policy.credits()));
        for _ in 1..refusals {
            run.with_policy(mint, |policy| {
                policy.clear_refusal();
                policy.refuse_next();
                assert!(matches!(
                    preparation.step(policy),
                    Err(BoundedError::Refused(_))
                ));
            });
            assert_eq!(preparation.position(), position, "refusal moved execution");
            assert_eq!(
                collect(|sink| preparation.observe_custody(sink)).unwrap(),
                custody,
                "refusal replaced the credit-free acquisition"
            );
            run.checkpoint(|sink| preparation.observe_custody(sink));
        }
        run.with_policy(mint, |policy| {
            assert_eq!(policy.attempts(), baseline.0 + refusals - 1);
            assert_eq!(policy.credits(), baseline.1, "refusal admitted credit");
        });
        let (admitting_family, admitting_by) = run.with_policy(admit, |policy| {
            (policy.origin().family(), policy.performer())
        });
        run.with_policy(admit, |policy| {
            assert!(matches!(preparation.step(policy), Ok(Step::Progress)));
        });
        run.checkpoint(|sink| preparation.observe_custody(sink));
        let held = collect(|sink| preparation.observe_custody(sink)).unwrap();
        let hold = *held
            .iter()
            .find(|group| group.owner == owner)
            .and_then(|group| group.held.first())
            .expect("the retried window retains its unused controls");
        assert_eq!(hold.obligation, Obligation::BucketWindow);
        assert_eq!(
            hold.acquisition, acquisition,
            "retry reminted the acquisition"
        );
        assert_eq!(hold.id.family(), admitting_family);
        assert_ne!(hold.work, WriteWork::default());
        let admitted_through = run.boundary();
        let performing_by = run.with_policy(settle, |policy| policy.performer());
        if !cancel {
            let mut completed = false;
            for _ in 0..bound {
                let result = run.with_policy(settle, |policy| preparation.step(policy));
                match result {
                    Ok(Step::Progress) => {}
                    Ok(Step::Complete(mut plan)) => {
                        run.checkpoint(|sink| {
                            dcbor::bounded::observed_all([
                                preparation.observe_custody(sink),
                                plan.observe_custody(sink),
                            ])
                        });
                        drop(plan);
                        completed = true;
                    }
                    Err(error) => panic!("cross-family continuation failed: {error:?}"),
                    Ok(Step::Finished) => panic!("continuation finished without publishing"),
                }
                run.checkpoint(|sink| preparation.observe_custody(sink));
                if completed {
                    break;
                }
            }
            assert!(completed, "cross-family continuation exceeded its bound");
        }
        let mut released = false;
        for _ in 0..bound {
            let result = run.with_policy(settle, |policy| preparation.reclaim_step(policy));
            run.checkpoint(|sink| preparation.observe_custody(sink));
            if result.unwrap() == Reclaimed::Done {
                released = true;
                break;
            }
        }
        assert!(released, "explicit cleanup exceeded its bound");
        let closed = run.boundary();
        drop(preparation);
        run.checkpoint(|_| PermitsObserved::Complete);
        run.inspect_evidence(move |events, checkpoints| {
            assert!(
                checkpoints
                    .iter()
                    .any(
                        |checkpoint| checkpoint.custody.iter().any(|group| group.owner == owner
                            && group.bound == [acquisition]
                            && group.held.is_empty())
                    ),
                "credit-free binding was not checkpointed"
            );
            let admissions: Vec<_> = events
                .iter()
                .filter_map(|event| match event.event {
                    Event::Credit(Credit::Admit {
                        work,
                        held: Some(admitted),
                    }) if admitted.acquisition == acquisition => {
                        Some((event.family, event.by, work, admitted))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(admissions.len(), 1, "window was readmitted");
            let (family, by, work, admitted) = admissions[0];
            assert_eq!((family, by), (admitting_family, admitting_by));
            assert_eq!(admitted.id, hold.id);
            assert_eq!(work.values, 1);
            assert_eq!(admitted.work, WriteWork::new(0, work.bytes));
            let mut total = WriteWork::default();
            let mut last_settlement = None;
            for (at, event) in events.iter().enumerate() {
                let settled = match event.event {
                    Event::Credit(Credit::Spend(value)) if value.id == hold.id => value,
                    Event::Credit(Credit::Forfeit(value, rule)) if value.id == hold.id => {
                        assert_eq!(
                            rule,
                            if cancel {
                                Forfeit::Cancelled
                            } else {
                                Forfeit::EnumerationComplete
                            }
                        );
                        value
                    }
                    _ => continue,
                };
                assert_eq!(event.family, admitting_family, "settlement changed origin");
                assert_eq!(settled.acquisition, acquisition);
                assert_eq!(
                    event.by,
                    if at < admitted_through {
                        admitting_by
                    } else {
                        performing_by
                    },
                    "settlement named a policy other than the step's performer"
                );
                assert_eq!(settled.permit, None, "a bucket window acquired a permit");
                assert_eq!(settled.obligation, Obligation::BucketWindow);
                total = total.checked_then(settled.work).unwrap();
                last_settlement = Some(at);
                assert!(at < closed, "drop settled explicitly closed credit");
            }
            assert_eq!(total, admitted.work, "window settlement was not exact");
            let ends: Vec<_> = events.iter().enumerate().filter(|(_, event)| {
                matches!(event.event, Event::End { acquisition: id, .. } if id == acquisition)
            }).collect();
            assert_eq!(ends.len(), 1, "window acquisition did not end exactly once");
            let (at, end) = ends[0];
            assert_eq!(end.family, acquisition.family());
            assert_eq!(end.by, performing_by);
            assert!(
                matches!(end.event, Event::End { owner: ended_owner, .. } if ended_owner == owner)
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(
                        event.event,
                        Event::Bound { owner: bound_owner, acquisition: id }
                            if id == acquisition && bound_owner == owner
                    ))
                    .count(),
                1,
                "the window was not bound exactly once under its mint-time owner"
            );
            assert!(last_settlement.is_some_and(|settled| settled < at));
            assert!(at < closed, "drop ended an explicitly closed acquisition");
        });
        Ok(())
    });
}

#[cfg(feature = "hashbrown")]
#[test]
fn preparation_credit_free_refusal_is_refined() {
    preparation_window_lifecycle(1, true);
}

#[cfg(feature = "hashbrown")]
#[test]
fn preparation_repeated_refusal_admits_the_window_exactly_once() {
    preparation_window_lifecycle(4, false);
}

#[cfg(feature = "hashbrown")]
#[test]
fn preparation_continues_a_window_across_families() {
    preparation_window_lifecycle(1, false);
}

#[cfg(feature = "hashbrown")]
#[test]
fn preparation_explicit_close_then_drop_settles_and_ends_once() {
    preparation_window_lifecycle(4, true);
}

/// The fresh turns a resumed acquisition's retry may take: an acquisition
/// admits at most its write, its release and its allocation, each within
/// one quantum and kept across a refusal (`stable::acquire`), so a retry
/// whose remaining units do not fit one turn's quantum completes within one
/// fresh turn per unit.
const RETRY_TURNS: usize = 3;

/// Reach a real holder's credit-free acquisition, refuse it repeatedly,
/// resume under another family, then destroy the holder. The resumed
/// retry takes fresh turns until the holder advances, each turn short of
/// it refused only as ordinary exhaustion of that turn's quantum, its
/// admissions retained ([`dcbor_test_support::ordinary_exhaustion`]). Every
/// boundary is refined, including the empty custody after destruction.
fn retained_holder_lifecycle<O>(
    mut operation: O,
    turns: usize,
    mut observe: impl FnMut(
        &mut O,
        &mut dyn dcbor::bounded::CustodySink<dcbor::bounded::Reservation>,
    ) -> PermitsObserved,
) where
    O: dcbor::bounded::Resumable<Limits>,
    O::Error: std::fmt::Debug + dcbor::bounded::Failure<Refusal = dcbor::bounded::LimitRefusal>,
{
    use dcbor::bounded::{Credit, Event, Performer, Step};
    use dcbor_test_support::{collect, recorded_run};

    recorded_run(|run| {
        let mint = run.policy(u64::MAX);
        let resume = run.policy(u64::MAX);
        let mut target = None;
        for at in 0..turns {
            let result = run.with_policy(mint, |m| {
                m.clear_refusal();
                m.refuse_next();
                dcbor_test_support::scheduled(m, &mut operation, at)
            })?;
            run.checkpoint(|sink| observe(&mut operation, sink));
            let custody = collect(|sink| observe(&mut operation, sink)).unwrap();
            if let Some(group) = custody
                .iter()
                .find(|group| group.bound.len() == 1 && group.held.is_empty())
            {
                assert!(
                    result.is_err(),
                    "a refused acquisition unexpectedly advanced"
                );
                target = Some(group.bound[0]);
                break;
            }
            drop(result);
            let resumed = run.with_policy(resume, |m| {
                dcbor_test_support::scheduled(m, &mut operation, at)
            })?;
            assert!(
                matches!(resumed, Ok(Step::Progress)),
                "holder ended before acquiring"
            );
            run.checkpoint(|sink| observe(&mut operation, sink));
        }
        let acquisition = target.expect("the holder reached a credit-free acquisition");
        let custody = collect(|sink| observe(&mut operation, sink)).unwrap();
        let position = operation.position();
        for at in 0..3 {
            let refused = run.with_policy(mint, |m| {
                m.clear_refusal();
                m.refuse_next();
                dcbor_test_support::scheduled(m, &mut operation, at)
            })?;
            assert!(refused.is_err(), "the repeated refusal was swallowed");
            assert_eq!(operation.position(), position, "refusal moved execution");
            assert_eq!(
                collect(|sink| observe(&mut operation, sink)).unwrap(),
                custody,
                "refusal replaced acquisition custody"
            );
            run.checkpoint(|sink| observe(&mut operation, sink));
        }
        let mut advanced = false;
        for at in 0..RETRY_TURNS {
            let resumed = run.with_policy(resume, |m| {
                let resumed = dcbor_test_support::scheduled(m, &mut operation, at)?;
                let exhausted = matches!(
                    &resumed,
                    Err(error) if dcbor_test_support::ordinary_exhaustion(m, error)
                );
                Ok::<_, dcbor_test_support::Finding>((resumed, exhausted))
            })?;
            run.checkpoint(|sink| observe(&mut operation, sink));
            match resumed {
                (Ok(Step::Progress), _) => {
                    advanced = true;
                    break;
                }
                (_, true) => {}
                (other, false) => panic!(
                    "the acquisition retry was refused other than by its turn's quantum: {}",
                    dcbor_test_support::label(&other)
                ),
            }
        }
        assert!(
            advanced,
            "the acquisition retry did not advance within {RETRY_TURNS} fresh turns"
        );
        let before_drop = run.boundary();
        drop(operation);
        run.checkpoint(|_| PermitsObserved::Complete);
        run.inspect_evidence(move |events, _| {
            let binds = events
                .iter()
                .filter(|event| {
                    matches!(
                        event.event, Event::Bound { acquisition: id, .. } if id == acquisition
                    )
                })
                .count();
            assert_eq!(binds, 1, "retries minted another acquisition");
            let ends: Vec<_> = events
                .iter()
                .enumerate()
                .filter(|(_, event)| {
                    matches!(
                        event.event, Event::End { acquisition: id, .. } if id == acquisition
                    )
                })
                .collect();
            assert_eq!(
                ends.len(),
                1,
                "the holder did not end its acquisition exactly once"
            );
            let (end_at, end) = ends[0];
            assert_eq!(
                end.family,
                acquisition.family(),
                "the end changed minting family"
            );
            if end_at >= before_drop {
                assert_eq!(end.by, Performer::None, "destruction invented a performer");
            }
            for (at, event) in events.iter().enumerate() {
                match event.event {
                    Event::Credit(Credit::Spend(settled))
                    | Event::Credit(Credit::Forfeit(settled, _))
                        if settled.acquisition == acquisition =>
                    {
                        assert!(at < end_at, "settlement followed the acquisition end");
                        assert_eq!(
                            event.family,
                            settled.id.family(),
                            "settlement changed origin"
                        );
                    }
                    _ => {}
                }
            }
        });
        Ok(())
    });
}

#[test]
fn string_continuation_retains_its_acquisition_across_refusal_and_destruction() {
    use dcbor::bounded::decode::{Options, string_cursor::StringDecoder};
    let wire = [0x63, b'a', b'b', b'c'];
    retained_holder_lifecycle(
        StringDecoder::new(&wire, Options::normalizing(16)),
        dcbor_test_support::string_turns(wire.len()),
        |operation, sink| operation.observe_custody(sink),
    );
}

#[test]
fn text_continuation_retains_its_acquisition_across_refusal_and_destruction() {
    use dcbor::bounded::text_cursor::TextEncoder;
    let source = "a\u{301}";
    retained_holder_lifecycle(
        TextEncoder::new(source),
        dcbor_test_support::normalize_turns(source),
        |operation, sink| operation.observe_custody(sink),
    );
}

#[test]
fn synchronous_writer_ends_each_call_after_settlement_on_refusal_and_success() {
    use dcbor::bounded::{Budget, Credit, Event, Forfeit, LimitRefusal, prepare};
    use dcbor_test_support::recorded_run;

    let mut preparation_policy = Limits::unlimited();
    let plan = prepare(&24u64, &mut preparation_policy).expect("the literal plan");
    // Release admission, allocation request, initialization, and success.
    for refusal in [Some(0), Some(1), Some(2), None] {
        recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let by = run.with_policy(policy, |m| {
                m.fail_call(refusal.map(|at| (at, LimitRefusal::Scheduled(at))));
                m.performer()
            });
            let result = run.with_policy(policy, |m| plan.encode_owned(m));
            match result {
                Ok(mut encoded) => {
                    assert_eq!(refusal, None, "the scheduled refusal was swallowed");
                    assert_eq!(encoded.as_ref(), [0x18, 0x18]);
                    run.checkpoint(|sink| encoded.observe_custody(sink));
                    drop(encoded);
                }
                Err(BoundedError::Refused(_)) => {
                    assert!(refusal.is_some(), "the unlimited writer refused");
                }
                Err(error) => panic!("the synchronous writer failed: {error:?}"),
            }
            run.checkpoint(|_| PermitsObserved::Complete);
            run.inspect_evidence(move |events, _| {
                let bindings: Vec<_> = events
                    .iter()
                    .filter_map(|event| match event.event {
                        Event::Bound { owner, acquisition } => Some((owner, acquisition)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    bindings.len(),
                    1,
                    "one synchronous call owns one acquisition"
                );
                let (owner, acquisition) = bindings[0];
                let ends: Vec<_> = events
                    .iter()
                    .enumerate()
                    .filter(|(_, event)| event.event == Event::End { owner, acquisition })
                    .collect();
                assert_eq!(
                    ends.len(),
                    1,
                    "the synchronous call did not end exactly once"
                );
                let (end_at, end) = ends[0];
                assert_eq!(end.by, by);
                assert_eq!(end.family, acquisition.family());
                let settlements: Vec<_> = events
                    .iter()
                    .enumerate()
                    .filter_map(|(at, event)| match event.event {
                        Event::Credit(Credit::Spend(settled))
                            if settled.acquisition == acquisition =>
                        {
                            Some((at, event.by, settled, None))
                        }
                        Event::Credit(Credit::Forfeit(settled, rule))
                            if settled.acquisition == acquisition =>
                        {
                            Some((at, event.by, settled, Some(rule)))
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(settlements.len(), usize::from(refusal != Some(0)));
                for (at, performer, settled, rule) in settlements {
                    assert!(at < end_at, "the call ended before settlement");
                    assert_eq!(performer, by);
                    assert_eq!(settled.id.family(), acquisition.family());
                    assert_eq!(
                        rule,
                        if refusal == Some(1) {
                            Some(Forfeit::AcquisitionRefused)
                        } else {
                            None
                        }
                    );
                    assert_eq!(settled.permit.is_some(), refusal != Some(1));
                }
            });
            Ok(())
        });
    }
    drop(plan);
    assert_eq!(preparation_policy.live_bytes(), 0);
}

#[test]
fn vector_growth_refused_requests_keep_their_obligations_until_completion() {
    let wire = integers(23);
    let (built, accounting) =
        dcbor_test_support::construction_requests::<Vec<u64>>(&wire, None, 3, |value| {
            assert_eq!(value, &(0..23).collect::<Vec<u64>>())
        });
    assert!(
        built.built,
        "the vector did not publish after its refused requests"
    );
    accounting.request_refusals(3);
}
