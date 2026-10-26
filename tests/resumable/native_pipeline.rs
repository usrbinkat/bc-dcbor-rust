use super::bindings::{string_decoder, text_encoder};
use super::harness::*;
use super::support::{
    Fault, allowed, drive_faulted, drive_within, pipeline::Refusal, refusal_matrix, refuse,
    rigor::rigor,
};
use dcbor::bounded::Allocator;
use dcbor::bounded::text_cursor::pipeline::{PreparedText, TextPreparation};

const SOURCE: &str = "a\u{301}";
const EXPECTED: &[u8] = &[0x62, 0xc3, 0xa1];

/// The prepared text of [`SOURCE`] and the policy holding its storage.
fn text_plan() -> (PreparedText<Reservation>, Limits) {
    let mut m = meter();
    let plan = drive_within(
        &mut m,
        &mut TextPreparation::new(SOURCE),
        normalize_turns(SOURCE),
    )
    .expect("text preparation failed");
    (plan, m)
}

/// Every refusal of preparing [`SOURCE`] resumed to a plan that owns its
/// storage beyond the preparation and emits the literal encoding, and a
/// cancellation at every call releasing the preparation's scratch.
#[test]
fn preparation_refusal_and_cancellation_preserve_literal_result_and_plan_ownership() {
    let (plan, baseline) = text_plan();
    assert_eq!(plan.len(), EXPECTED.len() as u64);
    drop(plan);
    assert_eq!(baseline.live_bytes(), 0);
    refusal_matrix("text preparation", rigor(), |fault: Fault| {
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let pool = m.share();
        let mut operation = TextPreparation::new(SOURCE);
        let turns = allowed(&m, normalize_turns(SOURCE));
        let plan = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a composing pair prepares");
        match plan {
            None => {
                drop(operation);
                assert_eq!(pool.live_bytes(), 0, "cancellation kept scratch");
            }
            Some(plan) => {
                m.assert_units(TURN);
                let retained = pool.live_bytes();
                assert!(retained > 0);
                drop(operation);
                assert_eq!(pool.live_bytes(), retained);
                let mut bytes = [0xee; 3];
                let mut emission = meter();
                drive_within(
                    &mut emission,
                    &mut plan.writer(&mut bytes),
                    text_emit_turns(EXPECTED.len()),
                )
                .expect("emission failed");
                emission.assert_units(TURN);
                assert_eq!(bytes, EXPECTED);
                assert_eq!(pool.live_bytes(), retained);
                drop(plan);
                assert_eq!(pool.live_bytes(), 0);
            }
        }
        super::support::RefusalRun::of(&m)
    });
}

/// Every refusal of emitting the plan resumed into the same guarded
/// destination without replaying its prefix, and a cancellation at every
/// call leaving exactly the literal prefix emitted so far, the guards intact
/// and the plan's storage held.
#[test]
fn emission_refusal_and_cancellation_preserve_destination_prefix_and_plan() {
    let (plan, allocator) = text_plan();
    let retained = allocator.live_bytes();
    refusal_matrix("text emission", rigor(), |fault: Fault| {
        let mut guarded = [0xee; 5];
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let mut operation = plan.writer(&mut guarded[1..4]);
        let turns = allowed(&m, text_emit_turns(EXPECTED.len()));
        let emitted = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a prepared plan emits");
        let calls = super::support::RefusalRun::of(&m);
        if emitted.is_some() {
            m.assert_units(TURN);
        }
        assert_eq!(
            allocator.live_bytes(),
            retained,
            "emission changed the plan"
        );
        // The writer's borrow of `guarded` ends here; it has no destructor.
        assert_eq!(
            (guarded[0], guarded[4]),
            (0xee, 0xee),
            "a guard was written"
        );
        let written = guarded[1..4]
            .iter()
            .take_while(|byte| **byte != 0xee)
            .count();
        assert_eq!(&guarded[1..1 + written], &EXPECTED[..written]);
        assert!(guarded[1 + written..4].iter().all(|byte| *byte == 0xee));
        if emitted.is_some() {
            assert_eq!(written, EXPECTED.len(), "a completed emission is partial");
        }
        calls
    });
    drop(plan);
    assert_eq!(allocator.live_bytes(), 0);
}

/// Every refusal of encoding [`SOURCE`], resumed or cancelled, beside an
/// independent output of the same pool: the output's storage is untouched
/// by the second encoding's suspension, resumption or cancellation.
#[test]
fn every_encoding_refusal_leaves_an_independent_output_untouched() {
    refusal_matrix("text encoding beside an output", rigor(), |fault: Fault| {
        let pool = meter();
        let output = drive_within(
            &mut pool.share(),
            &mut text_encoder(SOURCE),
            normalize_turns(SOURCE),
        )
        .unwrap();
        let retained = pool.live_bytes();
        assert!(retained >= EXPECTED.len() as u64);
        let mut m = pool.share();
        refuse(&mut m, fault.refusal);
        let mut operation = text_encoder(SOURCE);
        let turns = allowed(&m, normalize_turns(SOURCE));
        let second = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a composing pair encodes");
        assert!(pool.live_bytes() >= retained);
        drop(operation);
        if let Some(second) = second {
            assert_eq!(second.as_ref(), EXPECTED);
            drop(second);
        }
        assert_eq!(
            pool.live_bytes(),
            retained,
            "the independent output changed"
        );
        assert_eq!(output.as_ref(), EXPECTED);
        drop(output);
        assert_eq!(pool.live_bytes(), 0);
        super::support::RefusalRun::of(&m)
    });
}

// Ownership transitions and exact final reacquisition follow merge/split and
// stress_test in tokio/tests/sync_semaphore_owned.rs. Workers use real dCBOR
// calls and independently observed suspension; no worker simulates a result.
#[test]
fn concurrent_suspended_constructors_recover_exact_shared_capacity() {
    let capacity = 32 * 1024 * 1024;
    let mut pool = meter_with(capacity);
    let mut baseline = meter();
    drop(
        drive_within(
            &mut baseline,
            &mut string_decoder(EXPECTED),
            string_turns(EXPECTED.len()),
        )
        .unwrap(),
    );
    let boundaries = baseline.calls().len();
    // Every refused call is suspended and resumed the same number of times,
    // in rounds over all of them, about a thousand continuations in all; the
    // cases are dealt to the workers in turn.
    const WORKERS: usize = 8;
    const CONTINUATIONS: usize = 1000;
    let rounds = CONTINUATIONS.div_ceil(boundaries);
    let cases: Vec<usize> = (0..rounds).flat_map(|_| 0..boundaries).collect();
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..WORKERS {
            let shared = pool.share();
            let baseline = &baseline;
            let mine: Vec<usize> = cases
                .iter()
                .copied()
                .skip(worker)
                .step_by(WORKERS)
                .collect();
            handles.push(scope.spawn(move || {
                every_fixture(mine.len(), |case| {
                    let stop = mine[case];
                    let mut m = shared.share();
                    refuse(&mut m, Refusal::For(stop, LimitRefusal::Work));
                    let mut operation = string_decoder(EXPECTED);
                    let output = drive_within(&mut m, &mut operation, string_turns(EXPECTED.len()))
                        .expect("suspended construction failed");
                    super::support::RefusalRun::of(&m).resumed(
                        &super::support::RefusalRun::of(baseline),
                        stop,
                        LimitRefusal::Work,
                    );
                    assert_eq!(m.used(), baseline.used());
                    m.assert_units(TURN);
                    assert_eq!(output.value(), "\u{e1}");
                    drop(operation);
                    assert_eq!(output.value(), "\u{e1}");
                    drop(output);
                });
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(capacity).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
    assert_eq!(pool.live_bytes(), 0);
    assert!(
        outcomes.iter().all(Result::is_ok),
        "one or more continuation workers failed"
    );
}
