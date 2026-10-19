use super::support::*;
use dcbor::bounded::resumable::{Fault, Outcome};

#[test]
fn next_unit_bounds_cover_execution_and_bound_queries_do_not_advance() {
    for wire in [
        byte_string(65536),
        text_wire("q\u{301}😀"),
        vec![0x82, 0x01, 0x02],
    ] {
        let pool = pool();
        let mut decode = decoder(&wire, &pool);
        let mut completed = false;
        for _ in 0..wire.len() * 128 + 4096 {
            let before = decode.snapshot();
            let bound = decode.next_unit().unwrap();
            assert_eq!(bound, decode.next_unit().unwrap());
            unchanged(&before, &decode.snapshot());
            let live = pool.live();
            let mut allowance = budget();
            let outcome = decode.step(&mut allowance);
            assert!(bound.work.covers(allowance.consumed()));
            assert!(pool.peak_since_checkpoint() <= live + bound.additional_peak);
            pool.checkpoint();
            match outcome {
                Outcome::Progress => {}
                Outcome::Complete(value) => {
                    drop(value);
                    completed = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(completed);
    }
}

#[test]
fn admitted_unit_finishes_when_deadline_expires_after_admission() {
    let mut decode = decoder(&[0x81, 0x01], &pool());
    let before = decode.snapshot();
    let mut allowance = budget();
    allowance.expire_after_admission();
    assert!(matches!(
        decode.step(&mut allowance),
        Outcome::Progress | Outcome::Complete(_)
    ));
    assert!(decode.snapshot().completed_units > before.completed_units);
}

#[test]
fn understated_bound_is_a_defect_not_ordinary_refusal() {
    let mut decode = decoder(&[0x81, 0x01], &pool());
    decode.inject_bound_understatement_once();
    assert!(matches!(
        decode.step(&mut budget()),
        Outcome::BoundDefect(_)
    ));
    assert!(!decode
        .events()
        .iter()
        .any(|event| event.refusal() == Some(Fault::Capacity)));
}
