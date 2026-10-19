use super::support::*;
use dcbor::bounded::resumable::{Encode, Fault, Outcome, Value};

#[test]
fn normalized_emission_matches_literal_wire_under_every_refusal() {
    let value = Value::Text("e\u{301}".into());
    let expected = [0x62, 0xc3, 0xa9];
    let mut baseline = Encode::new(value.clone(), pool());
    let mut boundaries = None;
    for _ in 0..4096 {
        match baseline.step(&mut budget()) {
            Outcome::Progress => {}
            Outcome::Complete(bytes) => {
                assert_eq!(bytes.as_ref(), expected);
                boundaries = Some(baseline.snapshot().admission_points);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    for fault in [Fault::Work, Fault::Capacity] {
        for index in 0..boundaries.expect("encoder stalled") {
            let pool = pool();
            let mut encode = Encode::new(value.clone(), pool.clone());
            encode.inject_once(index, fault);
            let mut fired = false;
            let mut completed = false;
            let mut prefix = Vec::new();
            for _ in 0..4096 {
                match encode.step(&mut budget()) {
                    Outcome::Progress => {}
                    Outcome::Refused(reason) => {
                        assert_eq!(reason, fault);
                        assert!(!fired);
                        fired = true;
                    }
                    Outcome::Complete(bytes) => {
                        assert!(fired);
                        assert_eq!(bytes.as_ref(), expected);
                        completed = true;
                        drop(bytes);
                        break;
                    }
                    other => panic!("{other:?}"),
                }
                let current = encode.emitted_prefix();
                assert!(current.starts_with(&prefix), "previous output rewritten");
                assert!(
                    expected.starts_with(current),
                    "incorrect or duplicate emission"
                );
                prefix = current.to_vec();
            }
            assert!(completed);
            assert_no_replay(encode.events());
            drop(encode);
            assert_eq!(pool.live(), 0);
        }
    }
}

#[test]
fn large_emission_keeps_each_call_within_quantum_and_output_owned() {
    let expected = byte_string(65536);
    let pool = pool();
    let mut encode = Encode::new(Value::Bytes(expected[5..].to_vec()), pool.clone());
    for _ in 0..expected.len() * 128 {
        let mut allowance = budget();
        match encode.step(&mut allowance) {
            Outcome::Progress => {}
            Outcome::Complete(bytes) => {
                assert_eq!(bytes.as_ref(), expected);
                assert!(allowance.consumed().within(allowance.limits()));
                drop(encode);
                assert!(pool.live() >= expected.len() as u64);
                drop(bytes);
                assert_eq!(pool.live(), 0);
                return;
            }
            other => panic!("{other:?}"),
        }
        assert!(allowance.consumed().within(allowance.limits()));
    }
    panic!("large emission stalled");
}
