//! Whole text pipeline qualification, including preparation and cancellation.
use super::support::*;
use dcbor::bounded::resumable::{Encode, Fault, Outcome, Value};

fn encode_checked(source: &str, expected: &[u8], cancel_after: Option<u64>) -> u64 {
    let pool = pool();
    let mut encode = Encode::new(Value::Text(source.into()), pool.clone());
    let mut prefix = Vec::new();
    let mut output = None;
    let mut steps = 0;
    let mut completed = false;
    for _ in 0..source.len() * 256 + 8192 {
        if cancel_after == Some(steps) {
            break;
        }
        let before = encode.snapshot();
        let bound = encode.next_unit().unwrap();
        let mut allowance = budget();
        let outcome = encode.step(&mut allowance);
        steps += 1;
        assert!(allowance.consumed().within(allowance.limits()));
        assert!(bound.work.covers(allowance.consumed()));
        assert!(pool.live() <= pool.capacity());
        match outcome {
            Outcome::Progress => {
                assert!(encode.snapshot().completed_units > before.completed_units)
            }
            Outcome::Complete(bytes) => {
                assert_eq!(bytes.as_ref(), expected);
                output = Some(bytes);
                completed = true;
                break;
            }
            other => panic!("{other:?}; {:?}", encode.events()),
        }
        let emitted = encode.emitted_prefix();
        assert!(emitted.starts_with(&prefix));
        assert!(expected.starts_with(emitted));
        prefix = emitted.to_vec();
    }
    if cancel_after.is_none() {
        assert!(completed, "{:?}", encode.events());
    } else {
        assert_eq!(Some(steps), cancel_after);
    }
    if steps > 0 {
        assert_no_replay(encode.events());
    }
    drop(encode);
    if output.is_some() {
        assert!(pool.live() >= expected.len() as u64);
    }
    drop(output);
    assert_eq!(pool.live(), 0);
    steps
}

#[test]
fn normalization_preparation_and_emission_can_be_cancelled_at_every_step() {
    let source = "a\u{300}\u{305}\u{315}\u{5ae}b";
    let expected = [0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'];
    let steps = encode_checked(source, &expected, None);
    assert!(steps > 1);
    for stop in 0..steps {
        encode_checked(source, &expected, Some(stop));
    }
}

#[test]
fn long_disordered_combining_run_prepares_and_emits_under_small_allowances() {
    // q composes with neither mark. Stable canonical ordering places all
    // class-220 marks before all class-230 marks. No encoder builds the oracle.
    let source = format!("q{}", "\u{301}\u{316}".repeat(4096));
    let normal = format!("q{}{}", "\u{316}".repeat(4096), "\u{301}".repeat(4096));
    let expected = text_wire(&normal);
    encode_checked(&source, &expected, None);
    let mut decode = decoder(&expected, &pool());
    assert_eq!(finish(&mut decode), Value::Text(normal));
    assert_invalid(&text_wire(&source));
}

#[test]
fn quick_only_rejection_does_not_silently_normalize_or_publish() {
    use dcbor::bounded::resumable::{Decode, Policy};
    for (text, accepted) in [
        ("ordinary ASCII", true),
        ("é", true),
        ("q\u{301}", false),
        ("e\u{301}", false),
    ] {
        let pool = pool();
        let mut decode = Decode::new(
            text_wire(text).into_boxed_slice(),
            Policy::quick_only().max_depth(64),
            pool.clone(),
        )
        .unwrap();
        let mut terminated = false;
        let mut output = None;
        for _ in 0..8192 {
            let before = decode.snapshot();
            let mut allowance = budget();
            let outcome = decode.step(&mut allowance);
            assert!(allowance.consumed().within(allowance.limits()));
            match outcome {
                Outcome::Progress => {
                    assert!(decode.snapshot().completed_units > before.completed_units)
                }
                Outcome::Complete(value) => {
                    assert!(accepted);
                    assert_eq!(value, Value::Text(text.into()));
                    output = Some(value);
                    terminated = true;
                    break;
                }
                Outcome::Invalid(_) => {
                    assert!(!accepted);
                    assert_eq!(decode.completion_count(), 0);
                    terminated = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(terminated);
        drop(decode);
        drop(output);
        assert_eq!(pool.live(), 0);
    }
}

#[test]
fn canonical_decoder_rejects_late_text_error_after_observed_suspension() {
    use dcbor::bounded::resumable::StopPoint;
    let invalid = text_wire(&format!("q{}\u{316}", "\u{301}".repeat(128)));
    let pool = pool();
    let mut decode = decoder(&invalid, &pool);
    decode.refuse_at_position(StopPoint::PayloadByte(63), Fault::Work, 1);
    let mut fired = false;
    let mut rejected = false;
    for _ in 0..invalid.len() * 128 + 4096 {
        let before = decode.snapshot();
        let mut allowance = budget();
        let outcome = decode.step(&mut allowance);
        assert!(allowance.consumed().within(allowance.limits()));
        match outcome {
            Outcome::Progress => {
                assert!(decode.snapshot().completed_units > before.completed_units)
            }
            Outcome::Refused(Fault::Work) => {
                assert!(!fired);
                fired = true;
                unchanged(&before, &decode.snapshot());
            }
            Outcome::Invalid(_) => {
                assert!(fired);
                assert_eq!(decode.completion_count(), 0);
                rejected = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(rejected);
    assert_no_replay(decode.events());
    drop(decode);
    assert_eq!(pool.live(), 0);
}
