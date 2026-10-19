//! Cumulative contracts at observable semantic boundaries, not private states.
use super::support::*;
use dcbor::bounded::resumable::{Boundary, Encode, Fault, Outcome, Value};

fn limits(values: u64, bytes: u64) -> dcbor::bounded::resumable::Budget {
    dcbor::bounded::resumable::Budget::new(dcbor::bounded::resumable::Limits {
        values,
        bytes,
        allocated: 4096,
    })
}

fn literal() -> (Vec<u8>, Value) {
    // Two keys share a prefix. Text includes a four-byte UTF-8 scalar.
    (
        vec![
            0xa2, 0x62, b'a', b'a', 0x65, b'x', 0xf0, 0x9f, 0x98, 0x80, 0x62, b'a', b'b', 0x82,
            0x01, 0x02,
        ],
        Value::Map(vec![
            (Value::Text("aa".into()), Value::Text("x😀".into())),
            (
                Value::Text("ab".into()),
                Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
            ),
        ]),
    )
}

#[test]
fn named_boundary_schedules_preserve_exact_positions_and_never_publish_early() {
    let (wire, expected) = literal();
    for boundary in [
        Boundary::BeforeHead,
        Boundary::AfterHead,
        Boundary::PayloadValidation,
        Boundary::KeyComparison,
        Boundary::ContainerCompletion,
    ] {
        for fault in [Fault::Work, Fault::Capacity] {
            for (values, bytes) in [(3, 16), (8, 32), (16, 64)] {
                let pool = pool();
                let mut decode = decoder(&wire, &pool);
                decode.refuse_at_boundary_once(boundary, fault);
                let mut fired = false;
                let mut output = None;
                for _ in 0..8192 {
                    let before = decode.snapshot();
                    let bound = decode.next_unit().unwrap();
                    let mut allowance = limits(values, bytes);
                    let result = decode.step(&mut allowance);
                    assert!(allowance.consumed().within(allowance.limits()));
                    assert!(bound.work.covers(allowance.consumed()));
                    assert!(pool.live() <= pool.capacity());
                    match result {
                        Outcome::Progress => {
                            assert!(decode.snapshot().completed_units > before.completed_units)
                        }
                        Outcome::Refused(reason) => {
                            assert_eq!(reason, fault);
                            assert!(!fired, "target fired more than once");
                            assert_eq!(decode.refused_boundary(), Some(boundary));
                            unchanged(&before, &decode.snapshot());
                            assert!(output.is_none());
                            fired = true;
                        }
                        Outcome::Complete(value) => {
                            assert!(fired, "boundary never exercised: {boundary:?}");
                            assert_eq!(value, expected);
                            output = Some(value);
                            break;
                        }
                        other => panic!("{boundary:?}: {other:?}; {:?}", decode.events()),
                    }
                }
                assert!(output.is_some(), "schedule stalled: {:?}", decode.events());
                assert_no_replay(decode.events());
                assert_eq!(decode.completion_count(), 1);
                let before = decode.snapshot();
                assert!(matches!(decode.step(&mut budget()), Outcome::Finished));
                unchanged(&before, &decode.snapshot());
                drop(decode);
                assert!(pool.live() > 0, "output lost its reservation");
                drop(output);
                assert_eq!(pool.live(), 0);
            }
        }
    }
}

#[test]
fn multibyte_header_is_retained_before_and_after_payload_admission() {
    // Canonical 24-byte string: two-byte head followed by literal payload.
    let mut wire = vec![0x58, 0x18];
    wire.extend_from_slice(b"abcdefghijklmnopqrstuvwx");
    for boundary in [
        Boundary::BeforeHead,
        Boundary::AfterHead,
        Boundary::PayloadValidation,
    ] {
        let mut decode = decoder(&wire, &pool());
        decode.refuse_at_boundary_once(boundary, Fault::Work);
        let mut fired = false;
        let mut completed = false;
        for _ in 0..4096 {
            match decode.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::Refused(Fault::Work) => {
                    assert!(!fired);
                    fired = true;
                    assert_eq!(decode.refused_boundary(), Some(boundary));
                    let progress = decode.semantic_progress();
                    if boundary == Boundary::BeforeHead {
                        assert_eq!(progress.validated_headers, 0);
                        assert_eq!(progress.input_offset, 0);
                    } else {
                        assert_eq!(progress.validated_headers, 1);
                        assert!(progress.input_offset >= 2);
                    }
                }
                Outcome::Complete(value) => {
                    assert!(fired);
                    assert_eq!(value, Value::Bytes(b"abcdefghijklmnopqrstuvwx".to_vec()));
                    assert_eq!(decode.semantic_progress().validated_headers, 1);
                    completed = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(completed);
        assert_no_replay(decode.events());
    }
}

#[test]
fn normalization_literal_oracles_survive_every_preparation_and_emission_refusal() {
    // Literal UTF-8 and CBOR heads, not produced by the encoder under test.
    let fixtures: &[(&str, &[u8])] = &[
        ("a\u{301}", &[0x62, 0xc3, 0xa1]),
        ("\u{301}a", &[0x63, 0xcc, 0x81, b'a']),
        ("\u{1e0b}\u{323}", &[0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87]),
        (
            "a\u{300}\u{305}\u{315}\u{5ae}b",
            &[0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'],
        ),
        ("\u{1100}\u{1162}", &[0x63, 0xea, 0xb0, 0x9c]),
        ("\u{1111}\u{1171}\u{11b6}", &[0x63, 0xed, 0x93, 0x9b]),
    ];
    for &(source, expected) in fixtures {
        let mut baseline = Encode::new(Value::Text(source.into()), pool());
        let mut points = None;
        for _ in 0..8192 {
            match baseline.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::Complete(bytes) => {
                    assert_eq!(bytes.as_ref(), expected);
                    points = Some(baseline.snapshot().admission_points);
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        let points = points.expect("baseline stalled");
        assert!(points > 0);
        for quantum in [16, 32, 64] {
            for fault in [Fault::Work, Fault::Capacity] {
                for index in 0..points {
                    let pool = pool();
                    let mut encode = Encode::new(Value::Text(source.into()), pool.clone());
                    encode.inject_once(index, fault);
                    let mut fired = false;
                    let mut output = None;
                    let mut prefix = Vec::new();
                    for _ in 0..8192 {
                        let before = encode.snapshot();
                        let mut allowance = limits(3, quantum);
                        let result = encode.step(&mut allowance);
                        assert!(allowance.consumed().within(allowance.limits()));
                        match result {
                            Outcome::Progress => {
                                assert!(encode.snapshot().completed_units > before.completed_units)
                            }
                            Outcome::Refused(reason) => {
                                assert_eq!(reason, fault);
                                assert!(!fired);
                                fired = true;
                                unchanged(&before, &encode.snapshot());
                            }
                            Outcome::Complete(bytes) => {
                                assert!(fired);
                                assert_eq!(bytes.as_ref(), expected);
                                output = Some(bytes);
                                break;
                            }
                            other => panic!("{source:?}, {index}: {other:?}"),
                        }
                        let current = encode.emitted_prefix();
                        assert!(current.starts_with(&prefix));
                        assert!(expected.starts_with(current));
                        prefix = current.to_vec();
                    }
                    assert!(output.is_some());
                    assert_no_replay(encode.events());
                    drop(encode);
                    assert!(pool.live() >= expected.len() as u64);
                    drop(output);
                    assert_eq!(pool.live(), 0);
                }
            }
        }
        let text = std::str::from_utf8(&expected[1..]).unwrap();
        let mut decode = decoder(expected, &pool());
        assert_eq!(finish(&mut decode), Value::Text(text.into()));
        if source != text {
            assert_invalid(&text_wire(source));
        }
    }
}

#[test]
fn split_merge_zero_and_refused_transfer_preserve_exact_capacity() {
    let pool = pool();
    let total = pool.available();
    let mut first = pool.reserve(3).unwrap();
    assert_eq!(pool.available(), total - 3);
    let mut second = first.split(1).unwrap();
    assert_eq!(first.bytes(), 2);
    assert_eq!(second.bytes(), 1);
    assert_eq!(pool.available(), total - 3);
    let empty = first.split(0).unwrap();
    assert_eq!(empty.bytes(), 0);
    assert!(first.split(3).is_err());
    assert_eq!(first.bytes(), 2);
    assert_eq!(pool.available(), total - 3);
    first.merge(second).unwrap();
    assert_eq!(first.bytes(), 3);
    assert_eq!(pool.available(), total - 3);
    second = first.split(1).unwrap();
    drop(first);
    assert_eq!(pool.available(), total - 1);
    let last = second.split(1).unwrap();
    assert!(second.split(1).is_err());
    drop(second);
    drop(empty);
    assert_eq!(pool.available(), total - 1);
    drop(last);
    assert_eq!(pool.available(), total);
}

#[test]
fn thousand_operations_share_capacity_and_recover_exactly() {
    let pool = pool();
    let capacity = pool.available();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let pool = pool.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for iteration in 0..125 {
                    let wire = text_wire("q\u{301}😀");
                    let mut decode = decoder(&wire, &pool);
                    if (worker + iteration) % 2 == 0 {
                        // Cancellation after actual execution, not empty handles.
                        assert!(matches!(decode.step(&mut budget()), Outcome::Progress));
                    } else {
                        let value = finish(&mut decode);
                        assert_eq!(value, Value::Text("q\u{301}😀".into()));
                        assert_no_replay(decode.events());
                        drop(value);
                    }
                    drop(decode);
                    assert!(pool.live() <= pool.capacity());
                }
            });
        }
    });
    assert_eq!(pool.available(), capacity);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
    assert_eq!(pool.available(), capacity);
}

#[cfg(feature = "derive")]
#[test]
fn typed_ownership_is_accounted_at_every_transition_and_cancellation() {
    use dcbor::bounded::resumable::{Construct, OwnershipPhase};
    use dcbor::{ByteString, CBORResumableDecodable};
    #[derive(Debug, CBORResumableDecodable)]
    struct Record {
        #[cbor(n = 0)]
        bytes: ByteString,
    }
    let payload = byte_string(65536);
    let mut wire = vec![0xa1, 0x00];
    wire.extend_from_slice(&payload);
    for stop in [
        OwnershipPhase::InputRetained,
        OwnershipPhase::ParserScratch,
        OwnershipPhase::PartialField,
        OwnershipPhase::TypedOutput,
        OwnershipPhase::ScratchReleased,
    ] {
        for cancel in [false, true] {
            let pool = pool();
            let mut construction =
                Construct::<Record>::new(wire.clone().into_boxed_slice(), policy(), pool.clone())
                    .unwrap();
            construction.refuse_at_ownership_once(stop, Fault::Work);
            let mut fired = false;
            let mut completed = false;
            let mut output = None;
            for _ in 0..wire.len() * 128 + 4096 {
                let mut allowance = budget();
                let outcome = construction.step(&mut allowance);
                assert!(allowance.consumed().within(allowance.limits()));
                let ownership = construction.ownership();
                assert_eq!(pool.live(), ownership.total());
                assert!(pool.live() <= pool.capacity());
                match outcome {
                    Outcome::Progress => {}
                    Outcome::Refused(Fault::Work) => {
                        assert!(!fired);
                        fired = true;
                        assert_eq!(construction.refused_ownership(), Some(stop));
                        match stop {
                            OwnershipPhase::InputRetained => {
                                assert!(ownership.input >= wire.len() as u64)
                            }
                            OwnershipPhase::ParserScratch => assert!(ownership.scratch > 0),
                            OwnershipPhase::PartialField => assert!(ownership.partial > 0),
                            OwnershipPhase::TypedOutput => assert!(ownership.output >= 65536),
                            OwnershipPhase::ScratchReleased => {
                                assert_eq!(ownership.scratch, 0);
                                assert_eq!(ownership.partial, 0);
                                assert!(ownership.output >= 65536);
                            }
                        }
                        if cancel {
                            break;
                        }
                    }
                    Outcome::Complete(value) => {
                        assert!(fired);
                        assert_eq!(value.value().bytes.as_ref(), &payload[5..]);
                        assert_no_replay(construction.events());
                        let retained = value.retained_bytes();
                        assert!(retained >= 65536);
                        output = Some(value);
                        completed = true;
                        break;
                    }
                    other => panic!("{stop:?}: {other:?}"),
                }
            }
            assert!(fired, "ownership transition was not exercised: {stop:?}");
            assert_eq!(completed, !cancel);
            drop(construction);
            if let Some(value) = output {
                assert_eq!(pool.live(), value.retained_bytes());
                assert_eq!(value.value().bytes.as_ref(), &payload[5..]);
                drop(value);
            }
            assert_eq!(pool.live(), 0, "leaked at {stop:?}, cancellation={cancel}");
        }
    }
}
