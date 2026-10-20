use super::bindings::{decode_driver, text_driver};
use super::driver::{Step, finish};
use super::harness::*;
use dcbor::bounded::decode::{DecodeError, Kind, decode, decode_typed};
use dcbor::bounded::{BoundedError, encode};

const ARRAY: &[u8] = &[
    0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x65, b'h', b'e', b'l', b'l', b'o',
];

#[test]
fn boundary_schedules_preserve_literal_child_order_and_exact_consumption() {
    let mut m = meter();
    let doc = decode(ARRAY, 8, &mut m).unwrap();
    assert_eq!(doc.root().kind(), Kind::Array(3));
    let children: Vec<_> = doc.root().children().map(|n| n.kind()).collect();
    assert_eq!(
        children,
        [Kind::Text("abc"), Kind::Text("123"), Kind::Text("hello")]
    );
    assert_eq!(doc.root().encoded(), ARRAY);
    assert!(m.pool.live() > 0);
    drop(doc);
    assert_eq!(m.pool.live(), 0);
    for end in 0..ARRAY.len() {
        assert!(matches!(
            decode(&ARRAY[..end], 8, &mut meter()),
            Err(DecodeError::Invalid(_))
        ));
    }
    let mut trailing = ARRAY.to_vec();
    trailing.push(0);
    assert!(matches!(
        decode(&trailing, 8, &mut meter()),
        Err(DecodeError::Invalid(_))
    ));
}

#[test]
fn every_actual_admission_refusal_is_observed_and_stops_execution() {
    let mut baseline = meter();
    drop(decode(ARRAY, 8, &mut baseline).unwrap());
    for (index, call) in baseline.calls.iter().enumerate() {
        let reason = match call {
            Call::Work { .. } => Refusal::Work,
            Call::Allocate(_) => Refusal::Capacity,
        };
        let mut m = meter();
        m.fail_at = Some((index, reason));
        let result = decode(ARRAY, 8, &mut m);
        assert!(
            matches!(result, Err(DecodeError::Resource(BoundedError::Refused(r))) if r == reason)
        );
        assert_eq!(m.refused, Some((index, reason)));
        assert_eq!(m.calls, baseline.calls[..=index]);
        drop(result);
        assert_eq!(m.pool.live(), 0);
    }
}

#[test]
fn decoder_continuation_retains_completed_arena_on_work_refusal() {
    let mut operation = decode_driver(ARRAY, meter());
    let pool = operation.meter.pool.clone();
    let mut reached = false;
    for _ in 0..4096 {
        if operation.operation().position().completed_children == 1 {
            reached = true;
            break;
        }
        assert_eq!(operation.step(), Ok(Step::Progress));
    }
    assert!(reached);
    let position = operation.operation().position();
    let held = pool.live();
    assert!(held > 0);
    let stop = operation.meter.calls.len();
    operation.meter.fail_at = Some((stop, Refusal::Work));
    assert_eq!(operation.step(), Ok(Step::Refused(Refusal::Work)));
    assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
    assert_eq!(operation.operation().position(), position);
    assert_eq!(pool.live(), held);
    assert!(operation.output.is_none());
    operation.meter.fail_at = None;
    finish(&mut operation, 4096);
    assert_eq!(operation.output.as_ref().unwrap().root().encoded(), ARRAY);
    drop(operation);
    assert_eq!(pool.live(), 0);
}

#[test]
fn decoder_payload_operations_fit_three_value_sixty_four_byte_quantum() {
    let wire = text_wire(&"x".repeat(65536));
    let mut operation = decode_driver(&wire, meter());
    finish(&mut operation, wire.len() * 128 + 4096);
    let doc = operation.output.take().unwrap();
    let m = operation.meter;
    assert_eq!(doc.root().encoded(), wire);
    m.assert_units(3, 64);
    drop(doc);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn canonical_key_comparison_and_arena_growth_have_bounded_units() {
    let a = "a".repeat(4096);
    let b = format!("{}b", "a".repeat(4095));
    let mut wire = vec![0xa2];
    wire.extend(text_wire(&a));
    wire.push(0);
    wire.extend(text_wire(&b));
    wire.push(1);
    let mut operation = decode_driver(&wire, meter());
    finish(&mut operation, wire.len() * 128 + 4096);
    let doc = operation.output.take().unwrap();
    let m = operation.meter;
    assert_eq!(doc.root().kind(), Kind::Map(2));
    assert_eq!(doc.root().encoded(), wire);
    m.assert_units(3, 64);
    drop(doc);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn text_semantics_use_literal_composition_reordering_and_hangul_oracles() {
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
        let mut baseline = meter();
        let encoded = encode(&source, &mut baseline).unwrap();
        assert_eq!(encoded.as_ref(), expected);
        let canonical = std::str::from_utf8(&expected[1..]).unwrap();
        let mut m = meter();
        let doc = decode(expected, 8, &mut m).unwrap();
        assert_eq!(doc.root().kind(), Kind::Text(canonical));
        drop(doc);
        assert_eq!(m.pool.live(), 0);
        if source != canonical {
            assert!(decode(&text_wire(source), 8, &mut meter()).is_err());
        }
        for (index, call) in baseline.calls.iter().enumerate() {
            let reason = match call {
                Call::Work { .. } => Refusal::Work,
                Call::Allocate(_) => Refusal::Capacity,
            };
            let mut m = meter();
            m.fail_at = Some((index, reason));
            assert!(
                matches!(encode(&source, &mut m), Err(BoundedError::Refused(r)) if r == reason)
            );
            assert_eq!(m.refused, Some((index, reason)));
            assert_eq!(m.pool.live(), 0);
        }
        drop(encoded);
        assert_eq!(baseline.pool.live(), 0);
    }
}

#[test]
fn long_normalization_has_bounded_preparation_and_emission_units() {
    let input = format!("q{}", "\u{301}\u{316}".repeat(4096));
    let normal = format!("q{}{}", "\u{316}".repeat(4096), "\u{301}".repeat(4096));
    let mut operation = text_driver(&input, meter());
    finish(&mut operation, input.len() * input.len() + 4096);
    let output = operation.output.take().unwrap();
    let m = operation.meter;
    assert_eq!(output.as_ref(), text_wire(&normal));
    m.assert_units(3, 64);
    drop(output);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn typed_output_owns_capacity_after_parser_scratch_release() {
    let text = "😀é".repeat(1024);
    let wire = text_wire(&text);
    let mut m = meter();
    let value = decode_typed::<String, _>(&wire, 8, &mut m).unwrap();
    assert_eq!(value.value(), &text);
    assert!(m.pool.live() >= text.len() as u64);
    assert!(m.pool.peak() >= m.pool.live());
    let pool = m.pool.clone();
    drop(m);
    drop(wire);
    assert_eq!(value.value(), &text);
    assert!(pool.live() >= text.len() as u64);
    drop(value);
    assert_eq!(pool.live(), 0);
}

#[test]
fn typed_field_copies_have_bounded_units() {
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::{DecodeOwner, TypedDecoder, TypedStep};
    let text = "😀é".repeat(1024);
    let wire = text_wire(&text);
    let mut m = meter();
    let owner = DecodeOwner::new();
    let mut decoder = TypedDecoder::<String, Meter>::new(&owner, &wire, Options::normalizing(8));
    let mut value = None;
    for _ in 0..wire.len() + 4096 {
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        match decoder.step(&mut m) {
            Ok(TypedStep::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(TypedStep::Complete(output)) => {
                value = Some(output);
                break;
            }
            _ => panic!("bounded field copy failed"),
        }
    }
    let value = value.expect("bounded field copy did not complete");
    assert_eq!(value.value(), &text);
    m.assert_units(3, 64);
    drop(value);
    drop(decoder);
    super::heap::drain_decode(&owner, &mut m);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn shared_pool_thousand_real_decodes_restore_exact_capacity() {
    let capacity = 32 * 1024 * 1024;
    let pool = Pool::new(capacity);
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let pool = pool.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..125 {
                    let mut m = Meter::new(pool.clone());
                    let result = decode_typed::<Vec<String>, _>(ARRAY, 8, &mut m).unwrap();
                    assert_eq!(result.value(), &["abc", "123", "hello"]);
                    drop(result);
                }
            });
        }
    });
    assert_eq!(pool.live(), 0);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
    assert_eq!(pool.live(), 0);
}

#[test]
fn real_capacity_exhaustion_is_distinct_from_work_and_invalid_input() {
    let pool = Pool::new(4096);
    let held = pool.reserve(4096).unwrap();
    let mut m = Meter::new(pool.clone());
    assert!(matches!(
        decode(ARRAY, 8, &mut m),
        Err(DecodeError::Resource(BoundedError::Refused(
            Refusal::Capacity
        )))
    ));
    assert_eq!(pool.live(), 4096);
    drop(held);
    assert_eq!(pool.live(), 0);
    let mut m = Meter::new(pool.clone());
    m.limit_values = 0;
    assert!(matches!(
        decode(ARRAY, 8, &mut m),
        Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
    ));
    assert_eq!(m.values, 0);
    assert_eq!(pool.live(), 0);
}
