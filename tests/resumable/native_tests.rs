use super::bindings::{decoder, text_encoder};
use super::harness::*;
use super::support::{self, contracted, drive_within, expect_progress};
use dcbor::bounded::decode::{DecodeError, Kind, decode, decode_typed};
use dcbor::bounded::{Allocator, BoundedError, WriteWork, encode};

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
    assert!(m.live_bytes() > 0);
    drop(doc);
    assert_eq!(m.live_bytes(), 0);
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
    // Synchronous decode stops at the first refusal; identical allowance
    // makes the exact attempted prefix its contract, with no resumption.
    support::synchronous_matrix("literal array decode", baseline.attempts(), |index| {
        let call = &baseline.calls()[index];
        let reason = match call {
            Call::Work { .. } => LimitRefusal::Work,
            Call::Allocate(_) => LimitRefusal::Storage,
        };
        let mut m = meter();
        support::refuse(&mut m, support::pipeline::Refusal::For(index, reason));
        let result = decode(ARRAY, 8, &mut m);
        assert!(
            matches!(result, Err(DecodeError::Resource(BoundedError::Refused(r))) if r == reason)
        );
        assert_eq!(m.first_refusal(), Some((index, reason)));
        assert_eq!(m.calls(), &baseline.calls()[..=index]);
        drop(result);
        assert_eq!(m.live_bytes(), 0);
    });
}

#[test]
fn decoder_continuation_retains_completed_arena_on_work_refusal() {
    let mut m = meter();
    let pool = m.share();
    let mut operation = decoder(ARRAY);
    let mut reached = false;
    for _ in 0..decode_turns(ARRAY.len()) {
        if operation.position().completed_children == 1 {
            reached = true;
            break;
        }
        expect_progress(contracted(&mut m, &mut operation));
    }
    assert!(reached);
    let position = operation.position();
    let held = pool.live_bytes();
    assert!(held > 0);
    support::repeated_refusal(
        "decoder retains first completed child",
        &mut m,
        position,
        3,
        |m| {
            let result = contracted(m, &mut operation).map(|_| ());
            (operation.position(), result)
        },
    );
    assert_eq!(operation.position(), position);
    assert_eq!(pool.live_bytes(), held);
    let document = drive_within(&mut m, &mut operation, decode_turns(ARRAY.len()))
        .expect("resumed decode failed");
    assert_eq!(document.root().encoded(), ARRAY);
    drop(operation);
    drop(document);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn decoder_payload_operations_fit_three_value_sixty_four_byte_quantum() {
    let wire = text_wire(&"x".repeat(65536));
    let mut m = meter();
    let doc = drive_within(&mut m, &mut decoder(&wire), decode_turns(wire.len())).unwrap();
    assert_eq!(doc.root().encoded(), wire);
    m.assert_units(TURN);
    drop(doc);
    assert_eq!(m.live_bytes(), 0);
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
    let mut m = meter();
    let doc = drive_within(&mut m, &mut decoder(&wire), decode_turns(wire.len())).unwrap();
    assert_eq!(doc.root().kind(), Kind::Map(2));
    assert_eq!(doc.root().encoded(), wire);
    m.assert_units(TURN);
    drop(doc);
    assert_eq!(m.live_bytes(), 0);
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
        assert_eq!(m.live_bytes(), 0);
        if source != canonical {
            assert!(decode(&text_wire(source), 8, &mut meter()).is_err());
        }
        support::synchronous_matrix(
            &format!("literal text encode of {source:?}"),
            baseline.attempts(),
            |index| {
                let call = &baseline.calls()[index];
                let reason = match call {
                    Call::Work { .. } => LimitRefusal::Work,
                    Call::Allocate(_) => LimitRefusal::Storage,
                };
                let mut m = meter();
                support::refuse(&mut m, support::pipeline::Refusal::For(index, reason));
                assert!(
                    matches!(encode(&source, &mut m), Err(BoundedError::Refused(r)) if r == reason)
                );
                assert_eq!(m.first_refusal(), Some((index, reason)));
                assert_eq!(m.live_bytes(), 0);
            },
        );
        drop(encoded);
        assert_eq!(baseline.live_bytes(), 0);
    }
}

#[test]
fn long_normalization_has_bounded_preparation_and_emission_units() {
    let input = format!("q{}", "\u{301}\u{316}".repeat(4096));
    let normal = format!("q{}{}", "\u{316}".repeat(4096), "\u{301}".repeat(4096));
    let mut m = meter();
    let output = drive_within(&mut m, &mut text_encoder(&input), normalize_turns(&input)).unwrap();
    assert_eq!(output.as_ref(), text_wire(&normal));
    m.assert_units(TURN);
    drop(output);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn typed_output_owns_capacity_after_parser_scratch_release() {
    let text = "\u{1f600}\u{e9}".repeat(1024);
    let wire = text_wire(&text);
    let mut m = meter();
    let value = decode_typed::<String, _>(&wire, 8, &mut m).unwrap();
    assert_eq!(value.value(), &text);
    assert!(m.live_bytes() >= text.len() as u64);
    assert!(m.peak_bytes() >= m.live_bytes());
    let pool = m.share();
    drop(m);
    drop(wire);
    assert_eq!(value.value(), &text);
    assert!(pool.live_bytes() >= text.len() as u64);
    drop(value);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn typed_field_copies_have_bounded_units() {
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::TypedDecoder;
    let text = "\u{1f600}\u{e9}".repeat(1024);
    let wire = text_wire(&text);
    let mut m = meter();
    let (mut owner, input) = support::open(&mut m, &wire);
    let mut decoder = TypedDecoder::<_, String, Limits>::new(input, Options::normalizing(8));
    let value = drive_within(&mut m, &mut decoder, typed_turns::<String>(wire.len()))
        .expect("bounded field copy failed");
    support::exhausted(&mut m, &mut decoder);
    assert_eq!(value.value(), &text);
    m.assert_units(TURN);
    drop(value);
    drop(decoder);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn shared_pool_thousand_real_decodes_restore_exact_capacity() {
    let capacity = 32 * 1024 * 1024;
    let mut pool = meter_with(capacity);
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let shared = pool.share();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..125 {
                    let mut m = shared.share();
                    let result = decode_typed::<Vec<String>, _>(ARRAY, 8, &mut m).unwrap();
                    assert_eq!(result.value(), &["abc", "123", "hello"]);
                    drop(result);
                }
            });
        }
    });
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(capacity).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn real_capacity_exhaustion_is_distinct_from_work_and_invalid_input() {
    let mut pool = meter_with(4096);
    let held = pool.allocate(4096).unwrap();
    let mut m = pool.share();
    assert!(matches!(
        decode(ARRAY, 8, &mut m),
        Err(DecodeError::Resource(BoundedError::Refused(
            LimitRefusal::Storage
        )))
    ));
    assert_eq!(pool.live_bytes(), 4096);
    drop(held);
    assert_eq!(pool.live_bytes(), 0);
    let mut m = pool.share();
    m.set_limit(WriteWork::new(0, u64::MAX));
    assert!(matches!(
        decode(ARRAY, 8, &mut m),
        Err(DecodeError::Resource(BoundedError::Refused(
            LimitRefusal::Work
        )))
    ));
    assert_eq!(m.used().values, 0);
    assert_eq!(pool.live_bytes(), 0);
}
