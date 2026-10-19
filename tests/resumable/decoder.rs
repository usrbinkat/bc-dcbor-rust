use super::support::*;
use dcbor::bounded::resumable::{Budget, Fault, Limits, Outcome, Value};

#[test]
fn literal_values_survive_every_work_and_capacity_boundary() {
    let wire = [0xa2, 0x00, 0x83, 0x01, 0xf5, 0xf6, 0x01, 0x62, b'o', b'k'];
    let mut decode = decoder(&wire, &pool());
    assert_eq!(
        finish(&mut decode),
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::Array(vec![Value::Unsigned(1), Value::Bool(true), Value::Null])
            ),
            (Value::Unsigned(1), Value::Text("ok".into())),
        ])
    );
    refuse_each(&wire, Fault::Work);
    refuse_each(&wire, Fault::Capacity);
}

#[test]
fn zero_allowance_and_expired_deadline_do_not_advance() {
    let mut decode = decoder(&[0x81, 0x01], &pool());
    for mut allowance in [Budget::new(Limits::ZERO), Budget::expired()] {
        let before = decode.snapshot();
        assert!(matches!(decode.step(&mut allowance), Outcome::Refused(_)));
        unchanged(&before, &decode.snapshot());
        assert_eq!(allowance.consumed(), Limits::ZERO);
    }
    assert_eq!(finish(&mut decode), Value::Array(vec![Value::Unsigned(1)]));
}

#[test]
fn large_payload_and_arena_growth_complete_with_three_value_steps() {
    let wire = byte_string(65536);
    let mut decode = decoder(&wire, &pool());
    assert_eq!(finish(&mut decode), Value::Bytes(wire[5..].to_vec()));
    assert_no_replay(decode.events());
    let mut array = vec![0x99, 0x10, 0x00];
    array.extend(std::iter::repeat_n(0x01, 4096));
    let mut decode = decoder(&array, &pool());
    assert_eq!(
        finish(&mut decode),
        Value::Array(vec![Value::Unsigned(1); 4096])
    );
    assert_no_replay(decode.events());
}

#[test]
fn every_proper_prefix_and_trailing_item_is_invalid() {
    let wire = [0xa1, 0x00, 0x82, 0x18, 0x18, 0x62, b'o', b'k'];
    for end in 0..wire.len() {
        assert_invalid(&wire[..end]);
    }
    let mut trailing = wire.to_vec();
    trailing.push(0x00);
    assert_invalid(&trailing);
}

#[test]
fn malformed_heads_lengths_utf8_and_map_order_are_rejected() {
    for bytes in [
        &[0x18, 0x00][..],
        &[0x9f, 0xff],
        &[0x61, 0xff],
        &[0x62, 0xc0, 0x80],
        &[0x63, 0xed, 0xa0, 0x80],
        &[0xa2, 0x00, 0x01, 0x00, 0x02],
        &[0xa2, 0x01, 0x00, 0x00, 0x00],
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        assert_invalid(bytes);
    }
}

#[test]
fn long_common_key_prefix_is_resumable_and_order_is_enforced() {
    let first = byte_string(65536);
    let mut second = first.clone();
    *second.last_mut().unwrap() += 1;
    let make = |a: &[u8], b: &[u8]| {
        let mut wire = vec![0xa2];
        wire.extend_from_slice(a);
        wire.push(0x00);
        wire.extend_from_slice(b);
        wire.push(0x01);
        wire
    };
    let mut decode = decoder(&make(&first, &second), &pool());
    assert!(matches!(finish(&mut decode), Value::Map(_)));
    assert_no_replay(decode.events());
    assert_invalid(&make(&second, &first));
    assert_invalid(&make(&first, &first));
}
