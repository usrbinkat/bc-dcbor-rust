//! Explicit script positions are semantic byte ranges, independent of parser
//! representation. These tests require real budget/capacity interception.
use super::support::*;
use dcbor::bounded::resumable::{Budget, Fault, Limits, Outcome, StopPoint, Value};

#[test]
fn payload_and_key_offsets_survive_repeated_refusals_without_replay() {
    let key_a = "a".repeat(256);
    let key_b = format!("{}b", "a".repeat(255));
    let text = "😀".repeat(128);
    let mut wire = vec![0xa2];
    wire.extend(text_wire(&key_a));
    wire.extend(text_wire(&text));
    wire.extend(text_wire(&key_b));
    wire.push(0x01);
    let expected = Value::Map(vec![
        (Value::Text(key_a), Value::Text(text)),
        (Value::Text(key_b), Value::Unsigned(1)),
    ]);
    // Offsets within payload validation and comparison, including the final
    // byte. Text offsets deliberately include positions inside UTF-8 scalars.
    for point in [
        StopPoint::PayloadByte(1),
        StopPoint::PayloadByte(3),
        StopPoint::PayloadByte(63),
        StopPoint::PayloadByte(127),
        StopPoint::KeyByte(1),
        StopPoint::KeyByte(63),
        StopPoint::KeyByte(255),
    ] {
        for fault in [Fault::Work, Fault::Capacity] {
            let pool = pool();
            let mut decode = decoder(&wire, &pool);
            decode.refuse_at_position(point, fault, 3);
            let mut fired = 0;
            let mut stopped = None;
            let mut result = None;
            for _ in 0..wire.len() * 128 + 4096 {
                let before = decode.snapshot();
                let bound = decode.next_unit().unwrap();
                let mut allowance = budget();
                let outcome = decode.step(&mut allowance);
                assert!(allowance.consumed().within(allowance.limits()));
                assert!(bound.work.covers(allowance.consumed()));
                assert!(pool.live() <= pool.capacity());
                match outcome {
                    Outcome::Progress => {
                        assert!(decode.snapshot().completed_units > before.completed_units)
                    }
                    Outcome::Refused(reason) => {
                        assert_eq!(reason, fault);
                        assert_eq!(decode.refused_position(), Some(point));
                        unchanged(&before, &decode.snapshot());
                        if let Some(previous) = &stopped {
                            unchanged(previous, &before);
                        }
                        stopped = Some(before);
                        fired += 1;
                        assert!(fired <= 3);
                        assert!(result.is_none());
                    }
                    Outcome::Complete(value) => {
                        assert_eq!(fired, 3);
                        assert_eq!(value, expected);
                        result = Some(value);
                        break;
                    }
                    other => panic!("{point:?}: {other:?}; {:?}", decode.events()),
                }
            }
            assert!(
                result.is_some(),
                "stalled at {point:?}: {:?}",
                decode.events()
            );
            assert_no_replay(decode.events());
            drop(decode);
            assert!(pool.live() > 0);
            drop(result);
            assert_eq!(pool.live(), 0);
        }
    }
}

#[test]
fn ordered_children_are_completed_once_and_trailing_item_never_publishes() {
    // Literal array of three strings, analogous to Tokio's three frame oracle.
    let wire = [
        0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x65, b'h', b'e', b'l', b'l', b'o',
    ];
    let expected = Value::Array(vec![
        Value::Text("abc".into()),
        Value::Text("123".into()),
        Value::Text("hello".into()),
    ]);
    for trailing in [false, true] {
        for child in 0..3 {
            let mut input = wire.to_vec();
            if trailing {
                input.push(0x00);
            }
            let pool = pool();
            let mut decode = decoder(&input, &pool);
            let point = StopPoint::ChildCompletion(child);
            decode.refuse_at_position(point, Fault::Work, 1);
            let mut fired = false;
            let mut terminated = false;
            for _ in 0..8192 {
                let before = decode.snapshot();
                let mut allowance = budget();
                match decode.step(&mut allowance) {
                    Outcome::Progress => {
                        assert!(decode.snapshot().completed_units > before.completed_units)
                    }
                    Outcome::Refused(Fault::Work) => {
                        assert!(!fired);
                        fired = true;
                        assert_eq!(decode.refused_position(), Some(point));
                        unchanged(&before, &decode.snapshot());
                    }
                    Outcome::Complete(value) => {
                        assert!(!trailing, "published before checking trailing bytes");
                        assert!(fired);
                        assert_eq!(value, expected);
                        drop(value);
                        terminated = true;
                        break;
                    }
                    Outcome::Invalid(_) => {
                        assert!(trailing);
                        assert!(fired);
                        assert_eq!(decode.completion_count(), 0);
                        terminated = true;
                        break;
                    }
                    other => panic!("{other:?}"),
                }
                assert!(allowance.consumed().within(allowance.limits()));
            }
            assert!(terminated, "{:?}", decode.events());
            assert_no_replay(decode.events());
            drop(decode);
            assert_eq!(pool.live(), 0);
        }
    }
}

#[test]
fn capacity_refusal_preserves_a_partial_cursor_until_another_thread_releases() {
    let pool = pool();
    let capacity = pool.available();
    let wire = byte_string(65536);
    let mut decode = decoder(&wire, &pool);
    // Reach a real allocation boundary after useful work, then exhaust capacity
    // externally. Unlike synthetic injection this exercises actual contention.
    let mut reached = false;
    for _ in 0..8192 {
        if decode.next_unit().unwrap().additional_peak > 0 && decode.snapshot().completed_units > 0
        {
            reached = true;
            break;
        }
        assert!(matches!(decode.step(&mut budget()), Outcome::Progress));
    }
    assert!(reached);
    let retained = pool.live();
    let blocker = pool.reserve(pool.available()).unwrap();
    let (release, wait) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        wait.recv().unwrap();
        drop(blocker);
    });
    let before = decode.snapshot();
    for _ in 0..3 {
        let mut allowance = budget();
        assert!(matches!(
            decode.step(&mut allowance),
            Outcome::Refused(Fault::Capacity)
        ));
        unchanged(&before, &decode.snapshot());
        assert_eq!(pool.available(), 0);
        assert!(allowance.consumed().within(allowance.limits()));
    }
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(pool.live(), retained);
    let result = finish(&mut decode);
    assert_eq!(result, Value::Bytes(wire[5..].to_vec()));
    assert_no_replay(decode.events());
    drop(decode);
    assert!(pool.live() >= 65536);
    drop(result);
    assert_eq!(pool.available(), capacity);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
}

#[test]
fn budget_schedules_do_not_change_canonical_semantics() {
    let wire = [0x83, 0x18, 0x18, 0x62, 0xc3, 0xa9, 0x42, 0x00, 0xff];
    let expected = Value::Array(vec![
        Value::Unsigned(24),
        Value::Text("é".into()),
        Value::Bytes(vec![0, 255]),
    ]);
    for seed in 0..64u64 {
        let pool = pool();
        let mut decode = decoder(&wire, &pool);
        let mut random = seed + 1;
        let mut result = None;
        for turn in 0..4096 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let zero = turn % 3 == 0;
            let mut allowance = Budget::new(if zero {
                Limits::ZERO
            } else {
                Limits {
                    values: 3 + random % 14,
                    bytes: 16 + random % 49,
                    allocated: 4096,
                }
            });
            let before = decode.snapshot();
            match decode.step(&mut allowance) {
                Outcome::Progress => {
                    assert!(!zero);
                    assert!(decode.snapshot().completed_units > before.completed_units);
                }
                Outcome::Refused(Fault::Work) => {
                    assert!(zero);
                    unchanged(&before, &decode.snapshot());
                }
                Outcome::Complete(value) => {
                    assert_eq!(value, expected);
                    result = Some(value);
                    break;
                }
                other => panic!("seed={seed}, turn={turn}: {other:?}"),
            }
            assert!(allowance.consumed().within(allowance.limits()));
        }
        assert!(result.is_some(), "seed={seed}: {:?}", decode.events());
        assert_no_replay(decode.events());
        drop(decode);
        drop(result);
        assert_eq!(pool.live(), 0);
    }
}
