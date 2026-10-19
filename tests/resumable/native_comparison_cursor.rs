use super::harness::*;
use core::cmp::Ordering;
use dcbor::bounded::decode::comparison::{ComparisonStep, KeyComparison};
use dcbor::bounded::{BoundedError, WriteWork};

#[test]
fn production_comparison_retains_exact_offsets_across_every_refusal() {
    let mut right = [b'a'; 257];
    right[256] = b'b';
    let left = [b'a'; 257];
    every_case(5, |stop| {
        let mut cursor = KeyComparison::new(&left, &right);
        let mut m = meter();
        for turn in 0..5 {
            assert_eq!(cursor.position(), turn * 64);
            let bound = cursor.next_work().unwrap();
            assert!(WriteWork::new(3, 64).covers(&bound));
            if turn == stop {
                let call = m.calls.len();
                m.fail_at = Some((call, Refusal::Work));
                assert!(matches!(
                    cursor.step(&mut m),
                    Err(BoundedError::Refused(Refusal::Work))
                ));
                assert_eq!(m.refused, Some((call, Refusal::Work)));
                assert_eq!(cursor.position(), turn * 64);
                assert_eq!(cursor.next_work(), Some(bound));
                m.fail_at = None;
                m.refused = None;
            }
            let before = (m.values, m.bytes);
            let outcome = cursor.step(&mut m).unwrap();
            assert!(bound.covers(&WriteWork::new(m.values - before.0, m.bytes - before.1)));
            if turn == 4 {
                assert_eq!(outcome, ComparisonStep::Complete(Ordering::Less));
                assert_eq!(cursor.position(), 257);
            } else {
                assert_eq!(outcome, ComparisonStep::Progress);
                assert_eq!(cursor.position(), (turn + 1) * 64);
            }
        }
        assert_eq!((m.values, m.bytes), (5, 257));
        assert_eq!(m.calls.len(), 6, "exactly one refused callback, no replay");
        assert_eq!(cursor.next_work(), None);
        let calls = m.calls.len();
        assert_eq!(cursor.step(&mut m).unwrap(), ComparisonStep::Finished);
        assert_eq!(m.calls.len(), calls);
        assert_eq!(m.pool.live(), 0);
    });
}

#[test]
fn comparison_exact_position_is_not_the_admitted_chunk_end() {
    let left = [0; 64];
    let mut right = [0; 64];
    right[3] = 1;
    let mut cursor = KeyComparison::new(&left, &right);
    let mut m = meter();
    assert_eq!(
        cursor.step(&mut m).unwrap(),
        ComparisonStep::Complete(Ordering::Less)
    );
    assert_eq!(
        cursor.position(),
        4,
        "observation must report executed comparisons"
    );
    assert_eq!(
        m.bytes, 64,
        "admission is an upper bound, not measured execution"
    );
}

#[test]
fn comparison_literal_empty_prefix_and_equal_key_cases() {
    for (left, right, expected) in [
        (&b""[..], &b""[..], Ordering::Equal),
        (&b"a"[..], &b"ab"[..], Ordering::Less),
        (&b"ab"[..], &b"a"[..], Ordering::Greater),
        (&b"abc"[..], &b"abc"[..], Ordering::Equal),
    ] {
        let mut cursor = KeyComparison::new(left, right);
        let mut m = meter();
        assert_eq!(
            cursor.step(&mut m).unwrap(),
            ComparisonStep::Complete(expected)
        );
        assert_eq!(cursor.position(), left.len().min(right.len()));
        assert_eq!(cursor.step(&mut m).unwrap(), ComparisonStep::Finished);
        assert_eq!(m.pool.live(), 0);
    }
}
