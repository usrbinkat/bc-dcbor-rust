use super::harness::*;
use super::support::{Fault, contracted, exhausted, refusal_matrix, refuse, rigor::rigor};
use core::cmp::Ordering;
use dcbor::bounded::decode::comparison::KeyComparison;
use dcbor::bounded::{Failure, Step, WriteWork};

/// Every refusal of comparing two 257-byte keys that differ in their last
/// byte, resumed and cancelled, with the cursor's exact per-turn oracles:
/// each unit within its announced bound and a quantum, the position at a
/// multiple of 64 until the last unit, a refused unit moving nothing.
#[test]
fn production_comparison_retains_exact_offsets_across_every_refusal() {
    let mut right = [b'a'; 257];
    right[256] = b'b';
    let left = [b'a'; 257];
    let baseline = refusal_matrix("key comparison", rigor(), |fault: Fault| {
        let mut cursor = KeyComparison::new(&left, &right);
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let mut turn = 0;
        // Five units, each possibly refused once.
        for _ in 0..11 {
            m.turn();
            assert_eq!(cursor.position(), turn * 64);
            let bound = cursor.next_work().expect("a unit remains");
            assert!(TURN.covers(&bound));
            let before = m.used();
            match contracted(&mut m, &mut cursor) {
                Err(error) if error.refused() => {
                    assert_eq!(cursor.position(), turn * 64);
                    assert_eq!(cursor.next_work(), Some(bound));
                    if fault.cancel && m.injected_refusals() > 0 {
                        return super::support::RefusalRun::of(&m);
                    }
                }
                Ok(outcome) => {
                    let after = m.used();
                    assert!(bound.covers(&WriteWork::new(
                        after.values - before.values,
                        after.bytes - before.bytes
                    )));
                    if turn == 4 {
                        assert_eq!(outcome, Step::Complete(Ordering::Less));
                        assert_eq!(cursor.position(), 257);
                        assert_eq!(m.used(), WriteWork::new(5, 257));
                        assert_eq!(cursor.next_work(), None);
                        exhausted(&mut m, &mut cursor);
                        assert_eq!(m.live_bytes(), 0);
                        return super::support::RefusalRun::of(&m);
                    }
                    assert_eq!(outcome, Step::Progress);
                    turn += 1;
                    assert_eq!(cursor.position(), turn * 64);
                }
                Err(error) => panic!("comparison failed: {error:?}"),
            }
        }
        panic!("the comparison exceeded its five units");
    });
    assert_eq!(
        baseline.calls().len(),
        5,
        "one unit per 64 bytes, the last partial"
    );
}

#[test]
fn comparison_exact_position_is_not_the_admitted_chunk_end() {
    let left = [0; 64];
    let mut right = [0; 64];
    right[3] = 1;
    let mut cursor = KeyComparison::new(&left, &right);
    let mut m = meter();
    assert_eq!(
        contracted(&mut m, &mut cursor).unwrap(),
        Step::Complete(Ordering::Less)
    );
    assert_eq!(
        cursor.position(),
        4,
        "observation must report executed comparisons"
    );
    assert_eq!(
        m.used().bytes,
        64,
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
            contracted(&mut m, &mut cursor).unwrap(),
            Step::Complete(expected)
        );
        assert_eq!(cursor.position(), left.len().min(right.len()));
        exhausted(&mut m, &mut cursor);
        assert_eq!(m.live_bytes(), 0);
    }
}
