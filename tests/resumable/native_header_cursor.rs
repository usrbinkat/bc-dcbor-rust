use super::harness::*;
use dcbor::bounded::decode::{
    DecodeError,
    header::{HeaderCursor, HeaderStep},
};
use dcbor::bounded::{BoundedError, WriteWork};

// RocksDB db/log_test.cc NonBlockingReadFullRecord and TailLog_PartialHeader:
// exercise the retained reader, positively observe the interruption, then
// require literal completion. Here complete input stays immutably borrowed.
#[test]
fn production_header_cursor_retains_each_byte_before_and_after_refusal() {
    let wire = [0x1b, 0, 0, 0, 1, 0, 0, 0, 0];
    every_case(10, |stop| {
        let mut cursor = HeaderCursor::new(&wire);
        let mut m = meter();
        for turn in 0..10 {
            assert_eq!(cursor.acquired(), turn.min(9));
            let bound = cursor.next_work().unwrap();
            assert!(WriteWork::new(3, 64).covers(&bound));
            if turn == stop {
                let call = m.calls.len();
                m.fail_at = Some((call, Refusal::Work));
                assert!(matches!(
                    cursor.step(&mut m),
                    Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
                ));
                assert_eq!(m.refused, Some((call, Refusal::Work)));
                assert_eq!(cursor.acquired(), turn.min(9));
                assert_eq!(cursor.next_work(), Some(bound));
                m.fail_at = None;
                m.refused = None;
            }
            let outcome = cursor.step(&mut m).unwrap();
            if turn < 9 {
                assert_eq!(outcome, HeaderStep::Progress);
                assert_eq!(cursor.acquired(), turn + 1);
            } else {
                let HeaderStep::Complete(header) = outcome else {
                    panic!("header not completed");
                };
                assert_eq!(header.argument, 4_294_967_296);
                assert_eq!(header.length, 9);
            }
        }
        assert_eq!((m.values, m.bytes), (10, 18));
        assert_eq!(m.calls.len(), 11);
        assert_eq!(cursor.next_work(), None);
        assert_eq!(cursor.step(&mut m).unwrap(), HeaderStep::Finished);
        assert_eq!(m.calls.len(), 11);
        assert_eq!(m.pool.live(), 0);
    });
}

#[test]
fn retained_header_rejects_truncation_after_observed_refusal() {
    let complete = [0x1b, 0, 0, 0, 1, 0, 0, 0, 0];
    every_case(complete.len(), |end| {
        let mut cursor = HeaderCursor::new(&complete[..end]);
        let mut m = meter();
        for position in 0..end {
            assert_eq!(cursor.step(&mut m).unwrap(), HeaderStep::Progress);
            assert_eq!(cursor.acquired(), position + 1);
        }
        let stop = m.calls.len();
        m.fail_at = Some((stop, Refusal::Work));
        assert!(matches!(
            cursor.step(&mut m),
            Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
        ));
        assert_eq!(m.refused, Some((stop, Refusal::Work)));
        assert_eq!(cursor.acquired(), end);
        m.fail_at = None;
        m.refused = None;
        assert!(matches!(cursor.step(&mut m), Err(DecodeError::Invalid(_))));
        assert_eq!(cursor.acquired(), end);
        assert_eq!(cursor.step(&mut m).unwrap(), HeaderStep::Finished);
        assert_eq!(m.pool.live(), 0);
    });
}

#[test]
fn retained_header_never_publishes_nonminimal_or_reserved_encodings() {
    let invalid: &[&[u8]] = &[
        &[0x18, 0x17],
        &[0x19, 0, 0xff],
        &[0x1a, 0, 0, 0xff, 0xff],
        &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[0x1c],
        &[0x1d],
        &[0x1e],
        &[0x1f],
    ];
    every_case(invalid.len(), |fixture| {
        let wire = invalid[fixture];
        every_case(wire.len() + 1, |stop| {
            let mut cursor = HeaderCursor::new(wire);
            let mut m = meter();
            for turn in 0..=wire.len() {
                if turn == stop {
                    let call = m.calls.len();
                    m.fail_at = Some((call, Refusal::Work));
                    assert!(matches!(
                        cursor.step(&mut m),
                        Err(DecodeError::Resource(BoundedError::Refused(Refusal::Work)))
                    ));
                    assert_eq!(m.refused, Some((call, Refusal::Work)));
                    assert_eq!(cursor.acquired(), turn);
                    m.fail_at = None;
                    m.refused = None;
                }
                if turn == wire.len() {
                    assert!(matches!(cursor.step(&mut m), Err(DecodeError::Invalid(_))));
                } else {
                    assert_eq!(cursor.step(&mut m).unwrap(), HeaderStep::Progress);
                }
            }
            assert_eq!(cursor.step(&mut m).unwrap(), HeaderStep::Finished);
            assert_eq!(m.calls.len(), wire.len() + 2);
            m.assert_units(3, 64);
            assert_eq!(m.pool.live(), 0);
        });
    });
}
