use super::harness::*;
use super::support::{pipeline::Refusal, refuse};
use dcbor::ByteString;
use dcbor::bounded::encoding::EmitPosition;
use dcbor::bounded::{BoundedError, Resumable, Step, WriteWork, prepare};

/// A writer given a destination of another length than its plan refuses it
/// before admitting or writing anything, and is finished after.
#[test]
fn a_wrong_sized_destination_is_refused_before_any_admission() {
    let value = ByteString::new(vec![0x5a; 3]);
    super::support::recorded_run(|run| {
        // The plan is the preparing family's; each writer runs under a
        // family of its own, of the same recorded run.
        let allocator = run.policy(POOL);
        let prepared = run.with_policy(allocator, |a| prepare(&value, a).unwrap());
        assert_eq!(prepared.len(), 4);
        for size in [0, 3, 5] {
            let writing = run.policy(POOL);
            run.with_policy(writing, |m| {
                let mut guarded = [0xee; 7];
                let mut writer = prepared.writer(&mut guarded[1..1 + size]);
                assert_eq!(
                    writer.step(m),
                    Err(BoundedError::OutputSize {
                        measured: 4,
                        provided: size as u64,
                    })
                );
                assert_eq!(writer.step(m), Ok(Step::Finished));
                assert!(writer.emitted_prefix().is_empty());
                assert_eq!(m.attempts(), 0);
                // The writer's borrow of the destination ended at its last
                // use: the guard bytes around it are read untouched.
                assert!(guarded.iter().all(|b| *b == 0xee));
            });
        }
        drop(prepared);
        run.with_policy(allocator, |a| assert_eq!(a.live_bytes(), 0));
        Ok(())
    });
}

/// The position a writer reports, directly and as a resumable operation:
/// the plan offset, the gaps passed, the bytes written and whether it is
/// finished, each against what the writer emitted.
fn reported<'p, 'o>(
    writer: &mut dcbor::bounded::encoding::Writer<'p, 'o, Reservation>,
    expected: EmitPosition,
) {
    // The inherent method, which takes `&self`; through `&mut` the call
    // would resolve to the trait's.
    assert_eq!((*writer).position(), expected, "the writer's position");
    assert_eq!(
        <_ as Resumable<Limits>>::position(writer),
        expected,
        "the resumable writer's position"
    );
    assert_eq!(writer.emitted_prefix().len(), expected.written);
}

/// A refused segment leaves the emitted prefix and the writer's position as
/// they were; the same writer resumes with that segment and completes, every
/// byte written once and nothing outside its destination. The reported
/// position is the emission's own at every step: the plan of a 100-byte
/// string is its two-byte head and payload, with no header gap.
#[test]
fn a_refused_segment_preserves_the_emitted_prefix_and_position() {
    let value = ByteString::new(vec![0x5a; 100]);
    let at = |written: usize, finished: bool| EmitPosition {
        source: written,
        hole: 0,
        written,
        finished,
    };
    super::support::recorded_run(|run| {
        let allocator = run.policy(POOL);
        let prepared = run.with_policy(allocator, |a| prepare(&value, a).unwrap());
        let mut guarded = [0xee; 104];
        let writing = run.policy(POOL);
        run.with_policy(writing, |m| {
            let mut writer = prepared.writer(&mut guarded[1..103]);
            reported(&mut writer, at(0, false));
            assert_eq!(writer.step(m), Ok(Step::Progress));
            assert_eq!(writer.emitted_prefix().len(), 64);
            reported(&mut writer, at(64, false));
            let position = writer.position();
            let call = m.attempts();
            refuse(m, Refusal::For(call, LimitRefusal::Work));
            assert_eq!(
                writer.step(m),
                Err(BoundedError::Refused(LimitRefusal::Work))
            );
            assert_eq!(writer.position(), position);
            assert_eq!(writer.emitted_prefix().len(), 64);
            m.fail_call(None);
            m.clear_refusal();
            assert_eq!(writer.step(m), Ok(Step::Progress));
            reported(&mut writer, at(102, false));
            assert_eq!(writer.step(m), Ok(Step::Complete(())));
            reported(&mut writer, at(102, true));
            assert_eq!(writer.step(m), Ok(Step::Finished));
            assert_eq!(m.used(), WriteWork::new(3, 102));
        });
        assert_eq!((guarded[0], guarded[103]), (0xee, 0xee));
        assert_eq!(guarded[1..3], [0x58, 100]);
        assert!(guarded[3..103].iter().all(|b| *b == 0x5a));
        drop(prepared);
        run.with_policy(allocator, |a| assert_eq!(a.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn work_composition_checks_each_dimension_and_never_saturates() {
    let header = WriteWork::new(1, 9);
    let payload = WriteWork::new(0, 55);
    assert_eq!(header.checked_then(payload), Some(WriteWork::new(1, 64)));
    assert_eq!(header.checked_times(3), Some(WriteWork::new(3, 27)));
    assert_eq!(
        WriteWork::checked_sequence(&[header, payload, header]),
        Some(WriteWork::new(2, 73))
    );
    assert_eq!(WriteWork::checked_sequence(&[]), Some(WriteWork::default()));
    let quantum = WriteWork::new(3, 64);
    assert!(quantum.covers(&WriteWork::new(3, 64)));
    assert!(!quantum.covers(&WriteWork::new(4, 0)));
    assert!(!quantum.covers(&WriteWork::new(0, 65)));
    for value in [WriteWork::new(u64::MAX, 0), WriteWork::new(0, u64::MAX)] {
        assert_eq!(value.checked_then(WriteWork::new(1, 1)), None);
        assert_eq!(
            WriteWork::checked_sequence(&[value, WriteWork::new(1, 1)]),
            None
        );
        assert_eq!(value.checked_times(2), None);
        assert_eq!(value.checked_times(0), Some(WriteWork::default()));
        assert_eq!(value.checked_then(WriteWork::default()), Some(value));
    }
}
