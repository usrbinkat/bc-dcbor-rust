use super::bindings::decoder;
use super::harness::*;
use super::support::{
    TurnSchedule, contracted, drive_within, expect_progress, fail_within, finish_within, label,
    pipeline::Refusal, refuse, repeated_refusal, suspend_within,
};
use dcbor::bounded::Step;
use dcbor::bounded::decode::{
    DecodeError, Kind,
    cursor::{Phase, Position},
};

fn map_wire() -> Vec<u8> {
    // Byte-string keys distinguish comparison admission from text validation.
    let mut wire = vec![0xa2];
    for last in *b"ab" {
        wire.extend_from_slice(&[0x59, 0x01, 0x00]);
        wire.extend(std::iter::repeat_n(b'a', 255));
        wire.push(last);
        wire.push(0x01);
    }
    wire
}

fn script(wire: &[u8], select: impl Fn(Position) -> bool) {
    let mut baseline = meter();
    let mut reference = decoder(wire);
    let mut selected = None;
    let mut published = None;
    for _ in 0..decode_turns(wire.len()) {
        let position = reference.position();
        if selected.is_none() && select(position) {
            selected = Some((baseline.attempts(), position));
        }
        let result = contracted(&mut baseline, &mut reference);
        match result {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(document)) => {
                published = Some(document);
                break;
            }
            other => panic!("reference at {position:?}: {}", label(&other)),
        }
    }
    let document = published.expect("reference decode did not complete");
    assert_eq!(document.root().encoded(), wire);
    drop(document);
    let (stop, target) = selected.expect("requested execution boundary was not reached");
    assert!(stop < baseline.calls().len());
    let mut m = meter();
    refuse(&mut m, Refusal::For(stop, LimitRefusal::Work));
    let pool = m.share();
    let mut operation = decoder(wire);
    assert_eq!(
        suspend_within(
            &mut m,
            &mut operation,
            LimitRefusal::Work,
            decode_turns(wire.len()),
            TurnSchedule::Retained
        ),
        stop
    );
    assert_eq!(operation.position(), target);
    assert_eq!(m.calls(), &baseline.calls()[..=stop]);
    // Preserve the admitted prefix as the independent no-replay oracle.
    let prefix = m.calls()[..stop].to_vec();
    let paid = m.used();
    m.fail_call(None);
    let output =
        drive_within(&mut m, &mut operation, decode_turns(wire.len())).expect("resumed decode");
    assert_eq!(&m.calls()[..stop], prefix);
    let after = m.used();
    assert!(after.values >= paid.values && after.bytes >= paid.bytes);
    assert_eq!(output.root().encoded(), wire);
    // Suspension retains the original allowance; resumption uses fresh turns.
    // The shared oracle preserves the exact prefix and all admitted work,
    // accounting separately for later quantum exhaustion.
    super::support::RefusalRun::of(&m).resumed(
        &super::support::RefusalRun::of(&baseline),
        stop,
        LimitRefusal::Work,
    );
    assert_eq!(after, baseline.used());
    m.assert_units(TURN);
    drop(operation);
    assert!(pool.live_bytes() > 0, "document must retain its arena");
    assert_eq!(output.root().encoded(), wire);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn before_header_has_no_consumed_work_and_same_cursor_completes() {
    script(&[0x81, 0x18, 0x18], |p| {
        p.phase == Phase::Header && p.header_bytes == 0 && p.input == 0
    });
}

#[test]
fn after_header_retains_validation_and_same_cursor_completes() {
    script(&[0x43, b'a', b'b', b'c'], |p| {
        p.phase == Phase::Interpret && p.header_bytes == 1 && p.input == 1
    });
}

#[test]
fn second_payload_preserves_previous_child_and_same_cursor_completes() {
    script(
        &[0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'],
        |p| p.phase == Phase::Utf8 && p.completed_children == 1 && p.payload_validated == 1,
    );
}

#[test]
fn key_comparison_refusal_resumes_without_revalidating_prior_keys() {
    script(&map_wire(), |p| {
        p.phase == Phase::Compare && p.compared_bytes == 64
    });
}

#[test]
fn container_completion_refusal_does_not_complete_children_twice() {
    script(&[0x82, 0x01, 0x02], |p| {
        p.phase == Phase::Attach && p.completed_children == 1
    });
}

#[test]
fn long_prefix_keys_out_of_order_or_equal_are_rejected_after_bounded_comparison() {
    let key = |last: u8| {
        let mut key = vec![0x59, 0x01, 0x00];
        key.extend(std::iter::repeat_n(b'a', 255));
        key.push(last);
        key
    };
    let map = |first: &[u8], second: &[u8]| {
        let mut wire = vec![0xa2];
        wire.extend_from_slice(first);
        wire.push(0x00);
        wire.extend_from_slice(second);
        wire.push(0x01);
        wire
    };
    // The keys differ only in their last byte, or not at all: ordering is
    // decided only after the whole shared prefix is compared.
    for wire in [map(&key(b'b'), &key(b'a')), map(&key(b'a'), &key(b'a'))] {
        let mut m = meter();
        let mut operation = decoder(&wire);
        let error = fail_within(&mut m, &mut operation, decode_turns(wire.len()));
        assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
        m.assert_units(TURN);
        finish_within(&mut m.share(), &mut operation, decode_turns(wire.len()));
        drop(operation);
        assert_eq!(m.live_bytes(), 0);
    }
}

#[test]
fn key_comparison_quantum_is_checked_separately_from_payload_scans() {
    let wire = map_wire();
    let mut m = meter();
    let doc = drive_within(&mut m, &mut decoder(&wire), decode_turns(wire.len())).unwrap();
    assert_eq!(doc.root().kind(), Kind::Map(2));
    assert_eq!(doc.root().encoded(), wire);
    // Byte-string validation charges zero values. Comparisons charge visits.
    let oversized: Vec<_> = m
        .calls()
        .iter()
        .filter(|c| matches!(c, Call::Work { values, bytes } if *values > 0 && *bytes > 64))
        .collect();
    assert!(oversized.is_empty(), "unbounded comparison: {oversized:?}");
    drop(doc);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn arena_growth_quantum_is_checked_without_text_or_payload_processing() {
    let mut wire = vec![0x99, 0x10, 0x00];
    wire.extend(std::iter::repeat_n(0x01, 4096));
    let mut m = meter();
    let doc = drive_within(&mut m, &mut decoder(&wire), decode_turns(wire.len())).unwrap();
    assert_eq!(doc.node_count(), 4097);
    assert!(
        doc.root()
            .children()
            .all(|node| node.kind() == Kind::Unsigned(1))
    );
    assert!(
        m.calls()
            .iter()
            .all(|c| !matches!(c, Call::Work { bytes, .. } if *bytes > 64)),
        "growth relocation exceeds quantum: {:?}",
        m.calls()
    );
    drop(doc);
    assert_eq!(m.live_bytes(), 0);
}

// Prior art: tokio-util/tests/length_delimited.rs, read_multi_frame_multi_packet:
// three ordered outputs, each completed once across scripted boundaries.
const CHILDREN: &[u8] = &[
    0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x65, b'h', b'e', b'l', b'l', b'o',
];

#[test]
fn every_child_completion_refusal_completes_each_child_once() {
    for child in 0..3 {
        script(CHILDREN, |p| {
            p.phase == Phase::Attach && p.completed_children == child
        });
    }
}

#[test]
fn a_trailing_item_is_rejected_after_a_refusal_at_every_child_completion() {
    let mut wire = CHILDREN.to_vec();
    wire.push(0x00);
    for child in 0..3 {
        let mut m = meter();
        let pool = m.share();
        let mut operation = decoder(&wire);
        let mut reached = false;
        for _ in 0..decode_turns(wire.len()) {
            let position = operation.position();
            if position.phase == Phase::Attach && position.completed_children == child {
                reached = true;
                break;
            }
            expect_progress(contracted(&mut m, &mut operation));
        }
        assert!(reached, "child {child} never completed");
        let position = operation.position();
        repeated_refusal(
            "trailing item after completed child",
            &mut m,
            position,
            3,
            |m| {
                let result = contracted(m, &mut operation).map(|_| ());
                (operation.position(), result)
            },
        );
        assert_eq!(operation.position(), position);
        let error = fail_within(&mut m, &mut operation, decode_turns(wire.len()));
        assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
        finish_within(&mut m.share(), &mut operation, decode_turns(wire.len()));
        drop(operation);
        assert_eq!(pool.live_bytes(), 0);
    }
}

#[test]
fn late_invalid_trailing_item_is_never_published_after_a_refusal() {
    let wire = [0x82, 0x01, 0x02, 0x00];
    let mut m = meter();
    refuse(&mut m, Refusal::For(0, LimitRefusal::Work));
    let pool = m.share();
    let mut operation = decoder(&wire);
    assert_eq!(
        suspend_within(
            &mut m,
            &mut operation,
            LimitRefusal::Work,
            decode_turns(wire.len()),
            TurnSchedule::Retained
        ),
        0
    );
    m.fail_call(None);
    let error = fail_within(&mut m, &mut operation, decode_turns(wire.len()));
    assert!(matches!(error, DecodeError::Invalid(_)), "{error:?}");
    finish_within(&mut m.share(), &mut operation, decode_turns(wire.len()));
    drop(operation);
    assert_eq!(pool.live_bytes(), 0);
}
