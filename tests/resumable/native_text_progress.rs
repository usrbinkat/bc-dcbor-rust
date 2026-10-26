use super::bindings::text_encoder;
use super::harness::*;
use super::support::{
    Fault, allowed, checked, contracted, drive_within, expect_progress, label, pipeline::Refusal,
    refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::{BoundedError, Failure, Step};

#[test]
fn actual_normalizer_progress_and_emitted_prefix_survive_every_cancellation_point() {
    let source = "a\u{300}\u{305}\u{315}\u{5ae}b";
    let expected = [0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'];
    let mut baseline = meter();
    let mut reference = text_encoder(source);
    let mut states = Vec::new();
    let mut output = None;
    for _ in 0..normalize_turns(source) {
        let before = reference.position();
        let result = contracted(&mut baseline, &mut reference);
        match result {
            Ok(Step::Progress) => {
                assert_ne!(
                    reference.position(),
                    before,
                    "charges alone must not count as useful execution progress"
                );
                assert!(expected.starts_with(reference.emitted_prefix()));
                states.push((reference.position(), baseline.live_bytes()));
            }
            Ok(Step::Complete(encoded)) => {
                output = Some(encoded);
                break;
            }
            other => panic!("unexpected normalization outcome {}", label(&other)),
        }
    }
    let output = output.expect("normalization did not complete");
    assert_eq!(output.as_ref(), expected);
    baseline.assert_units(TURN);
    assert!(!states.is_empty());
    // Every admission refused from the state the unrefused encoding reaches
    // there, the refused step moving nothing (`contracted`), and a
    // cancellation at every admission releasing everything the encoder held.
    // After each step that makes progress, the encoder is at the position,
    // holding the storage, the unrefused encoding reached after as many
    // steps: refusals change when steps happen, never what they do.
    refusal_matrix(
        "text encoder of a reordered run",
        rigor(),
        |fault: Fault| {
            let mut m = meter();
            refuse(&mut m, fault.refusal);
            let pool = m.share();
            let mut operation = text_encoder(source);
            let mut steps = 0;
            for _ in 0..allowed(&m, normalize_turns(source)) {
                match checked(&mut m, |m| contracted(m, &mut operation)) {
                    Ok(Step::Progress) => {
                        assert_eq!(
                            (operation.position(), pool.live_bytes()),
                            states[steps],
                            "progress step {steps} reached another state"
                        );
                        assert!(expected.starts_with(operation.emitted_prefix()));
                        steps += 1;
                    }
                    Ok(Step::Complete(encoded)) => {
                        assert_eq!(steps, states.len(), "completion came at another step");
                        assert_eq!(encoded.as_ref(), expected);
                        drop(operation);
                        drop(encoded);
                        assert_eq!(pool.live_bytes(), 0);
                        return super::support::RefusalRun::of(&m);
                    }
                    Err(error) if error.refused() => {
                        if fault.cancel && m.injected_refusals() > 0 {
                            assert!(expected.starts_with(operation.emitted_prefix()));
                            drop(operation);
                            assert_eq!(pool.live_bytes(), 0);
                            return super::support::RefusalRun::of(&m);
                        }
                    }
                    other => panic!("unexpected normalization outcome {}", label(&other)),
                }
            }
            panic!("the encoding exceeded its bound");
        },
    );
}

#[test]
fn text_resume_retains_actual_offsets_and_owned_output_after_decoder_drop() {
    let source = "\u{1e0b}\u{323}";
    let expected = [0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87];
    let mut m = meter();
    let pool = m.share();
    let mut operation = text_encoder(source);
    expect_progress(contracted(&mut m, &mut operation));
    let before = operation.position();
    assert_eq!(before.source_bytes, 3);
    let call = m.attempts();
    refuse(&mut m, Refusal::For(call, LimitRefusal::Storage));
    assert!(matches!(
        contracted(&mut m, &mut operation),
        Err(BoundedError::Refused(LimitRefusal::Storage))
    ));
    assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Storage)));
    assert_eq!(operation.position(), before);
    m.fail_call(None);
    let output = drive_within(&mut m, &mut operation, normalize_turns(source))
        .expect("resumed encoding failed");
    assert_eq!(output.as_ref(), expected);
    assert_eq!(operation.position().source_bytes, source.len());
    drop(operation);
    assert_eq!(pool.live_bytes(), expected.len() as u64);
    assert_eq!(output.as_ref(), expected);
    drop(output);
    assert_eq!(pool.live_bytes(), 0);
}
