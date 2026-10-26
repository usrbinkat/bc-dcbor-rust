use super::bindings::{decoder, string_decoder};
use super::harness::*;
use super::support::{
    self, Fault, allowed, checked, contracted, drive_faulted, drive_within, expect_progress,
    pipeline::Refusal, refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{Allocator, BoundedError, Step};

#[test]
fn header_and_first_payload_admissions_are_separately_observed() {
    use dcbor::bounded::decode::cursor::Phase;
    let mut wire = vec![0x78, 0x18];
    wire.extend_from_slice(b"abcdefghijklmnopqrstuvwx");
    let mut baseline = meter();
    let document =
        drive_within(&mut baseline, &mut decoder(&wire), decode_turns(wire.len())).unwrap();
    assert_eq!(document.root().encoded(), wire);
    drop(document);
    for (phase, header, payload) in [
        (Phase::Header, 0, 0),
        (Phase::Header, 1, 0),
        (Phase::Interpret, 2, 0),
        (Phase::Utf8, 2, 1),
        (Phase::Utf8, 2, 23),
        (Phase::Complete, 2, 24),
    ] {
        let mut m = meter();
        let pool = m.share();
        let mut operation = decoder(&wire);
        let mut reached = false;
        for _ in 0..decode_turns(wire.len()) {
            let position = operation.position();
            if (
                position.phase,
                position.header_bytes,
                position.payload_validated,
            ) == (phase, header, payload)
            {
                reached = true;
                break;
            }
            match checked(&mut m, |m| contracted(m, &mut operation)) {
                Err(error) if support::ordinary_exhaustion(&m, &error) => {}
                result => expect_progress(result),
            }
        }
        assert!(reached, "missing boundary {phase:?}/{header}/{payload}");
        let stop = m.attempts();
        refuse(&mut m, Refusal::For(stop, LimitRefusal::Work));
        let document = drive_within(&mut m, &mut operation, decode_turns(wire.len())).unwrap();
        support::RefusalRun::of(&m).resumed(
            &support::RefusalRun::of(&baseline),
            stop,
            LimitRefusal::Work,
        );
        m.assert_units(TURN);
        assert_eq!(
            document.root().kind(),
            dcbor::bounded::decode::Kind::Text("abcdefghijklmnopqrstuvwx")
        );
        drop(operation);
        assert!(pool.live_bytes() > 0);
        assert_eq!(document.root().encoded(), wire);
        drop(document);
        assert_eq!(pool.live_bytes(), 0);
    }
}

#[test]
fn constructor_failure_at_every_callback_never_touches_parser_storage() {
    use dcbor::bounded::decode::construction::Construction;
    let wire = text_wire("q\u{301}\u{1f600}");
    // Each run parses its own document under `parser`, then constructs from
    // it under its own policy. Construction owns the document: through every
    // step, refusal and cancellation the parser's storage is untouched, and
    // the scope's drain releases both policies' storage completely. The
    // construction's calls are what the matrix compares.
    refusal_matrix(
        "construction from a parsed document",
        rigor(),
        |fault: Fault| {
            let mut parser = meter();
            let (mut owner, document) =
                support::document(&mut parser, &wire, Options::normalizing(8));
            let parser_live = parser.live_bytes();
            let mut m = meter();
            refuse(&mut m, fault.refusal);
            let mut operation = Construction::<_, String, Limits>::construct(document);
            let turns = allowed(&m, typed_turns::<String>(wire.len()));
            let value = support::drive_faulted_observed(
                &mut m,
                &mut operation,
                turns,
                fault.cancel,
                |_, _, _| assert_eq!(parser.live_bytes(), parser_live),
            )
            .expect("construction failed");
            if let Some(value) = &value {
                assert_eq!(value.value(), "q\u{301}\u{1f600}");
                assert!(m.live_bytes() >= value.value().len() as u64);
            }
            drop(value);
            let construction_calls = support::RefusalRun::of(&m);
            drop(operation);
            assert_eq!(parser.live_bytes(), parser_live);
            support::drain(&mut owner, &mut m);
            assert_eq!(parser.live_bytes(), 0);
            assert_eq!(m.live_bytes(), 0);
            construction_calls
        },
    );
}

#[test]
fn quick_only_matches_upstream_for_all_scalars_and_cross_character_cases() {
    use dcbor::bounded::decode::cursor::Decoder;
    use unicode_normalization::{IsNormalized, is_nfc_quick};
    fn check(text: &str) {
        let wire = text_wire(text);
        let mut m = meter();
        let mut operation = Decoder::new(&wire, Options::quick_only(8));
        let mut result = None;
        for _ in 0..decode_turns(wire.len()) {
            match contracted(&mut m, &mut operation) {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(document)) => {
                    result = Some(Ok(document));
                    break;
                }
                Err(error) => {
                    result = Some(Err(error));
                    break;
                }
                Ok(Step::Finished) => panic!("quick check finished without an outcome"),
            }
        }
        let result = result.expect("incremental quick check did not terminate");
        match is_nfc_quick(text.chars()) {
            IsNormalized::Yes => assert!(result.is_ok(), "{text:?}"),
            IsNormalized::No | IsNormalized::Maybe => {
                assert!(matches!(result, Err(DecodeError::UnprovenText)), "{text:?}")
            }
        }
        drop(result);
        drop(operation);
        m.assert_units(TURN);
        assert_eq!(m.live_bytes(), 0);
    }
    for scalar in 0..=0x10ffff {
        if let Some(ch) = char::from_u32(scalar) {
            check(&ch.to_string());
        }
    }
    for text in [
        "",
        "q\u{301}a",
        "q\u{301}\u{316}",
        "\u{301}a",
        "a\u{301}",
        "\u{1100}\u{1162}",
        "\u{e9}\u{1f600}",
    ] {
        check(text);
    }
}

#[test]
fn writer_refusals_preserve_literal_prefix_guards_and_plan_ownership() {
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "a\u{301}";
    let expected = [0x62, 0xc3, 0xa1];
    let mut preparation = meter();
    let pool = preparation.share();
    let prepared = drive_within(
        &mut preparation,
        &mut TextPreparation::new(source),
        normalize_turns(source),
    )
    .unwrap();
    let live = pool.live_bytes();
    refusal_matrix("text writer", rigor(), |fault: Fault| {
        let mut guarded = [0xee; 5];
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let mut emission = prepared.writer(&mut guarded[1..4]);
        let turns = allowed(&m, text_emit_turns(expected.len()));
        let emitted = drive_faulted(&mut m, &mut emission, turns, fault.cancel)
            .expect("a prepared text emits");
        if emitted.is_some() {
            assert_eq!(emission.emitted_prefix(), expected);
            m.assert_units(TURN);
        }
        // The writer's borrow of `guarded` ends here; it has no destructor.
        assert_eq!((guarded[0], guarded[4]), (0xee, 0xee));
        let written = guarded[1..4].iter().take_while(|b| **b != 0xee).count();
        assert_eq!(&guarded[1..1 + written], &expected[..written]);
        assert!(guarded[1 + written..4].iter().all(|b| *b == 0xee));
        assert_eq!(pool.live_bytes(), live);
        support::RefusalRun::of(&m)
    });
    drop(prepared);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn emission_is_bounded_independently_of_preparation() {
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "x".repeat(65536);
    let mut preparation = meter();
    let prepared = drive_within(
        &mut preparation,
        &mut TextPreparation::new(&source),
        normalize_turns(&source),
    )
    .unwrap();
    let mut bytes = vec![0; prepared.len() as usize];
    let turns = text_emit_turns(bytes.len());
    let mut emission = meter();
    drive_within(&mut emission, &mut prepared.writer(&mut bytes), turns).unwrap();
    assert_eq!(emission.requests(), 0, "emission requested allocation");
    emission.assert_units(TURN);
    assert_eq!(bytes, text_wire(&source));
}

#[test]
fn capacity_pool_survives_concurrent_success_and_every_refused_constructor() {
    let capacity = 32 * 1024 * 1024;
    let mut pool = meter_with(capacity);
    let wire = text_wire("q\u{301}\u{1f600}");
    let mut baseline = meter();
    drop(
        drive_within(
            &mut baseline,
            &mut string_decoder(&wire),
            string_turns(wire.len()),
        )
        .unwrap(),
    );
    let boundaries = baseline.calls().len();
    assert!(boundaries > 0);
    // In rounds, every call refused once and as many decodes unrefused,
    // about a thousand decodes in all; the cases are dealt to the workers
    // in turn.
    const WORKERS: usize = 8;
    const DECODES: usize = 1000;
    let rounds = DECODES.div_ceil(2 * boundaries);
    let cases: Vec<Option<usize>> = (0..rounds)
        .flat_map(|_| (0..boundaries).flat_map(|stop| [Some(stop), None]))
        .collect();
    std::thread::scope(|scope| {
        for worker in 0..WORKERS {
            let shared = pool.share();
            let wire = &wire;
            let baseline = &baseline;
            let mine: Vec<Option<usize>> = cases
                .iter()
                .copied()
                .skip(worker)
                .step_by(WORKERS)
                .collect();
            scope.spawn(move || {
                for case in mine {
                    let mut m = shared.share();
                    let mut operation = string_decoder(wire);
                    if let Some(stop) = case {
                        refuse(&mut m, Refusal::For(stop, LimitRefusal::Work));
                        let output =
                            drive_within(&mut m, &mut operation, string_turns(wire.len())).unwrap();
                        assert_eq!(output.value(), "q\u{301}\u{1f600}");
                        support::RefusalRun::of(&m).resumed(
                            &support::RefusalRun::of(baseline),
                            stop,
                            LimitRefusal::Work,
                        );
                    } else {
                        let output =
                            drive_within(&mut m, &mut operation, string_turns(wire.len())).unwrap();
                        assert_eq!(output.value(), "q\u{301}\u{1f600}");
                    }
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
fn storage_refusal_holds_a_retained_decode_until_another_thread_releases_capacity() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::construction::TypedDecoder;
    let payload = vec![0x5a; 65536];
    let wire = dcbor::CBOR::to_byte_string(&payload).to_cbor_data();
    let turns = typed_turns::<ByteString>(wire.len());
    // The admissions of an unobstructed decode of the same input.
    let baseline = {
        let mut m = meter();
        let mut owner = support::scope(&mut m);
        let input = support::copy(&owner, &mut m, &wire);
        m.measure();
        let value = support::decode::<_, ByteString>(&mut m, input, Options::normalizing(8))
            .expect("baseline decode failed");
        let trace = m.admitted().to_vec();
        drop(value);
        support::drain(&mut owner, &mut m);
        trace
    };
    let capacity = 1 << 20;
    let mut pool = meter_with(capacity);
    let mut m = pool.share();
    let mut owner = support::scope(&mut m);
    let input = support::copy(&owner, &mut m, &wire);
    m.measure();
    let mut operation = TypedDecoder::<_, ByteString, Limits>::new(input, Options::normalizing(8));
    match checked(&mut m, |m| contracted(m, &mut operation)) {
        Err(error) if support::ordinary_exhaustion(&m, &error) => {}
        result => expect_progress(result),
    }
    // Another owner takes every remaining byte of the shared capacity.
    let blocker = pool.allocate(capacity - pool.live_bytes()).unwrap();
    let mut refused = None;
    for _ in 0..turns {
        match checked(&mut m, |m| contracted(m, &mut operation)) {
            Ok(Step::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Storage))) => {
                refused = Some(operation.position());
                break;
            }
            Err(error) if support::ordinary_exhaustion(&m, &error) => {}
            other => panic!("unexpected outcome {}", support::label(&other)),
        }
    }
    let position = refused.expect("no allocation met the exhausted capacity");
    let live = pool.live_bytes();
    assert_eq!(live, capacity);
    // While the capacity stays held the same operation is refused at the same
    // unit, and nothing it holds is released or replayed.
    for _ in 0..3 {
        assert!(matches!(
            checked(&mut m, |m| contracted(m, &mut operation)),
            Err(DecodeError::Resource(BoundedError::Refused(
                LimitRefusal::Storage
            )))
        ));
        assert_eq!(operation.position(), position);
        assert_eq!(pool.live_bytes(), live);
    }
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        wait.recv().unwrap();
        drop(blocker);
    });
    release.send(()).unwrap();
    holder.join().unwrap();
    let value = drive_within(&mut m, &mut operation, turns).expect("resumed decode failed");
    assert_eq!(value.value().data(), &payload[..]);
    assert_eq!(m.admitted(), baseline, "resumption replayed admitted work");
    drop(operation);
    drop(value);
    support::drain(&mut owner, &mut m);
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(capacity).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "an admission beyond one quantum made straight to the policy, which the \
              unit assertion must reject"
)]
fn bound_assertion_rejects_oversized_instrumentation() {
    use dcbor::bounded::Budget;
    let mut m = meter();
    m.traverse(1, 256).unwrap();
    assert!(std::panic::catch_unwind(|| m.assert_units(TURN)).is_err());
}
