use super::harness::*;
use dcbor::bounded::BoundedError;
use dcbor::bounded::decode::{DecodeError, Options, decode};

#[test]
fn header_and_first_payload_admissions_are_separately_observed() {
    use super::bindings::decode_driver;
    use super::driver::{Step, finish};
    use dcbor::bounded::decode::cursor::Phase;
    let mut wire = vec![0x78, 0x18];
    wire.extend_from_slice(b"abcdefghijklmnopqrstuvwx");
    let mut baseline = decode_driver(&wire, meter());
    finish(&mut baseline, 4096);
    assert_eq!(baseline.output.as_ref().unwrap().root().encoded(), wire);
    for (phase, header, payload) in [
        (Phase::Header, 0, 0),
        (Phase::Header, 1, 0),
        (Phase::Interpret, 2, 0),
        (Phase::Utf8, 2, 1),
        (Phase::Utf8, 2, 23),
        (Phase::Complete, 2, 24),
    ] {
        let mut operation = decode_driver(&wire, meter());
        let pool = operation.meter.pool.clone();
        let mut reached = false;
        for _ in 0..4096 {
            let position = operation.operation().position();
            if (
                position.phase,
                position.header_bytes,
                position.payload_validated,
            ) == (phase, header, payload)
            {
                reached = true;
                break;
            }
            assert_eq!(operation.step(), Ok(Step::Progress));
        }
        assert!(reached, "missing boundary {phase:?}/{header}/{payload}");
        let before = operation.operation().position();
        let stop = operation.meter.calls.len();
        operation.meter.fail_at = Some((stop, Refusal::Work));
        assert_eq!(operation.step(), Ok(Step::Refused(Refusal::Work)));
        assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
        assert_eq!(operation.operation().position(), before);
        assert!(operation.output.is_none());
        operation.meter.fail_at = None;
        finish(&mut operation, 4096);
        let mut trace = baseline.meter.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(operation.meter.calls, trace);
        operation.meter.assert_units(3, 64);
        let document = operation.output.take().unwrap();
        assert_eq!(
            document.root().kind(),
            dcbor::bounded::decode::Kind::Text("abcdefghijklmnopqrstuvwx")
        );
        assert_eq!(operation.step(), Ok(Step::Finished));
        drop(operation);
        assert!(pool.live() > 0);
        assert_eq!(document.root().encoded(), wire);
        drop(document);
        assert_eq!(pool.live(), 0);
    }
}

#[test]
fn constructor_failure_at_every_callback_releases_only_constructor_ownership() {
    use dcbor::bounded::decode::construction::{BuildStep, ResumableDecodable};
    use dcbor::bounded::decode::storage::Storage;
    let wire = text_wire("q\u{301}😀");
    let mut parser = meter();
    let doc = decode(&wire, 8, &mut parser).unwrap();
    let parser_live = parser.pool.live();
    let run = |stop: Option<(usize, Refusal)>, cancel: bool| {
        let mut m = meter();
        m.fail_at = stop;
        let mut state = String::start::<Permit>();
        let mut permits = Storage::new();
        let mut observed = false;
        let mut done = false;
        for _ in 0..4096 {
            let before = (m.values, m.bytes);
            m.limit_values = before.0 + 3;
            m.limit_bytes = before.1 + 64;
            m.refused = None;
            let result = String::construct_step(&doc, 0, &mut state, &mut permits, &mut m);
            assert!(m.values - before.0 <= 3 && m.bytes - before.1 <= 64);
            assert_eq!(parser.pool.live(), parser_live);
            match result {
                Ok(BuildStep::Progress) => assert_ne!((m.values, m.bytes), before),
                Ok(BuildStep::Complete(value)) => {
                    assert_eq!(value, "q\u{301}😀");
                    assert!(m.pool.live() >= value.len() as u64);
                    drop(value);
                    done = true;
                    break;
                }
                Err(DecodeError::Resource(BoundedError::Refused(reason))) => {
                    assert_eq!(m.refused, stop);
                    assert_eq!(Some((m.calls.len() - 1, reason)), stop);
                    assert!(!observed);
                    observed = true;
                    m.fail_at = None;
                    if cancel {
                        done = true;
                        break;
                    }
                }
                _ => panic!("unexpected construction outcome"),
            }
        }
        assert!(done, "construction did not terminate");
        assert_eq!(observed, stop.is_some());
        drop(state);
        drop(permits);
        assert_eq!(m.pool.live(), 0);
        m
    };
    let baseline = run(None, false);
    for (index, call) in baseline.calls.iter().enumerate() {
        let reason = if matches!(call, Call::Allocate(_)) {
            Refusal::Capacity
        } else {
            Refusal::Work
        };
        let resumed = run(Some((index, reason)), false);
        let mut trace = baseline.calls.clone();
        trace.insert(index, *call);
        assert_eq!(resumed.calls, trace);
        assert_eq!(
            (resumed.values, resumed.bytes),
            (baseline.values, baseline.bytes)
        );
        let cancelled = run(Some((index, reason)), true);
        assert_eq!(cancelled.calls, baseline.calls[..=index]);
    }
    drop(doc);
    assert_eq!(parser.pool.live(), 0);
}

#[test]
fn quick_only_matches_upstream_for_all_scalars_and_cross_character_cases() {
    use unicode_normalization::{IsNormalized, is_nfc_quick};
    fn check(text: &str) {
        let wire = text_wire(text);
        let mut m = meter();
        use dcbor::bounded::decode::cursor::{DecodeStep, Decoder};
        let mut operation = Decoder::new(&wire, Options::quick_only(8));
        let mut result = None;
        for _ in 0..text.len() * 8 + 64 {
            match operation.step(&mut m) {
                Ok(DecodeStep::Progress) => {}
                Ok(DecodeStep::Complete(document)) => {
                    result = Some(Ok(document));
                    break;
                }
                Err(error) => {
                    result = Some(Err(error));
                    break;
                }
                Ok(DecodeStep::Finished) => panic!("quick check finished without an outcome"),
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
        m.assert_units(3, 64);
        assert_eq!(m.pool.live(), 0);
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
        "é😀",
    ] {
        check(text);
    }
}

#[test]
fn writer_refusals_preserve_literal_prefix_guards_and_plan_ownership() {
    use super::driver::{Driver, finish, resume};
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "a\u{301}";
    let expected = [0x62, 0xc3, 0xa1];
    let mut preparation = Driver::from_operation(TextPreparation::new(source), meter());
    finish(&mut preparation, 4096);
    let pool = preparation.meter.pool.clone();
    let prepared = preparation.output.take().unwrap();
    drop(preparation);
    let live = pool.live();
    let mut baseline_bytes = [0; 3];
    let mut baseline = Driver::from_operation(prepared.writer(&mut baseline_bytes), meter());
    finish(&mut baseline, 4096);
    for index in 0..baseline.meter.calls.len() {
        let mut guarded = [0xee; 5];
        let mut m = meter();
        m.fail_at = Some((index, Refusal::Work));
        let mut emission = Driver::from_operation(prepared.writer(&mut guarded[1..4]), m);
        resume(&mut emission, Refusal::Work);
        let mut trace = baseline.meter.calls.clone();
        trace.insert(index, trace[index]);
        assert_eq!(emission.meter.calls, trace);
        assert_eq!(emission.operation().emitted_prefix(), expected);
        emission.meter.assert_units(3, 64);
        drop(emission);
        assert_eq!((guarded[0], guarded[4]), (0xee, 0xee));
        let written = guarded[1..4].iter().take_while(|b| **b != 0xee).count();
        assert_eq!(&guarded[1..1 + written], &expected[..written]);
        assert!(guarded[1 + written..4].iter().all(|b| *b == 0xee));
        assert_eq!(pool.live(), live);
    }
    drop(baseline);
    drop(prepared);
    assert_eq!(pool.live(), 0);
}

#[test]
fn emission_is_bounded_independently_of_preparation() {
    use super::driver::{Driver, finish};
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "x".repeat(65536);
    let mut preparation = Driver::from_operation(TextPreparation::new(&source), meter());
    finish(&mut preparation, source.len() * 32 + 4096);
    let prepared = preparation.output.take().unwrap();
    let mut bytes = vec![0; prepared.len() as usize];
    let mut emission = Driver::from_operation(prepared.writer(&mut bytes), meter());
    finish(&mut emission, source.len() + 4096);
    assert!(
        !emission
            .meter
            .calls
            .iter()
            .any(|c| matches!(c, Call::Allocate(_)))
    );
    emission.meter.assert_units(3, 64);
    drop(emission);
    assert_eq!(bytes, text_wire(&source));
}

#[test]
fn capacity_pool_survives_concurrent_success_and_every_refused_constructor() {
    use super::bindings::string_driver;
    use super::driver::{finish, resume};
    let capacity = 32 * 1024 * 1024;
    let pool = Pool::new(capacity);
    let wire = text_wire("q\u{301}😀");
    let mut baseline = string_driver(&wire, meter());
    finish(&mut baseline, 4096);
    let boundaries = baseline.meter.calls.len();
    assert!(boundaries > 0);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let pool = pool.clone();
            let wire = &wire;
            let baseline = &baseline;
            scope.spawn(move || {
                for iteration in 0..125 {
                    let mut m = Meter::new(pool.clone());
                    if (iteration + worker) % 2 == 0 {
                        let stop = iteration % boundaries;
                        m.fail_at = Some((stop, Refusal::Work));
                        let mut operation = string_driver(wire, m);
                        resume(&mut operation, Refusal::Work);
                        assert_eq!(operation.output.as_ref().unwrap().value(), "q\u{301}😀");
                        let mut trace = baseline.meter.calls.clone();
                        trace.insert(stop, trace[stop]);
                        assert_eq!(operation.meter.calls, trace);
                    } else {
                        let mut operation = string_driver(wire, m);
                        finish(&mut operation, 4096);
                        assert_eq!(operation.output.as_ref().unwrap().value(), "q\u{301}😀");
                    }
                }
            });
        }
    });
    assert_eq!(pool.live(), 0);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
    assert_eq!(pool.live(), 0);
}

#[test]
fn bound_assertion_rejects_oversized_instrumentation() {
    use dcbor::bounded::Budget;
    let mut m = meter();
    m.traverse(1, 256).unwrap();
    assert!(std::panic::catch_unwind(|| m.assert_units(3, 64)).is_err());
}
