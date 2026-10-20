use super::*;
use dcbor::bounded::decode::DecodeError;
use dcbor::bounded::decode::construction::in_place::StableOption;

fn run_probe(turn: &mut Turn) {
    let owner = DecodeOwner::new();
    let mut decoder = TypedDecoder::<Probe, Turn>::new(&owner, &[0xf6], Options::normalizing(8));
    let mut published = false;
    for _ in 0..512 {
        turn.fresh();
        match decoder.step(turn) {
            Ok(TypedStep::Progress) => {}
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {}
            Ok(TypedStep::Complete(output)) => {
                assert_eq!(output.value().inline, [0x5a; 256]);
                assert_eq!(
                    output.value().construction_address,
                    std::ptr::from_ref(output.value()) as usize
                );
                drop(output);
                published = true;
                break;
            }
            _ => panic!("literal null failed to publish"),
        }
    }
    assert!(published, "construction exceeded its finite bound");
    drop(decoder);
    for _ in 0..512 {
        turn.fresh();
        match owner.shutdown_step(turn) {
            Ok(Reclaimed::Done) => {
                assert_eq!(owner.outstanding(), 0);
                assert_eq!(turn.live.load(Ordering::SeqCst), 0);
                return;
            }
            Ok(Reclaimed::Progress) | Err(BoundedError::Refused(())) => {}
            _ => panic!("cleanup failed"),
        }
    }
    panic!("cleanup exceeded its finite bound");
}

#[test]
fn every_lifecycle_admission_can_refuse_without_replaying_useful_work() {
    let mut baseline = Turn::default();
    run_probe(&mut baseline);
    assert_eq!(baseline.refusals, 0);
    assert!(!baseline.admitted.is_empty());
    for denied in 0..baseline.attempts {
        STARTS.set(0);
        DROPS.set(0);
        let mut turn = Turn {
            deny_at: Some(denied),
            ..Turn::default()
        };
        run_probe(&mut turn);
        assert_eq!(
            turn.refusals, 1,
            "admission {denied} was not refused exactly once"
        );
        assert_eq!(
            turn.admitted, baseline.admitted,
            "admission {denied} replayed or skipped committed work"
        );
        assert_eq!(STARTS.get(), 1);
        assert_eq!(DROPS.get(), 0);
    }
}

#[test]
fn normalized_nested_text_cancellation_retains_custody_at_every_boundary() {
    // Literal [["q\u{301}", "b"], ["c"]]. The first text requires the retained
    // NFC proof path but is already canonical; no encoder supplies the oracle.
    let wire = [
        0x82, 0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b', 0x81, 0x61, b'c',
    ];
    let mut boundaries = None;
    {
        let owner = DecodeOwner::new();
        let mut turn = Turn::default();
        let mut decoder =
            TypedDecoder::<Vec<Vec<String>>, Turn>::new(&owner, &wire, Options::normalizing(8));
        for boundary in 0..8192 {
            turn.fresh();
            match decoder.step(&mut turn) {
                Ok(TypedStep::Progress) | Err(DecodeError::Resource(BoundedError::Refused(()))) => {
                }
                Ok(TypedStep::Complete(value)) => {
                    assert_eq!(
                        value.value(),
                        &vec![
                            vec!["q\u{301}".to_owned(), "b".to_owned()],
                            vec!["c".to_owned()]
                        ]
                    );
                    drop(value);
                    boundaries = Some(boundary + 1);
                    break;
                }
                _ => panic!("literal nested text failed"),
            }
        }
        drop(decoder);
        drain(&owner, &mut turn);
    }
    let boundaries = boundaries.expect("nested text exceeded its finite bound");
    for boundary in 0..boundaries {
        let owner = DecodeOwner::new();
        let mut turn = Turn::default();
        let mut decoder =
            TypedDecoder::<Vec<Vec<String>>, Turn>::new(&owner, &wire, Options::normalizing(8));
        for _ in 0..boundary {
            turn.fresh();
            assert!(matches!(
                decoder.step(&mut turn),
                Ok(TypedStep::Progress) | Err(DecodeError::Resource(BoundedError::Refused(())))
            ));
        }
        let live = turn.live.load(Ordering::SeqCst);
        let admissions = turn.attempts;
        drop(decoder);
        assert_eq!(
            turn.live.load(Ordering::SeqCst),
            live,
            "cancellation released resources outside admission at {boundary}"
        );
        assert_eq!(turn.attempts, admissions);
        drain(&owner, &mut turn);
    }
}

#[test]
fn large_optional_payload_is_initialized_at_its_published_address() {
    assert_eq!(
        std::mem::size_of::<StableOption<Probe, Turn>>(),
        std::mem::size_of::<usize>()
    );
    for (wire, present) in [([0x00], true), ([0xf6], false)] {
        let owner = DecodeOwner::new();
        let mut turn = Turn::default();
        let mut decoder = TypedDecoder::<StableOption<Probe, Turn>, Turn>::new(
            &owner,
            &wire,
            Options::normalizing(8),
        );
        let mut completed = false;
        for _ in 0..512 {
            turn.fresh();
            match decoder.step(&mut turn) {
                Ok(TypedStep::Progress) => {}
                Ok(TypedStep::Complete(output)) => {
                    assert_eq!(output.value().is_some(), present);
                    if let Some(value) = output.value().as_ref() {
                        assert_eq!(value.inline, [0x5a; 256]);
                        assert_eq!(
                            value.construction_address,
                            std::ptr::from_ref(value) as usize
                        );
                    }
                    drop(output);
                    completed = true;
                    break;
                }
                _ => panic!("stable optional literal failed"),
            }
        }
        assert!(completed);
        drop(decoder);
        drain(&owner, &mut turn);
    }
}

#[test]
fn excessive_native_dispatch_depth_is_rejected_before_acquisition() {
    type Four<T> = Vec<Vec<Vec<Vec<T>>>>;
    type Sixteen<T> = Four<Four<Four<Four<T>>>>;
    type SixtyFour<T> = Sixteen<Sixteen<Sixteen<Sixteen<T>>>>;
    let owner = DecodeOwner::new();
    let mut turn = Turn::default();
    let mut decoder =
        TypedDecoder::<SixtyFour<u8>, Turn>::new(&owner, &[0x80], Options::normalizing(128));
    assert!(matches!(
        decoder.step(&mut turn),
        Err(DecodeError::Resource(BoundedError::PlanMismatch))
    ));
    assert_eq!(turn.attempts, 0);
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(turn.live.load(Ordering::SeqCst), 0);
    assert!(matches!(decoder.step(&mut turn), Ok(TypedStep::Progress)));
    assert!(matches!(decoder.step(&mut turn), Ok(TypedStep::Finished)));
}

#[test]
fn nested_construction_and_cleanup_run_on_a_fixed_size_native_stack() {
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            type Four<T> = Vec<Vec<Vec<Vec<T>>>>;
            type Sixteen<T> = Four<Four<Four<Four<T>>>>;
            macro_rules! four {
                ($value:expr) => {
                    $value
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                };
            }
            macro_rules! sixteen {
                ($value:expr) => {
                    four!(four!(four!(four!($value))))
                };
            }
            let mut wire = [0x81; 33];
            wire[32] = 0;
            let owner = DecodeOwner::new();
            let mut turn = Turn::default();
            let mut decoder = TypedDecoder::<Sixteen<Sixteen<Probe>>, Turn>::new(
                &owner,
                &wire,
                Options::normalizing(32),
            );
            let mut completed = false;
            for _ in 0..32768 {
                turn.fresh();
                match decoder.step(&mut turn) {
                    Ok(TypedStep::Progress)
                    | Err(DecodeError::Resource(BoundedError::Refused(()))) => {}
                    Ok(TypedStep::Complete(output)) => {
                        let leaf = sixteen!(sixteen!(output.value()));
                        assert_eq!(leaf.inline, [0x5a; 256]);
                        assert_eq!(leaf.construction_address, std::ptr::from_ref(leaf) as usize);
                        drop(output);
                        completed = true;
                        break;
                    }
                    _ => panic!("nested construction failed"),
                }
            }
            assert!(completed);
            drop(decoder);
            for _ in 0..8192 {
                turn.fresh();
                match owner.shutdown_step(&mut turn) {
                    Ok(Reclaimed::Done) => {
                        assert_eq!(turn.live.load(Ordering::SeqCst), 0);
                        assert_eq!(DROPS.get(), 0);
                        return;
                    }
                    Ok(Reclaimed::Progress) | Err(BoundedError::Refused(())) => {}
                    _ => panic!("nested cleanup failed"),
                }
            }
            panic!("nested cleanup exceeded its finite bound");
        })
        .unwrap()
        .join()
        .unwrap();
}
