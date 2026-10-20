use super::super::harness::{Meter, meter};
use super::*;
use dcbor::bounded::{
    BoundedError,
    decode::{
        DecodeError, Options,
        construction::{DecodeOwner, TypedDecoder, TypedStep, in_place::StableOption},
    },
};

#[test]
fn stable_optional_acquisitions_fail_physically_and_cleanup_never_allocates() {
    let wire = [0x63, b'q', 0xcc, 0x81];
    let mut baseline = meter();
    baseline.calls.reserve(16384);
    let owner = DecodeOwner::new();
    let observer = Observation::begin(None);
    let value =
        retained_value::<StableOption<String, Meter>>(&owner, &wire, &mut baseline).unwrap();
    assert_eq!(value.value().as_ref().map(String::as_str), Some("q\u{301}"));
    let published = observer.snapshot();
    drop(value);
    let queued = observer.snapshot();
    assert_eq!(queued.calls, published.calls);
    assert_eq!(queued.live, published.live);
    drain_decode(&owner, &mut baseline);
    let cleaned = observer.snapshot();
    observer.stop();
    assert_eq!(cleaned.calls, published.calls);
    assert_eq!(cleaned.live, 0);
    assert_eq!(cleaned.unadmitted, 0);
    assert!(!cleaned.overflow);
    assert_eq!(baseline.pool.live(), 0);
    drop(observer);
    for failure in 0..published.calls {
        let mut turn = meter();
        turn.calls.reserve(16384);
        let owner = DecodeOwner::new();
        let observer = Observation::begin(Some(failure));
        let result = retained_value::<StableOption<String, Meter>>(&owner, &wire, &mut turn);
        assert!(matches!(
            result,
            Err(DecodeError::Resource(BoundedError::Allocation { .. }))
        ));
        drop(result);
        let failed = observer.snapshot();
        assert!(failed.denied);
        drain_decode(&owner, &mut turn);
        let cleaned = observer.snapshot();
        observer.stop();
        assert_eq!(
            cleaned.calls, failed.calls,
            "cleanup allocated after failure {failure}"
        );
        assert_eq!(cleaned.live, 0);
        assert_eq!(cleaned.unadmitted, 0);
        assert!(!cleaned.overflow);
        assert_eq!(turn.pool.live(), 0);
    }
}

#[test]
fn every_public_decoder_cancellation_transfers_custody_without_allocating() {
    // Literal ["q\u{301}", "b"] crosses parser, normalizer, document transfer,
    // vector child construction and pre-publication cleanup boundaries.
    let wire = [0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'];
    let mut boundaries = None;
    {
        let mut turn = meter();
        let owner = DecodeOwner::new();
        let mut decoder =
            TypedDecoder::<Vec<String>, Meter>::new(&owner, &wire, Options::normalizing(8));
        for step in 0..8192 {
            turn.limit_values = turn.values + 3;
            turn.limit_bytes = turn.bytes + 64;
            match decoder.step(&mut turn) {
                Ok(TypedStep::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
                Ok(TypedStep::Complete(value)) => {
                    assert_eq!(value.value(), &["q\u{301}", "b"]);
                    drop(value);
                    boundaries = Some(step + 1);
                    break;
                }
                _ => panic!("literal baseline failed"),
            }
        }
        drop(decoder);
        drain_decode(&owner, &mut turn);
    }
    for stop in 0..boundaries.expect("baseline did not terminate") {
        let mut turn = meter();
        turn.calls.reserve(16384);
        let observer = Observation::begin(None);
        let owner = DecodeOwner::new();
        let mut decoder =
            TypedDecoder::<Vec<String>, Meter>::new(&owner, &wire, Options::normalizing(8));
        assert_eq!(observer.snapshot().calls, 0, "constructors allocated");
        for _ in 0..stop {
            turn.limit_values = turn.values + 3;
            turn.limit_bytes = turn.bytes + 64;
            assert!(matches!(
                decoder.step(&mut turn),
                Ok(TypedStep::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_)))
            ));
        }
        let before = observer.snapshot();
        drop(decoder);
        let queued = observer.snapshot();
        assert_eq!(queued.calls, before.calls);
        assert_eq!(queued.live, before.live);
        drain_decode(&owner, &mut turn);
        let cleaned = observer.snapshot();
        observer.stop();
        assert_eq!(
            cleaned.calls, before.calls,
            "cleanup allocated at boundary {stop}"
        );
        assert_eq!(cleaned.live, 0);
        assert_eq!(cleaned.unadmitted, 0);
        assert!(!cleaned.overflow);
        assert_eq!(turn.pool.live(), 0);
    }
}
