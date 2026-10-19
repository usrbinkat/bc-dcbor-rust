use super::support::*;
use dcbor::bounded::resumable::{Construct, Fault, Outcome};
use dcbor::{ByteString, CBORResumableDecodable};

#[derive(Debug, PartialEq, CBORResumableDecodable)]
struct Record {
    #[cbor(n = 0)]
    text: String,
    #[cbor(n = 1)]
    bytes: ByteString,
    #[cbor(n = 2)]
    optional: Option<bool>,
}

#[test]
fn derived_fields_resume_without_reconstructing_completed_fields() {
    let text = "😀é".repeat(1024);
    let payload = byte_string(65536);
    let mut wire = vec![0xa2, 0x00];
    wire.extend(text_wire(&text));
    wire.push(0x01);
    wire.extend_from_slice(&payload);
    let expected = Record {
        text,
        bytes: ByteString::new(payload[5..].to_vec()),
        optional: None,
    };
    // Baseline determines public admission boundaries, never private stages.
    let mut boundaries = None;
    for injection in std::iter::once(None).chain((0..).map(Some)) {
        if injection.is_some_and(|i| i >= boundaries.unwrap()) {
            break;
        }
        let pool = pool();
        let mut construct =
            Construct::<Record>::new(wire.clone().into_boxed_slice(), policy(), pool.clone())
                .unwrap();
        if let Some(index) = injection {
            construct.inject_once(index, Fault::Work);
        }
        let mut fired = false;
        let mut completed = false;
        for _ in 0..wire.len() * 128 + 4096 {
            match construct.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::Refused(Fault::Work) => {
                    assert!(!fired);
                    fired = true;
                }
                Outcome::Complete(value) => {
                    assert_eq!(value.value(), &expected);
                    assert_eq!(fired, injection.is_some());
                    boundaries.get_or_insert(construct.snapshot().admission_points);
                    assert_no_replay(construct.events());
                    drop(construct);
                    assert!(pool.live() >= 65536);
                    drop(value);
                    assert_eq!(pool.live(), 0);
                    completed = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(completed, "typed construction stalled at {injection:?}");
    }
}

#[test]
fn derived_schema_rejects_missing_unknown_duplicate_and_wrong_type_fields() {
    for bytes in [
        &[0xa0][..],
        &[0xa2, 0x00, 0x00, 0x01, 0x40],
        &[0xa3, 0x00, 0x60, 0x01, 0x40, 0x03, 0xf5],
        &[0xa3, 0x00, 0x60, 0x00, 0x60, 0x01, 0x40],
    ] {
        let pool = pool();
        let mut construct =
            Construct::<Record>::new(bytes.to_vec().into_boxed_slice(), policy(), pool.clone())
                .unwrap();
        let mut rejected = false;
        for _ in 0..4096 {
            match construct.step(&mut budget()) {
                Outcome::Progress => {}
                Outcome::Invalid(_) => {
                    rejected = true;
                    break;
                }
                other => panic!("schema accepted/deferred {bytes:x?}: {other:?}"),
            }
        }
        assert!(rejected);
        drop(construct);
        assert_eq!(pool.live(), 0);
    }
}
