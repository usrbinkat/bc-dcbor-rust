use super::*;
use dcbor::bounded::decode::construction::in_place::{Construction, InPlace, Step};
use dcbor::bounded::decode::{DecodeError, decode};

#[path = "enumeration.rs"]
mod enumeration;

fn fixture<T: InPlace<Turn> + 'static>(wire: &[u8], inspect: impl Fn(&T), invalid: bool) {
    let mut a = Turn::new();
    a.values = u64::MAX;
    a.bytes = u64::MAX;
    let document = decode(wire, 8, &mut a).unwrap();
    let baseline = a.live.load(Ordering::SeqCst);
    let owner = Reclaimer::new();
    let mut operation = Construction::<T, Turn>::new(&owner, &document, 0);
    let mut failed = false;
    let mut terminal = false;
    for _ in 0..512 {
        // Each transition first observes refusal with no released reservations.
        let held = a.live.load(Ordering::SeqCst);
        a.values = 0;
        a.bytes = 0;
        match operation.step(&mut a) {
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {}
            Ok(Step::Finished) if failed => {
                terminal = true;
                break;
            }
            _ => panic!("transition did work without admission"),
        }
        assert_eq!(a.live.load(Ordering::SeqCst), held);
        a.fresh();
        match operation.step(&mut a) {
            Ok(Step::Progress) => {}
            Ok(Step::Complete(value)) => {
                assert!(!invalid);
                inspect(value.value());
                drop(value);
                terminal = true;
                break;
            }
            Err(DecodeError::Invalid(_)) => {
                assert!(invalid);
                assert!(!failed, "terminal error replayed");
                failed = true;
            }
            _ => panic!("unexpected schema transition"),
        }
    }
    drop(operation);
    for _ in 0..512 {
        a.fresh();
        if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
            break;
        }
    }
    assert!(terminal);
    assert_eq!(failed, invalid);
    assert!(a.refused > 0);
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(a.live.load(Ordering::SeqCst), baseline);
    drop(document);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
}

#[test]
fn tagged_newtype_and_unit_have_separate_payload_custody() {
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Text(String);
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Unit;
    fixture::<Text>(&[0xd8, 42, 0x61, b'x'], |v| assert_eq!(v.0, "x"), false);
    fixture::<Text>(
        &[0xd8, 43, 0x61, b'x'],
        |_| panic!("wrong tag published"),
        true,
    );
    fixture::<Unit>(&[0xd8, 42, 0xf6], |_| {}, false);
    fixture::<Unit>(&[0xd8, 43, 0xf6], |_| panic!("wrong tag published"), true);
}

#[test]
fn optional_omission_and_present_payload_are_distinct() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Fields {
        #[cbor(n = 0)]
        before: Option<u64>,
        #[cbor(n = 1)]
        required: u64,
        #[cbor(n = 2)]
        after: Option<String>,
    }
    fixture::<Fields>(
        &[0xa1, 1, 7],
        |v| {
            assert_eq!(v.before, None);
            assert_eq!(v.required, 7);
            assert_eq!(v.after, None);
        },
        false,
    );
    fixture::<Fields>(
        &[0xa3, 0, 9, 1, 7, 2, 0x61, b'x'],
        |v| {
            assert_eq!(v.before, Some(9));
            assert_eq!(v.required, 7);
            assert_eq!(v.after.as_deref(), Some("x"));
        },
        false,
    );
    fixture::<Fields>(&[0xa2, 0, 0xf6, 1, 7], |_| panic!("null published"), true);
    fixture::<Fields>(
        &[0xa0],
        |_| panic!("missing required field published"),
        true,
    );
}
