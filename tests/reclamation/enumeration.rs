use super::*;

macro_rules! representation_matrix {
    ($test:ident, $($repr:ident),+) => {
        #[test]
        fn $test() {
            #[derive(dcbor::CBORBoundedDecodable)]
            #[repr($($repr),+)]
            enum Message {
                #[cbor(n = 0)]
                Empty,
                #[cbor(n = 10)]
                Pair(u64, String),
                #[cbor(n = 20)]
                Named {
                    #[cbor(n = 1)]
                    number: u64,
                    #[cbor(n = 2)]
                    text: Option<String>,
                },
            }
            fixture::<Message>(&[0], |v| assert!(matches!(v, Message::Empty)), false);
            fixture::<Message>(&[0x83, 10, 7, 0x61, b'x'], |v| match v {
                Message::Pair(n, text) => { assert_eq!(*n, 7); assert_eq!(text, "x"); }
                _ => panic!("wrong tuple variant"),
            }, false);
            fixture::<Message>(&[0x82, 20, 0xa1, 1, 7], |v| match v {
                Message::Named { number, text } => {
                    assert_eq!(*number, 7);
                    assert_eq!(text, &None);
                }
                _ => panic!("wrong named variant"),
            }, false);
            fixture::<Message>(&[0x82, 20, 0xa2, 1, 7, 2, 0x61, b'x'], |v| match v {
                Message::Named { number, text } => {
                    assert_eq!(*number, 7);
                    assert_eq!(text.as_deref(), Some("x"));
                }
                _ => panic!("wrong named variant"),
            }, false);
            for wire in [&[0x18, 99][..], &[0x82, 10, 7], &[0x82, 20, 0xa0],
                &[0x83, 10, 7, 0xf6], &[0x82, 20, 0xa2, 1, 7, 2, 0xf6]] {
                fixture::<Message>(wire, |_| panic!("invalid variant published"), true);
            }
            cancellation::<Message>(&[0x83, 10, 7, 0x61, b'x']);
            cancellation::<Message>(&[0x82, 20, 0xa2, 1, 7, 2, 0x61, b'x']);
        }
    };
}

representation_matrix!(primitive_layout, u8);
representation_matrix!(c_layout, C);
representation_matrix!(c_primitive_layout, C, u8);

fn cancellation<T: InPlace<Turn> + 'static>(wire: &[u8]) {
    let mut observed_publication = false;
    // Each successive run cancels one transition later. Stop only after the
    // publication boundary has actually been reached, not at a guessed count.
    for stop in 0..512 {
        let mut a = Turn::new();
        a.values = u64::MAX;
        a.bytes = u64::MAX;
        let document = decode(wire, 8, &mut a).unwrap();
        let baseline = a.live.load(Ordering::SeqCst);
        let owner = Reclaimer::new();
        let mut operation = Construction::<T, Turn>::new(&owner, &document, 0);
        let mut output = None;
        for _ in 0..stop {
            a.fresh();
            match operation.step(&mut a).unwrap() {
                Step::Progress => {}
                Step::Complete(value) => {
                    output = Some(value);
                    observed_publication = true;
                    break;
                }
                Step::Finished => panic!("publication omitted"),
            }
        }
        let held = a.live.load(Ordering::SeqCst);
        drop(operation);
        drop(output);
        assert_eq!(a.live.load(Ordering::SeqCst), held);
        for _ in 0..512 {
            a.values = 0;
            a.bytes = 0;
            let held = a.live.load(Ordering::SeqCst);
            if owner.outstanding() != 0 {
                assert!(matches!(
                    owner.shutdown_step(&mut a),
                    Err(BoundedError::Refused(()))
                ));
                assert_eq!(a.live.load(Ordering::SeqCst), held);
            }
            a.fresh();
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                break;
            }
        }
        assert_eq!(owner.outstanding(), 0);
        assert_eq!(a.live.load(Ordering::SeqCst), baseline);
        drop(document);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
        if observed_publication {
            break;
        }
    }
    assert!(
        observed_publication,
        "enumeration never reached publication"
    );
}

#[test]
fn generic_tagged_enum_keeps_native_and_wire_discriminants_distinct() {
    #[derive(dcbor::CBORBoundedDecodable)]
    #[repr(C, u8)]
    #[cbor(tag = 42)]
    enum Generic<T> {
        #[cbor(n = 1000)]
        Value(T),
        #[cbor(n = 7)]
        Empty,
    }
    fixture::<Generic<u64>>(
        &[0xd8, 42, 0x82, 0x19, 3, 0xe8, 9],
        |v| match v {
            Generic::Value(n) => assert_eq!(*n, 9),
            _ => panic!("wrong variant"),
        },
        false,
    );
    fixture::<Generic<u64>>(
        &[0xd8, 42, 7],
        |v| assert!(matches!(v, Generic::Empty)),
        false,
    );
    fixture::<Generic<u64>>(&[0xd8, 43, 7], |_| panic!("wrong tag published"), true);
}
