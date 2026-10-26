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

/// Construct `T` from `wire`, retiring the construction after `stop` turns:
/// retirement releases nothing synchronously, and the scope's queued cleanup
/// takes every unit refused once, releasing nothing, before it is admitted,
/// then recovers everything. Both are within the decode's own bound. The
/// turns construction took to publish, when it published within `stop`.
fn retired<T: Transferable<Limits> + 'static>(wire: &[u8], stop: usize) -> Option<usize> {
    let bound = support::typed_turns::<T>(wire.len());
    let mut m = meter();
    let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
    let mut operation = Construction::<_, T, Limits>::construct(document);
    let mut output = None;
    let mut published = None;
    for turn in 0..stop.min(bound) {
        match support::checked(&mut m, |m| support::contracted(m, &mut operation)) {
            Ok(Step::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(Step::Complete(value)) => {
                support::exhausted(&mut m, &mut operation);
                output = Some(value);
                published = Some(turn + 1);
                break;
            }
            _ => panic!("publication omitted"),
        }
    }
    let held = m.live_bytes();
    drop(operation);
    drop(output);
    assert_eq!(m.live_bytes(), held, "retirement released storage");
    // Every queued cleanup unit is first refused without release.
    let mut drained = false;
    for _ in 0..bound {
        m.clear_refusal();
        m.exhaust();
        let held = m.live_bytes();
        if owner.outstanding() != 0 {
            match owner.shutdown_step(&mut m) {
                Err(BoundedError::Refused(_)) => assert_eq!(m.live_bytes(), held),
                Ok(Reclaimed::Progress) => assert!(m.live_bytes() < held),
                Ok(Reclaimed::Done) => {
                    drained = true;
                    break;
                }
                other => panic!("unexpected cleanup: {other:?}"),
            }
        }
        if support::checked(&mut m, |m| owner.shutdown_step(m)).unwrap() == Reclaimed::Done {
            drained = true;
            break;
        }
    }
    assert!(drained, "cleanup exceeded its bound of {bound} turns");
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(m.live_bytes(), 0);
    published
}

/// The enumeration constructed from `wire` retired after every number of
/// turns through its publication ([`support::stop_matrix`]): publication is
/// reached within the decode's bound, and exactly the stops at or past it
/// publish.
fn cancellation<T: Transferable<Limits> + 'static>(wire: &[u8]) {
    let boundaries = retired::<T>(wire, usize::MAX)
        .expect("enumeration never reached publication within its bound");
    support::stop_matrix(
        &format!(
            "retired construction of {} from {wire:02x?}",
            core::any::type_name::<T>()
        ),
        boundaries,
        |stop| {
            assert_eq!(
                retired::<T>(wire, stop).is_some(),
                stop == boundaries,
                "a stop after {stop} turns"
            );
        },
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
