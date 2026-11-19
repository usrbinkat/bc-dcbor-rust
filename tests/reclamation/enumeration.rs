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

/// The enumeration constructed from `wire` retired after every number of
/// turns through its publication ([`support::stop_matrix`]), its queued
/// cleanup's every unit first refused without release
/// ([`super::super::retired`]): publication is reached within the decode's
/// bound, and exactly the stops at or past it publish.
fn cancellation<T: Transferable<Limits> + 'static>(wire: &[u8]) {
    let retired = |stop| {
        super::super::retired::<T>(wire, stop, super::super::Discipline::RefusedFirst, |_| {})
    };
    let boundaries = retired(usize::MAX)
        .0
        .expect("enumeration never reached publication within its bound");
    support::stop_matrix(
        &format!(
            "retired construction of {} from {wire:02x?}",
            core::any::type_name::<T>()
        ),
        boundaries,
        |stop| {
            let (published, reached) = retired(stop);
            assert_eq!(
                published.is_some(),
                stop == boundaries,
                "a stop after {stop} turns"
            );
            reached
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
