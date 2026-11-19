#![deny(warnings)]
use std::collections::BTreeMap;

use dcbor::{CBORBoundedEncodable, CBORCodable, CBOREncodable, CBOR};

// Field names that the expansion's own bindings could capture (`map`,
// `inner_map`, `v`, `f0`, `value`), generic fields bounded only by what the
// encoding needs, and no `Clone` anywhere: the symbolic encoding reads every
// field by reference.
#[derive(CBORCodable, CBORBoundedEncodable)]
struct Record<A, B, P> {
    #[cbor(n = 0)]
    map: A,
    #[cbor(n = 1)]
    inner_map: B,
    #[cbor(n = 2)]
    v: Option<P>,
    #[cbor(n = 3)]
    value: u64,
}

#[derive(CBORCodable, CBORBoundedEncodable)]
enum Choice<A, B, P> {
    #[cbor(n = 0)]
    Item {
        #[cbor(n = 0)]
        map: A,
        #[cbor(n = 1)]
        inner_map: B,
        #[cbor(n = 2)]
        v: Option<P>,
        #[cbor(n = 3)]
        f0: bool,
        #[cbor(n = 4)]
        value: u64,
    },
    #[cbor(n = 1)]
    Pair(A, B),
}

#[derive(CBORCodable, CBORBoundedEncodable)]
struct Wrapper<A>(A);

#[derive(CBORCodable, CBORBoundedEncodable)]
struct Unit;

#[derive(CBORCodable, CBORBoundedEncodable)]
enum Empty {}

/// A symbolic-only record whose generic field is a host map: its encoding
/// can fail, and the derive's bound is `CBOREncodable`, never `Into<CBOR>`.
#[derive(dcbor::CBOREncodable)]
struct Labels<M> {
    #[cbor(n = 0)]
    names: M,
}

/// The symbolic derives expand in the user's crate. Here every prelude name
/// their expansions could rely on is shadowed by an unrelated item: `Vec`,
/// `vec!`, `From`, `TryFrom`, `Iterator`, `IntoIterator`, `Option`, `Some`,
/// `None`, `Result`, `Ok` and `Err`. The expansions name only `dcbor`, its
/// hidden `__derive` functions and `::core` paths, so they compile here; and
/// trybuild runs this fixture (`check_pass`, `cargo run`), so `check`'s
/// assertions check the bytes they encode and that they decode them back.
/// A module of its own, so the shadows reach only these derives.
mod prelude_shadowed {
    #[expect(dead_code, reason = "the shadows exist only to be named by mistake")]
    mod shadowed {
        pub struct Vec;
        pub struct From;
        pub struct TryFrom;
        pub struct Iterator;
        pub struct IntoIterator;
        pub struct Option;
        pub struct Result;
        pub enum Shadow {
            Some,
            None,
            Ok,
            Err,
        }
    }

    #[expect(unused_imports, reason = "an expansion naming one would use it, and fail")]
    use shadowed::Shadow::{Err, None, Ok, Some};
    #[expect(unused_imports, reason = "an expansion naming one would use it, and fail")]
    use shadowed::{From, IntoIterator, Iterator, Option, Result, TryFrom, Vec};

    #[expect(unused_macros, reason = "an expansion invoking it fails to compile")]
    macro_rules! vec {
        ($($tokens:tt)*) => {
            compile_error!("the expansion named the user's `vec!`")
        };
    }

    #[derive(dcbor::CBORCodable)]
    struct Record {
        #[cbor(n = 0)]
        count: u64,
        #[cbor(n = 1)]
        note: ::core::option::Option<::std::string::String>,
        #[cbor(n = 2)]
        items: ::std::vec::Vec<u64>,
    }

    #[derive(dcbor::CBORCodable)]
    struct Newtype(u64);

    #[derive(dcbor::CBORCodable)]
    struct Unit;

    #[derive(dcbor::CBORCodable)]
    enum Choice {
        #[cbor(n = 0)]
        Point,
        #[cbor(n = 1)]
        Pair(u64, ::std::string::String),
        #[cbor(n = 2)]
        Named {
            #[cbor(n = 0)]
            value: ::core::option::Option<u64>,
        },
        #[cbor(n = 3)]
        Empty(),
    }

    #[derive(dcbor::CBORCodable)]
    enum Never {}

    #[derive(dcbor::CBORCodable)]
    #[cbor(tag = 40_002)]
    struct Tagged {
        #[cbor(n = 0)]
        count: u64,
    }

    pub fn check() {
        use dcbor::{CBOREncodable, CBORTaggedEncodable};

        let record = Record {
            count: 1,
            note: ::core::option::Option::Some("x".into()),
            items: ::std::vec![2, 3],
        };
        let bytes = record.encode_cbor_data().unwrap();
        assert_eq!(bytes, [0xa3, 0, 1, 1, 0x61, b'x', 2, 0x82, 2, 3]);
        let decoded = <Record as ::core::convert::TryFrom<dcbor::CBOR>>::try_from(
            dcbor::CBOR::try_from_data(&bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded.count, 1);
        assert_eq!(decoded.items, [2, 3]);
        assert_eq!(record.into_encoded_cbor().unwrap().to_cbor_data(), bytes);

        assert_eq!(Newtype(7).encode_cbor_data().unwrap(), [7]);
        assert_eq!(Unit.encode_cbor_data().unwrap(), [0xf6]);
        for (choice, expected) in [
            (Choice::Point, &[0u8][..]),
            (Choice::Pair(1, "y".into()), &[0x83, 1, 1, 0x61, b'y'][..]),
            (
                Choice::Named {
                    value: ::core::option::Option::None,
                },
                &[0x82, 2, 0xa0][..],
            ),
            (Choice::Empty(), &[0x81, 3][..]),
        ] {
            let bytes = choice.encode_cbor_data().unwrap();
            assert_eq!(bytes, expected);
            let decoded = <Choice as ::core::convert::TryFrom<dcbor::CBOR>>::try_from(
                dcbor::CBOR::try_from_data(&bytes).unwrap(),
            )
            .unwrap();
            assert_eq!(decoded.encode_cbor_data().unwrap(), bytes);
        }
        assert!(
            <Never as ::core::convert::TryFrom<dcbor::CBOR>>::try_from(dcbor::CBOR::from(0u64))
                .is_err()
        );
        let tagged = Tagged { count: 4 }.tagged_cbor_data().unwrap();
        assert_eq!(tagged, [0xd9, 0x9c, 0x42, 0xa1, 0, 4]);
    }
}

fn main() -> dcbor::Result<()> {
    prelude_shadowed::check();
    let value = Record {
        map: 1u64,
        inner_map: 2u64,
        v: Some(3u64),
        value: 4,
    };
    let cbor = value.encode_cbor()?;
    assert_eq!(cbor.to_cbor_data(), [0xa4, 0, 1, 1, 2, 2, 3, 3, 4]);
    let _: Record<u64, u64, u64> = cbor.try_into()?;
    let value = Choice::Item {
        map: 1u64,
        inner_map: 2u64,
        v: Some(3u64),
        f0: true,
        value: 4,
    };
    let cbor = value.encode_cbor()?;
    assert_eq!(
        cbor.to_cbor_data(),
        [0x82, 0, 0xa5, 0, 1, 1, 2, 2, 3, 3, 0xf5, 4, 4]
    );
    let _: Choice<u64, u64, u64> = cbor.try_into()?;
    let _: Choice<u64, u64, u64> = Choice::<u64, u64, u64>::Pair(1, 2)
        .encode_cbor()?
        .try_into()?;
    let _: Wrapper<u64> = Wrapper(1u64).encode_cbor()?.try_into()?;
    assert_eq!(Unit.encode_cbor_data()?, [0xf6]);
    assert!(Empty::try_from(CBOR::from(0)).is_err());
    let names = BTreeMap::from([("\u{e9}".to_string(), 1u8), ("e\u{301}".to_string(), 2)]);
    assert!(matches!(
        Labels { names }.encode_cbor(),
        Err(dcbor::Error::DuplicateMapKey)
    ));
    Ok(())
}
