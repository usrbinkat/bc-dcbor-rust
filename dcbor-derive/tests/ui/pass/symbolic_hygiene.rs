#![deny(warnings)]
use dcbor::{CBORBoundedEncodable, CBORCodable, CBOR};

#[derive(Clone, CBORCodable, CBORBoundedEncodable)]
struct Record<A, B, P>
where
    A: Clone,
{
    #[cbor(n = 0)]
    map: A,
    #[cbor(n = 1)]
    inner_map: B,
    #[cbor(n = 2)]
    v: Option<P>,
}

#[derive(Clone, CBORCodable, CBORBoundedEncodable)]
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
    },
    #[cbor(n = 1)]
    Pair(A, B),
}

#[derive(Clone, CBORCodable, CBORBoundedEncodable)]
struct Wrapper<A>(A);

#[derive(Clone, CBORCodable, CBORBoundedEncodable)]
enum Empty {}

fn main() {
    let value = Record {
        map: 1u64,
        inner_map: 2u64,
        v: Some(3u64),
    };
    let cbor = CBOR::from(value);
    assert_eq!(cbor.to_cbor_data(), [0xa3, 0, 1, 1, 2, 2, 3]);
    let _: Record<u64, u64, u64> = cbor.try_into().unwrap();
    let value = Choice::Item {
        map: 1u64,
        inner_map: 2u64,
        v: Some(3u64),
        f0: true,
    };
    let cbor = CBOR::from(value);
    assert_eq!(
        cbor.to_cbor_data(),
        [0x82, 0, 0xa4, 0, 1, 1, 2, 2, 3, 3, 0xf5]
    );
    let _: Choice<u64, u64, u64> = cbor.try_into().unwrap();
    let _: Choice<u64, u64, u64> = CBOR::from(Choice::<u64, u64, u64>::Pair(1, 2))
        .try_into()
        .unwrap();
    let _: Wrapper<u64> = CBOR::from(Wrapper(1u64)).try_into().unwrap();
    assert!(Empty::try_from(CBOR::from(0)).is_err());
}
