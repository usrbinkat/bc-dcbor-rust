use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
struct RepeatedKey {
    #[cbor(n = 0, n = 1)]
    field: u64,
}

#[derive(CBORBoundedEncodable)]
#[cbor(tag = 1)]
#[cbor(tag = 2)]
struct RepeatedTag;

#[derive(CBORBoundedEncodable)]
struct RepeatedField {
    #[cbor(n = 0)]
    #[cbor(n = 1)]
    field: u64,
}

#[derive(CBORBoundedEncodable)]
#[cbor(tag = 0, n = 1)]
struct Contradictory;

fn main() {}
