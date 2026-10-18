use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
struct Pair(u64, u64);

#[derive(CBORBoundedEncodable)]
struct KeyedTuple(#[cbor(n = 0)] u64);

#[derive(CBORBoundedEncodable)]
enum Discriminant {
    #[cbor(n = 0)]
    A = 1,
}

fn main() {}
