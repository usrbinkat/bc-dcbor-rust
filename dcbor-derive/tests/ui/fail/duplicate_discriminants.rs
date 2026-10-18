use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
enum Duplicate {
    #[cbor(n = 2)]
    First,
    #[cbor(n = 2)]
    Second(u64),
}
fn main() {}
