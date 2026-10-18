use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
struct Duplicate {
    #[cbor(n = 1)]
    first: u64,
    #[cbor(n = 1)]
    second: u64,
}
fn main() {}
