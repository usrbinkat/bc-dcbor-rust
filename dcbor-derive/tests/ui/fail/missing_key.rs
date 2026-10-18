use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
struct Missing {
    value: u64,
}
fn main() {}
