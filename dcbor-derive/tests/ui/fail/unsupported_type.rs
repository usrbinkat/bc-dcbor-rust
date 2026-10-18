use dcbor::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
struct Unsupported(std::collections::VecDeque<bool>);

fn main() {}
