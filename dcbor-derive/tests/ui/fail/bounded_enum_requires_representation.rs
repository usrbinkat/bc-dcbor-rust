#[derive(dcbor::CBORBoundedDecodable)]
enum Message {
    #[cbor(n = 0)]
    Empty,
}

fn main() {}
