#[path = "../support/policy.rs"]
mod policy;

fn main() {
    let mut input = vec![0x61, b'a'];
    let document = dcbor::bounded::decode::decode(&input, 8, &mut policy::Policy).unwrap();
    input[1] = b'b';
    println!("{:?}", document.root().kind());
}
