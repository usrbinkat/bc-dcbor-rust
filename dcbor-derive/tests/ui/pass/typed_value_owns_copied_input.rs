#![deny(warnings)]
#[path = "../support/policy.rs"]
mod policy;

fn main() {
    let value = {
        let input = vec![0x61, b'a'];
        dcbor::bounded::decode::decode_typed::<String, _>(&input, 8, &mut policy::Policy).unwrap()
    };
    assert_eq!(value.value(), "a");
}
