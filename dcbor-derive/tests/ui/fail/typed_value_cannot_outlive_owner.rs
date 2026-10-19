#[path = "../support/policy.rs"]
mod policy;

fn main() {
    let borrowed;
    {
        let value = dcbor::bounded::decode::decode_typed::<String, _>(
            &[0x61, b'a'],
            8,
            &mut policy::Policy,
        )
        .unwrap();
        borrowed = value.value();
    }
    println!("{borrowed}");
}
