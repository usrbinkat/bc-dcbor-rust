#![deny(warnings)]
use dcbor::{
    bounded::{encode, Limits},
    CBORBoundedEncodable,
};

#[derive(CBORBoundedEncodable)]
struct StandaloneOption(Option<bool>);

fn main() {
    let mut limits = Limits::new(100, 100, 100);
    assert_eq!(
        encode(&StandaloneOption(None), &mut limits)
            .unwrap()
            .as_ref(),
        &[0xf6]
    );
    assert_eq!(
        encode(&StandaloneOption(Some(true)), &mut limits)
            .unwrap()
            .as_ref(),
        &[0xf5]
    );
}
