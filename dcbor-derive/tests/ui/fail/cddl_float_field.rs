// A float field has no CDDL rule: its decoder accepts an integer exactly
// when the float represents it exactly, a set no CDDL type denotes, so the
// derive's bound on the field (`dcbor::cddl::Cddl`) is not met, and the
// diagnostic names why (`dcbor::cddl::Cddl`'s `on_unimplemented`).
use dcbor::CBORCddl;

#[derive(CBORCddl)]
struct Reading {
    #[cbor(n = 0)]
    celsius: f64,
}

fn main() {}
