// A derived, generic record whose fields' costs together do not fit in u64:
// its generated `COST` (`const_cost!` over the field engine's checked
// composition) fails to compile where the record is instantiated with a
// concrete payload and allocator.
#[path = "../support/huge.rs"]
mod huge;

use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::InPlace;

#[derive(dcbor::CBORBoundedDecodable)]
struct Pair<T> {
    #[cbor(n = 0)]
    first: T,
    #[cbor(n = 1)]
    second: T,
}

fn main() {
    let _ = <Pair<huge::Huge> as InPlace<Limits>>::COST;
}
