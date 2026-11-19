// A recorded origin cannot hold an unobserved capability: the unobserved
// constructor exists for the unrecorded origin `()` alone (E0599), so a
// capability of a recorded family is always minted by its budget, its end
// published through that family.
use dcbor::bounded::{Acquisition, Family, Owner};

fn unobserved(owner: &Owner) -> Option<Acquisition<Family>> {
    Acquisition::<Family>::unobserved(owner)
}

fn main() {
    let _ = unobserved;
}
