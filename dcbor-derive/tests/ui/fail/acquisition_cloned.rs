// An acquisition capability is one authority: it is neither `Clone` nor
// `Copy` (E0599), so no second holder can publish its end.
use dcbor::bounded::{Acquisition, Family};

fn duplicated(acquisition: Acquisition<Family>) -> (Acquisition<Family>, Acquisition<Family>) {
    (acquisition.clone(), acquisition)
}

fn main() {
    let _ = duplicated;
}
