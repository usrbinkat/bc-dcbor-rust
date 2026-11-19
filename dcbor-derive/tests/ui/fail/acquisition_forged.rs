// An acquisition capability cannot be forged from raw identities: its
// fields are private (E0451), so a recorded capability is minted only by its
// budget (`Budget::acquisition`), under the minting family's origin.
use dcbor::bounded::{Acquisition, Family, Identity};

fn forged(origin: Family) -> Acquisition<Family> {
    Acquisition {
        origin,
        id: Identity::new(1, 1),
        owner: Identity::new(1, 0),
    }
}

fn main() {
    let _ = forged;
}
