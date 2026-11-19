// An acquisition's owner is captured when it is minted and never replaced:
// `Acquisition::end` takes the performer alone (E0061), so no caller can
// publish the end under another owner.
use dcbor::bounded::{Acquisition, Family, Identity, Performer};

fn substituted(acquisition: Acquisition<Family>) {
    acquisition.end(Identity::new(1, 0), Performer::None);
}

fn main() {
    let _ = substituted;
}
