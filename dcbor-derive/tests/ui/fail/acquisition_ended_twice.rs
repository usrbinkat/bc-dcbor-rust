// An acquisition ends once: `Acquisition::end` consumes the capability, so a
// second end is a use of a moved value (E0382).
use dcbor::bounded::{Acquisition, Family, Performer};

fn ended_twice(acquisition: Acquisition<Family>) {
    acquisition.end(Performer::None);
    acquisition.end(Performer::None);
}

fn main() {
    let _ = ended_twice;
}
