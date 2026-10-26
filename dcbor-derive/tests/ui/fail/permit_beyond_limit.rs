// A permit of more than PERMIT_BYTES: requesting an allocation held with it
// fails to compile, so no arena or record can ever hold one.
use dcbor::bounded::{Allocator, Budget, Owned};

struct Wide([u64; 3]);

struct Policy;

impl Budget for Policy {
    type Refusal = ();

    fn traverse(&mut self, _: u64, _: u64) -> Result<(), ()> {
        Ok(())
    }
}

impl Allocator for Policy {
    type Permit = Wide;

    fn allocate(&mut self, _: u64) -> Result<Wide, ()> {
        Ok(Wide([0; 3]))
    }
}

fn main() {
    let mut arena = Owned::<u8, Wide>::new();
    assert!(arena.reserve(1, &mut Policy).is_ok());
}
