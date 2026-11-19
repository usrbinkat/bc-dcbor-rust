// A permit of more than PERMIT_BYTES: requesting an allocation held with it
// fails to compile, so no arena or record can ever hold one.
#[path = "../support/policy.rs"]
mod policy;

use dcbor::bounded::{Allocator, Budget, Identity, Owned, Owner, Releasing};

struct Wide([u64; 3]);

// The unit policy's admissions, a permit wider than PERMIT_BYTES.
struct Policy(policy::Policy);

impl Budget for Policy {
    type Refusal = ();
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> { self.0.traverse(values, bytes) }
    type Origin = ();
    fn origin(&self) {}
    fn admitted(&mut self, work: dcbor::bounded::WriteWork) { self.0.admitted(work) }
    fn identify(&mut self) -> Result<Identity, ()> { self.0.identify() }
    fn held(&mut self, work: dcbor::bounded::WriteWork, hold: dcbor::bounded::Hold) { self.0.held(work, hold) }
    fn effect(&mut self, effect: dcbor::bounded::Effect) { self.0.effect(effect) }
    fn owner(&mut self) -> Result<Owner, ()> { self.0.owner() }
    fn acquisition(&mut self, owner: &Owner) -> Result<dcbor::bounded::Acquisition<()>, ()> { self.0.acquisition(owner) }
    fn validate_owner(&mut self, owner: &Owner) -> Result<(), ()> { self.0.validate_owner(owner) }
    fn performer(&self) -> dcbor::bounded::Performer { self.0.performer() }
}

impl Releasing for Policy {
    type Permit = Wide;
    fn permit_identity(_: &Wide) -> Identity { Identity::UNOBSERVED } fn custody(_: &Wide, _: Identity, _: dcbor::bounded::RecordStage) {}
}
impl Allocator for Policy { fn allocate(&mut self, _: u64) -> Result<Wide, ()> { Ok(Wide([0; 3])) } }

fn main() {
    let mut arena = Owned::<u8, Wide>::new();
    assert!(arena.reserve(1, &mut Policy(policy::Policy), &Owner::unobserved()).is_ok());
}
