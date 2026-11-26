pub struct Policy;
// SAFETY: this resource-free policy never allocates or unwinds and admits all
// work.
unsafe impl dcbor::bounded::TerminalAllocator for Policy {
    fn terminal(_: &()) -> Self {
        Self
    }
}
// A policy that records nothing: its credit origin is the unit type, which
// settles nothing, and every identity it mints is unobserved.
impl dcbor::bounded::Budget for Policy {
    type Refusal = ();
    fn traverse(&mut self, _: u64, _: u64) -> Result<(), ()> {
        Ok(())
    }
    type Origin = ();
    fn origin(&self) {}
    fn admitted(&mut self, _: dcbor::bounded::WriteWork) {}
    fn identify(&mut self) -> Result<dcbor::bounded::Identity, ()> {
        Ok(dcbor::bounded::Identity::UNOBSERVED)
    }
    fn held(&mut self, _: dcbor::bounded::WriteWork, _: dcbor::bounded::Hold) {}
    fn effect(&mut self, _: dcbor::bounded::Effect) {}
    fn owner(&mut self) -> Result<dcbor::bounded::Owner, ()> {
        Ok(dcbor::bounded::Owner::unobserved())
    }
    fn acquisition(
        &mut self,
        owner: &dcbor::bounded::Owner,
    ) -> Result<dcbor::bounded::Acquisition<()>, ()> {
        dcbor::bounded::Acquisition::unobserved(owner).ok_or(())
    }
    fn validate_owner(&mut self, _: &dcbor::bounded::Owner) -> Result<(), ()> {
        Ok(())
    }
    fn performer(&self) -> dcbor::bounded::Performer {
        dcbor::bounded::Performer::None
    }
}
impl dcbor::bounded::Releasing for Policy {
    type Permit = ();
    fn reclaim(&mut self, _: u64, _: u64) -> Result<(), ()> {
        Ok(())
    }
    fn permit_identity(_: &()) -> dcbor::bounded::Identity {
        dcbor::bounded::Identity::UNOBSERVED
    }
    fn custody(_: &(), _: dcbor::bounded::Identity, _: dcbor::bounded::RecordStage) {}
}
impl dcbor::bounded::Allocator for Policy {
    fn allocate(&mut self, _: u64) -> Result<(), ()> {
        Ok(())
    }
}
