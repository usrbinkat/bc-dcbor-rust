pub struct Policy;
impl dcbor::bounded::Budget for Policy {
    type Refusal = ();
    fn traverse(&mut self, _: u64, _: u64) -> Result<(), ()> {
        Ok(())
    }
}
impl dcbor::bounded::Allocator for Policy {
    type Permit = ();
    fn allocate(&mut self, _: u64) -> Result<(), ()> {
        Ok(())
    }
}
