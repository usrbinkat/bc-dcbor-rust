// A binding cannot report `Done` without taking on its record's obligation:
// the record is minted only by `Assembly::assemble`, an unsafe function whose
// contract is the binding's coverage (E0133). Control:
// tests/data/controls/record-assembly-safe.patch.
use dcbor::bounded::decode::construction::in_place::{Assembly, Building};

fn unproven<'b>(assembly: Assembly<'b, u64>) -> Building<'b, u64> {
    Building::Done(assembly.assemble())
}

fn main() {
    let _ = unproven;
}
