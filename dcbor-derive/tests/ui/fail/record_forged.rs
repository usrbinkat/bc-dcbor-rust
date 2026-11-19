// A binding cannot forge the record of its value: `Initialized`'s fields are
// private (E0451), so a record is minted only from its context's assembly,
// unsafely. Control: tests/data/controls/record-fields-public.patch.
use core::marker::PhantomData;
use dcbor::bounded::decode::construction::in_place::Initialized;

fn forged() -> Initialized<'static, u64> {
    Initialized {
        place: 0,
        bound: true,
        marker: PhantomData,
    }
}

fn main() {
    let _ = forged;
}
