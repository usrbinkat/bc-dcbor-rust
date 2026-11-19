// A binding cannot present one record twice: `Initialized` is neither
// `Clone` nor `Copy` (E0599), so each record is consumed by the one check it
// reaches. Control: tests/data/controls/record-clone-derived.patch.
use dcbor::bounded::decode::construction::in_place::Initialized;

fn duplicated<'b>(record: Initialized<'b, u64>) -> (Initialized<'b, u64>, Initialized<'b, u64>) {
    (record.clone(), record)
}

fn main() {
    let _ = duplicated;
}
