// The cleanup capability gives no route back to the policy it wraps by
// dereference: it implements no `Deref` (E0614). Control:
// tests/data/controls/cleanup-derefs-to-policy.patch.
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::reclamation::Cleanup;

fn reach<'c>(cleanup: &'c mut Cleanup<'_, Limits>) -> &'c mut Limits {
    &mut **cleanup
}

fn main() {
    let _ = reach;
}
