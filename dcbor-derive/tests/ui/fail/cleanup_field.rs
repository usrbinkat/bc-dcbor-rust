// The cleanup capability gives no route back to the policy it wraps by its
// field: the field is private (E0616). Control:
// tests/data/controls/cleanup-policy-public.patch.
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::reclamation::Cleanup;

fn reach<'c>(cleanup: &'c mut Cleanup<'_, Limits>) -> &'c mut Limits {
    cleanup.policy
}

fn main() {
    let _ = reach;
}
