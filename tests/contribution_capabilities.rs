//! Positive compile contracts for required downstream capabilities.
//! These are intentionally ordinary, registered tests: missing implementations
//! must fail compilation rather than appear as ignored or compile-fail successes.
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::{InPlace, StableOption};
use dcbor::bounded::decode::construction::{
    Borrowed, DecodeInput, DecodeOwner, TypedDecoder, TypedValue,
};
use dcbor::bounded::encoding::Schema;

fn schema<T: Schema>() {}
fn construct<T: InPlace<Limits>>() {}
fn transferable<T: Send>() {}

#[test]
fn ordered_and_stable_representations_have_schema_support() {
    // Ordered trees are walked by the bounded-collection standard library's
    // stepped cursor, as hash maps use its bucket access.
    #[cfg(feature = "custom-std-collections")]
    {
        schema::<std::collections::BTreeMap<u64, u64>>();
        schema::<dcbor::Map>();
        schema::<dcbor::CBOR>();
    }
    schema::<StableOption<u64, Limits>>();
}

#[test]
fn fixed_arrays_have_in_place_construction() {
    construct::<[u8; 16]>();
    construct::<[u8; 32]>();
}

#[test]
fn owned_lifecycle_can_transfer_with_send_input_and_permits() {
    fn input<T: DecodeInput<Limits>>() {}
    input::<dcbor::ByteString>();
    input::<Borrowed<'static>>();
    transferable::<DecodeOwner<'static, Limits>>();
    transferable::<TypedDecoder<'static, dcbor::ByteString, u64, Limits>>();
    transferable::<TypedValue<'static, dcbor::ByteString, u64, Limits>>();
}
