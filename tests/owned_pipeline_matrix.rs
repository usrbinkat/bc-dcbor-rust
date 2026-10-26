//! The owned pipeline end to end in one scope: input acquisition, typed
//! decoding, owned preparation and chunked emission. Every admission is
//! refused once and resumed without replay, every physical acquisition fails
//! with exact recovery, and at the boundaries the layer selects
//! ([`dcbor_test_support::rigor`]) the consumer retires what it holds,
//! unwinds, or cancels the operation in progress. Each value states its
//! stop classes: by its construction state's declared cleanup reduction
//! where it has one, by its parse alone where it has none.
#![cfg(feature = "std")]
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::encoding::TransferableSchema;
use dcbor_test_support::classes::{self, Classes, Typed};
use dcbor_test_support::heap;
use dcbor_test_support::pipeline::{Expected, encode, matrix};
use dcbor_test_support::rigor::rigor;

/// The fault matrix of `T` decoded from `wire` and encoded back to it, its
/// stops classed by `classes`.
fn pipeline<T: Transferable<Limits> + TransferableSchema + 'static>(
    name: &str,
    wire: &[u8],
    expected: Expected,
    classes: Classes<Typed<T>>,
) {
    matrix(
        &format!("{name}: {} from {wire:02x?}", core::any::type_name::<T>()),
        rigor(),
        expected,
        |schedule| encode::<T>(wire, schedule, &classes),
    );
}

#[test]
fn scalar_pipeline_distinguishes_turn_exhaustion_from_injected_refusals() {
    // This is also the recorder's u64 fixture. Prepaid acquisition work can
    // span fresh turns even without a fault schedule; the matrix checks all
    // attempts against admitted calls plus actual policy refusals and injects
    // exactly one refusal per successful admission in its one-pass run.
    pipeline::<u64>(
        "scalar with retained acquisition admissions",
        &[0x19, 0x01, 0x00],
        Expected::Complete,
        classes::reduced::<u64>(),
    );
}

#[test]
fn text_survives_every_admission_physical_failure_and_stop() {
    pipeline::<String>(
        "text",
        &dcbor::CBOR::from("\u{301}".repeat(16)).to_cbor_data(),
        Expected::Complete,
        classes::reduced::<String>(),
    );
}

#[test]
fn vector_children_survive_every_admission_physical_failure_and_stop() {
    // ["q\u{301}", "b"] crosses parsing, normalization, the document's
    // transfer, vector child construction and pre-publication cleanup.
    pipeline::<Vec<String>>(
        "vector",
        &[0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'],
        Expected::Complete,
        classes::parsed::<Vec<String>>(),
    );
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn tree_nodes_and_partial_children_survive_every_pipeline_boundary() {
    use std::collections::BTreeMap;
    // Canonical CBOR orders these text keys by encoded length. Rust orders
    // them lexicographically, so construction must reorder document indices.
    let mut map = dcbor::Map::new();
    map.insert("z", "short");
    map.insert("aa", "q\u{301}");
    pipeline::<BTreeMap<String, String>>(
        "reordered tree",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<BTreeMap<String, String>>(),
    );
    pipeline::<BTreeMap<String, String>>(
        "empty tree",
        &[0xa0],
        Expected::Complete,
        classes::parsed::<BTreeMap<String, String>>(),
    );
    let mut internal = dcbor::Map::new();
    for n in 0..12u64 {
        internal.insert(n, n);
    }
    pipeline::<BTreeMap<u64, u64>>(
        "internal node",
        &dcbor::CBOR::from(internal).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<BTreeMap<u64, u64>>(),
    );
    // Both remaining scalar key bindings use the same numeric view but
    // distinct source-kind/range validation.
    pipeline::<BTreeMap<bool, bool>>(
        "boolean keys",
        &[0xa2, 0xf4, 0xf5, 0xf5, 0xf4],
        Expected::Complete,
        classes::parsed::<BTreeMap<bool, bool>>(),
    );
    pipeline::<BTreeMap<usize, bool>>(
        "usize keys",
        &[0xa2, 0x00, 0xf4, 0x18, 0x18, 0xf5],
        Expected::Complete,
        classes::parsed::<BTreeMap<usize, bool>>(),
    );
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn tree_key_comparison_resumes_across_multiple_byte_quanta() {
    use std::collections::BTreeMap;
    // Both the equal prefix and the final decision cross 32-byte comparison
    // chunks. The shorter key is later in Rust order, forcing a permutation
    // of canonical CBOR order. The third key exercises the prefix-length tie.
    let prefix = "a".repeat(65);
    let mut map = dcbor::Map::new();
    map.insert(prefix.clone(), 0u64);
    map.insert(format!("{prefix}z"), 1u64);
    map.insert(format!("{prefix}aa"), 2u64);
    pipeline::<BTreeMap<String, u64>>(
        "long shared prefixes",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<BTreeMap<String, u64>>(),
    );
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn nested_tree_values_retain_custody_at_every_pipeline_boundary() {
    use std::collections::BTreeMap;
    let mut child = dcbor::Map::new();
    child.insert("z", "last");
    child.insert("aa", "first");
    let mut map = dcbor::Map::new();
    map.insert(0u64, child);
    map.insert(1u64, dcbor::Map::new());
    pipeline::<BTreeMap<u64, BTreeMap<String, String>>>(
        "nested trees",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<BTreeMap<u64, BTreeMap<String, String>>>(),
    );
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn tree_wrong_value_reclaims_completed_and_partial_entries() {
    use std::collections::BTreeMap;
    // The first string pair completes; the second key completes before its
    // integer value is rejected by String construction.
    pipeline::<BTreeMap<String, String>>(
        "tree with a wrong value",
        &[0xa2, 0x61, b'a', 0x62, b'o', b'k', 0x61, b'b', 0x00],
        Expected::Invalid,
        classes::parsed::<BTreeMap<String, String>>(),
    );
}

#[test]
fn stable_optional_acquisitions_survive_every_admission_physical_failure_and_stop() {
    pipeline::<StableOption<String, Limits>>(
        "present stable option",
        &[0x63, b'q', 0xcc, 0x81],
        Expected::Complete,
        classes::reduced::<StableOption<String, Limits>>(),
    );
    pipeline::<StableOption<String, Limits>>(
        "null stable option",
        &[0xf6],
        Expected::Complete,
        classes::reduced::<StableOption<String, Limits>>(),
    );
}

#[test]
fn rejected_inputs_clean_up_their_decode_and_never_reach_preparation() {
    // Not NFC: the combining mark follows a composable base.
    pipeline::<String>(
        "decomposed text",
        &[0x63, b'e', 0xcc, 0x81],
        Expected::Invalid,
        classes::reduced::<String>(),
    );
    // A byte string is not text.
    pipeline::<String>(
        "byte string as text",
        &[0x41, 0x00],
        Expected::Invalid,
        classes::reduced::<String>(),
    );
}
