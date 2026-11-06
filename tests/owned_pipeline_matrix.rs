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
use dcbor::bounded::decode::construction::TypedPosition;
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::encoding::TransferableSchema;
use dcbor_test_support::classes::{self, Classes, Typed};
use dcbor_test_support::heap;
use dcbor_test_support::pipeline::{Expected, encode, matrix};
use dcbor_test_support::rigor::{Rigor, rigor};

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

/// The emission classes' planted control: every emission boundary merged
/// with the decode's first boundary, taken before its parse record exists,
/// whose cleanup is the input record's alone, every other classifier the
/// real one. That decode boundary is alone in its class otherwise, so only
/// the merge of the emission's boundaries with it can make the exhaustive
/// layer refuse a class, and it must: an emission boundary's cleanup is its
/// plan record's, the decoded value and its input with it.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn an_emission_class_merged_with_a_decode_boundary_is_rejected() {
    const PLANTED: &str = "planted";
    let merged = Classes::<Typed<u64>> {
        decode: |position| match position {
            TypedPosition::Parse(parse) if !parse.allocated => Some(PLANTED.to_owned()),
            other => classes::typed::<u64>(other),
        },
        emit: |_| Some(PLANTED.to_owned()),
        ..classes::reduced::<u64>()
    };
    matrix(
        "an emission under a planted class",
        Rigor::Exhaustive,
        Expected::Complete,
        |schedule| encode::<u64>(&[0x19, 0x01, 0x00], schedule, &merged),
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

/// `["q\u{301}", "b"]`: two text elements, the first normalizing.
const TWO_TEXTS: [u8; 7] = [0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'];

#[test]
fn vector_children_survive_every_admission_physical_failure_and_stop() {
    // Crosses parsing, normalization, the document's transfer, vector child
    // construction and pre-publication cleanup, its stops classed by the
    // sequence's declared reduction over its texts' complete class.
    pipeline::<Vec<String>>(
        "vector",
        &TWO_TEXTS,
        Expected::Complete,
        classes::reduced::<Vec<String>>(),
    );
}

/// The claims the sequences' stop classes rest on, each checked on every
/// state its construction reaches, from nothing built to complete, each
/// cancelled there and cleaned up: every complete scalar, text and tagged
/// text is of its declared complete class, and each sequence's declared
/// reduction, over those elements, is a simulation of its cleanup, for a
/// vector and an array, of scalars and of texts.
#[test]
fn sequences_and_their_elements_declare_sound_reductions() {
    dcbor_test_support::uniform::<u64>("an integer", &[0x19, 0x01, 0x00]);
    dcbor_test_support::uniform::<String>("a text", &[0x63, b'q', 0xcc, 0x81]);
    dcbor_test_support::uniform::<String>("an empty text", &[0x60]);
    dcbor_test_support::certified::<Vec<String>>("a vector of texts", &TWO_TEXTS);
    dcbor_test_support::certified::<Vec<u64>>("a vector of integers", &[0x83, 0x01, 0x02, 0x03]);
    dcbor_test_support::certified::<Vec<u64>>("an empty vector", &[0x80]);
    dcbor_test_support::certified::<[u64; 2]>("an array of integers", &[0x82, 0x01, 0x18, 0x18]);
}

/// The complete-class check's planted control: a text declared complete
/// without its payload's permit, which every complete text holds, is
/// refused.
#[test]
#[should_panic(expected = "is not of its declared complete class")]
fn a_planted_complete_class_is_rejected() {
    use dcbor::bounded::decode::construction::Reduction;
    use dcbor::bounded::decode::construction::in_place::BufferClass;
    dcbor_test_support::complete_class::<String, _>(
        "a text under a planted complete class",
        &[0x63, b'q', 0xcc, 0x81],
        |observation| {
            <<String as dcbor::bounded::decode::construction::Reclaim<Limits>>::State as Reduction>::class(observation)
        },
        BufferClass::Written { payload: false },
    );
}

/// The sequence reduction's planted control: a class that drops the
/// committed count merges a vector holding one complete text with one
/// holding two, whose cleanups differ by a text's, and the simulation check
/// refuses it.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn a_sequence_class_dropping_its_committed_count_is_rejected() {
    use dcbor::bounded::decode::construction::Reduction;
    use dcbor::bounded::decode::construction::in_place::SequenceClass;
    type State = <Vec<String> as dcbor::bounded::decode::construction::Reclaim<Limits>>::State;
    dcbor_test_support::simulation::<Vec<String>, _>(
        "a vector under a planted class",
        &TWO_TEXTS,
        |observation| match <State as Reduction>::class(observation) {
            SequenceClass::Written {
                payload, newest, ..
            } => SequenceClass::Written {
                payload,
                committed: 0,
                newest,
            },
            SequenceClass::Reclaim {
                payload, newest, ..
            } => SequenceClass::Reclaim {
                payload,
                committed: 0,
                newest,
            },
            other => other,
        },
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
