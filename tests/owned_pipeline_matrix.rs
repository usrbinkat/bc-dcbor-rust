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
use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::TypedPosition;
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::encoding::TransferableSchema;
use dcbor_test_support::classes::{self, Pipeline};
use dcbor_test_support::heap;
use dcbor_test_support::pipeline::{Expected, encode, matrix};
use dcbor_test_support::rigor::{Rigor, rigor};

/// The fault matrix of `T` decoded from `wire` and encoded back to it, its
/// stops classed by `classes`.
fn pipeline<T: Transferable<Limits> + TransferableSchema + 'static>(
    name: &str,
    wire: &[u8],
    expected: Expected,
    classes: Pipeline<ByteString, T>,
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
        classes::reduced::<ByteString, u64>(),
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
    const PLANTED: classes::Class = classes::Class::Planted("planted");
    let merged = Pipeline::<ByteString, u64> {
        decode: |position| match position {
            TypedPosition::Parse(parse) if !parse.allocated => Some(PLANTED),
            other => classes::typed::<ByteString, u64>(other),
        },
        emit: |_| Some(PLANTED),
        ..classes::reduced::<ByteString, u64>()
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
        classes::reduced::<ByteString, String>(),
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
        classes::reduced::<ByteString, Vec<String>>(),
    );
}

/// The empty vector through the whole pipeline (parse, transfer,
/// construction, cleanup), across every admission, physical failure and
/// stop: a sequence with no child to construct.
#[test]
fn an_empty_vector_survives_every_admission_physical_failure_and_stop() {
    pipeline::<Vec<String>>(
        "empty vector",
        &[0x80],
        Expected::Complete,
        classes::reduced::<ByteString, Vec<String>>(),
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
    use dcbor::bounded::decode::construction::in_place::{BufferClass, Session, StageClass};
    type Root = Session<<String as dcbor::bounded::decode::construction::Reclaim<Limits>>::State>;
    dcbor_test_support::complete_class::<String, _>(
        "a text under a planted complete class",
        &[0x63, b'q', 0xcc, 0x81],
        <Root as Reduction>::class,
        (StageClass::Bound, BufferClass::Written { payload: false }),
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
    use dcbor::bounded::decode::construction::in_place::{SequenceClass, stage_class};
    type State = <Vec<String> as dcbor::bounded::decode::construction::Reclaim<Limits>>::State;
    // The root session's class kept; the sequence's planted.
    dcbor_test_support::simulation::<Vec<String>, _>(
        "a vector under a planted class",
        &TWO_TEXTS,
        |observation| {
            let sequence = match <State as Reduction>::class(&observation.inner) {
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
            };
            (stage_class(observation.stage), sequence)
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
    map.insert("z", "short").unwrap();
    map.insert("aa", "q\u{301}").unwrap();
    pipeline::<BTreeMap<String, String>>(
        "reordered tree",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<String, String>>(),
    );
    pipeline::<BTreeMap<String, String>>(
        "empty tree",
        &[0xa0],
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<String, String>>(),
    );
    let mut internal = dcbor::Map::new();
    for n in 0..12u64 {
        internal.insert(n, n).unwrap();
    }
    pipeline::<BTreeMap<u64, u64>>(
        "internal node",
        &dcbor::CBOR::from(internal).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<u64, u64>>(),
    );
    // Both remaining scalar key bindings use the same numeric view but
    // distinct source-kind/range validation.
    pipeline::<BTreeMap<bool, bool>>(
        "boolean keys",
        &[0xa2, 0xf4, 0xf5, 0xf5, 0xf4],
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<bool, bool>>(),
    );
    pipeline::<BTreeMap<usize, bool>>(
        "usize keys",
        &[0xa2, 0x00, 0xf4, 0x18, 0x18, 0xf5],
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<usize, bool>>(),
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
    map.insert(prefix.clone(), 0u64).unwrap();
    map.insert(format!("{prefix}z"), 1u64).unwrap();
    map.insert(format!("{prefix}aa"), 2u64).unwrap();
    pipeline::<BTreeMap<String, u64>>(
        "long shared prefixes",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<String, u64>>(),
    );
}

#[cfg(feature = "custom-std-collections")]
#[test]
fn nested_tree_values_retain_custody_at_every_pipeline_boundary() {
    use std::collections::BTreeMap;
    let mut child = dcbor::Map::new();
    child.insert("z", "last").unwrap();
    child.insert("aa", "first").unwrap();
    let mut map = dcbor::Map::new();
    map.insert(0u64, child).unwrap();
    map.insert(1u64, dcbor::Map::new()).unwrap();
    pipeline::<BTreeMap<u64, BTreeMap<String, String>>>(
        "nested trees",
        &dcbor::CBOR::from(map).to_cbor_data(),
        Expected::Complete,
        classes::parsed::<ByteString, BTreeMap<u64, BTreeMap<String, String>>>(),
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
        classes::parsed::<ByteString, BTreeMap<String, String>>(),
    );
}

#[test]
fn stable_optional_acquisitions_survive_every_admission_physical_failure_and_stop() {
    pipeline::<StableOption<String, Limits>>(
        "present stable option",
        &[0x63, b'q', 0xcc, 0x81],
        Expected::Complete,
        classes::reduced::<ByteString, StableOption<String, Limits>>(),
    );
    pipeline::<StableOption<String, Limits>>(
        "null stable option",
        &[0xf6],
        Expected::Complete,
        classes::reduced::<ByteString, StableOption<String, Limits>>(),
    );
}

/// A stabilized text through the whole pipeline, its stops classed by its
/// declared reduction (its text's): U+1FA8A TROMBONE, assigned in the
/// pinned version, decodes and encodes back; U+0378, which dCBOR accepts as
/// text, is refused as invalid by the stabilized text's check and its
/// decode cleaned up; a decomposed text is refused by dCBOR's own NFC check
/// before the binding sees it. The reduction's claims are certified on the
/// same inputs.
#[test]
fn a_stabilized_text_survives_every_boundary_and_refuses_what_it_does_not_assign() {
    use dcbor::StabilizedText;
    let assigned = dcbor::CBOR::from("\u{1fa8a}").to_cbor_data();
    let unassigned = dcbor::CBOR::from("\u{378}").to_cbor_data();
    let decomposed = [0x63, b'e', 0xcc, 0x81];
    dcbor_test_support::uniform::<StabilizedText>(
        "an assigned code point-construction-certification",
        &assigned,
    );
    dcbor_test_support::certified::<StabilizedText>(
        "an unassigned code point-construction-certification",
        &unassigned,
    );
    for (name, wire, expected) in [
        (
            "an assigned code point",
            assigned.as_slice(),
            Expected::Complete,
        ),
        (
            "an unassigned code point",
            unassigned.as_slice(),
            Expected::Invalid,
        ),
        (
            "a decomposed text",
            decomposed.as_slice(),
            Expected::Invalid,
        ),
    ] {
        pipeline::<StabilizedText>(
            name,
            wire,
            expected,
            classes::reduced::<ByteString, StabilizedText>(),
        );
    }
}

/// An ASCII text through the whole pipeline, its stops classed by its
/// declared reduction (its text's): a text of both ASCII edges decodes and
/// encodes back; U+00E9, which dCBOR accepts as text and the quick check
/// proves, is refused as invalid by the ASCII rule and its decode cleaned
/// up; a text the quick check leaves unproven (`q` U+0301) is refused by the
/// parse under the type's quick-only profile, before the binding sees it.
/// The reduction's claims are certified on the same inputs.
#[test]
fn an_ascii_text_survives_every_boundary_and_refuses_what_is_not_ascii() {
    use dcbor::AsciiText;
    let ascii = dcbor::CBOR::from("\u{0}id\u{7f}").to_cbor_data();
    let accented = dcbor::CBOR::from("\u{e9}").to_cbor_data();
    let unproven = dcbor::CBOR::from("q\u{301}").to_cbor_data();
    dcbor_test_support::uniform::<AsciiText>("an ASCII text-construction-certification", &ascii);
    dcbor_test_support::certified::<AsciiText>(
        "a non-ASCII text-construction-certification",
        &accented,
    );
    for (name, wire, expected) in [
        ("an ASCII text", ascii.as_slice(), Expected::Complete),
        ("a non-ASCII text", accented.as_slice(), Expected::Invalid),
    ] {
        pipeline::<AsciiText>(
            name,
            wire,
            expected,
            classes::reduced::<ByteString, AsciiText>(),
        );
    }
    let mut limits = dcbor::bounded::Limits::unlimited();
    let refused = dcbor::bounded::decode::decode_typed::<AsciiText, _>(&unproven, &mut limits);
    assert!(
        matches!(
            refused,
            Err(dcbor::bounded::decode::DecodeError::UnprovenText)
        ),
        "an unproven text reached the ASCII binding"
    );
    assert_eq!(limits.live_bytes(), 0);
}

/// A minimal big integer through the whole pipeline, its stops classed by
/// its declared reduction (its magnitude's): 2^64, a bignum, and 1, a plain
/// integer, decode and encode back; `c2 41 01`, which dCBOR accepts as a
/// tagged byte string, is refused as invalid and its decode cleaned up. The
/// reduction's claims are certified on the same inputs.
#[test]
fn a_minimal_big_integer_survives_every_boundary_and_refuses_a_non_minimal_encoding() {
    use dcbor::MinimalBigInt;
    let big = [0xc2, 0x49, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    let plain = [0x01];
    let tagged = [0xc2, 0x41, 0x01];
    dcbor_test_support::uniform::<MinimalBigInt>("2^64-construction-certification", &big);
    dcbor_test_support::uniform::<MinimalBigInt>("one-construction-certification", &plain);
    dcbor_test_support::certified::<MinimalBigInt>(
        "one as a bignum-construction-certification",
        &tagged,
    );
    for (name, wire, expected) in [
        ("2^64", big.as_slice(), Expected::Complete),
        ("one", plain.as_slice(), Expected::Complete),
        ("one as a bignum", tagged.as_slice(), Expected::Invalid),
    ] {
        pipeline::<MinimalBigInt>(
            name,
            wire,
            expected,
            classes::reduced::<ByteString, MinimalBigInt>(),
        );
    }
}

#[test]
fn rejected_inputs_clean_up_their_decode_and_never_reach_preparation() {
    // Not NFC: the combining mark follows a composable base.
    pipeline::<String>(
        "decomposed text",
        &[0x63, b'e', 0xcc, 0x81],
        Expected::Invalid,
        classes::reduced::<ByteString, String>(),
    );
    // A byte string is not text.
    pipeline::<String>(
        "byte string as text",
        &[0x41, 0x00],
        Expected::Invalid,
        classes::reduced::<ByteString, String>(),
    );
}
