//! Stabilized text (UAX #15, section 12) above dCBOR conformance: what dCBOR
//! accepts as text (NFC), less any code point the pinned Unicode version
//! leaves unassigned. Vectors from `data/unicode/17.0.0/DerivedAge.txt`:
//! U+1FA8A TROMBONE is assigned in 17.0 (line 2106, `1FA8A ; 17.0`);
//! U+0378 is unassigned, no line listing it (the nearest lines are 895,
//! `0376..0377 ; 5.1`, and 71, `037A ; 1.1`).

use dcbor::bounded::{Limits, encode};
use dcbor::prelude::*;
use dcbor::{Error, StabilizedText, is_assigned};

/// U+1FA8A TROMBONE, assigned in Unicode 17.0.
const ASSIGNED: &str = "\u{1FA8A}";

/// U+0378, unassigned in Unicode 17.0.
const UNASSIGNED: &str = "\u{378}";

/// `text`'s dCBOR text encoding, its head and its UTF-8 bytes.
fn wire(text: &str) -> Vec<u8> {
    let mut bytes = vec![0x60 | text.len() as u8];
    bytes.extend(text.as_bytes());
    bytes
}

/// An assigned code point is accepted by construction, by symbolic
/// decoding and by bounded encoding, which writes the plain text bytes.
#[test]
fn an_assigned_code_point_is_stabilized() {
    assert!(is_assigned('\u{1FA8A}'));
    let text = StabilizedText::new(ASSIGNED).expect("assigned in 17.0");
    assert_eq!(text.as_str(), ASSIGNED);
    let decoded = CBOR::try_from_data(wire(ASSIGNED)).expect("dCBOR text");
    assert_eq!(StabilizedText::try_from(decoded).unwrap(), text);
    let symbolic = CBOR::from(text.clone()).to_cbor_data();
    assert_eq!(symbolic, wire(ASSIGNED));
    let mut limits = Limits::unlimited();
    let bounded = encode(&text, &mut limits).expect("an unlimited encoding");
    assert_eq!(bounded.as_ref(), symbolic);
}

/// An unassigned code point is dCBOR text, accepted by plain `String`
/// decoding, and refused as stabilized text, naming the code point, by
/// construction and by symbolic decoding.
#[test]
fn an_unassigned_code_point_is_dcbor_text_but_not_stabilized() {
    assert!(!is_assigned('\u{378}'));
    let decoded = CBOR::try_from_data(wire(UNASSIGNED)).expect("dCBOR accepts it");
    assert_eq!(String::try_from(decoded.clone()).unwrap(), UNASSIGNED);
    assert!(matches!(
        StabilizedText::try_from(decoded),
        Err(Error::UnassignedCodePoint(0x378))
    ));
    assert!(matches!(
        StabilizedText::new(UNASSIGNED),
        Err(Error::UnassignedCodePoint(0x378))
    ));
    // Behind an assigned one, the first unassigned code point is named.
    assert!(matches!(
        StabilizedText::new(format!("{ASSIGNED}a{UNASSIGNED}")),
        Err(Error::UnassignedCodePoint(0x378))
    ));
}

/// Text not in NFC is refused by both: dCBOR's decoder, and stabilized
/// text's construction, before any code point is looked up.
#[test]
fn non_nfc_text_is_refused_by_both() {
    let decomposed = "e\u{301}";
    assert!(matches!(
        CBOR::try_from_data(wire(decomposed)),
        Err(Error::NonCanonicalString)
    ));
    assert!(matches!(
        StabilizedText::new(decomposed),
        Err(Error::NonCanonicalString)
    ));
}

/// A value that is not text is the wrong type.
#[test]
fn a_value_that_is_not_text_is_the_wrong_type() {
    assert!(matches!(
        StabilizedText::try_from(CBOR::from(1u64)),
        Err(Error::WrongType)
    ));
}
