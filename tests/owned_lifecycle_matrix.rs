//! The owned typed decode of a custom input installed through the public
//! resource-binding interface: every admission refused once and resumed
//! without replay, every physical request failed, and at the boundaries the
//! layer selects ([`dcbor_test_support::rigor`]) the consumer retires,
//! unwinds or cancels; the input is released exactly once, by the drain.
use dcbor_test_support::classes;
use dcbor_test_support::pipeline::{Expected, Schedule, decode, matrix};
use dcbor_test_support::rigor::rigor;

#[test]
fn every_admission_physical_failure_and_stop_of_an_owned_text_decode() {
    let texts = [
        String::new(),
        "hello".to_owned(),
        "\u{301}".to_owned(),
        "a\u{315}\u{300}".to_owned(),
        "\u{301}".repeat(32),
    ];
    for text in texts {
        let wire = dcbor::CBOR::from(text.as_str()).to_cbor_data();
        // The symbolic decoder is the independent oracle of the value.
        let expected = String::try_from(dcbor::CBOR::try_from_data(&wire).unwrap()).unwrap();
        matrix(
            &format!("owned decode of {text:?}"),
            rigor(),
            Expected::Complete,
            |schedule| {
                decode::<String>(
                    &wire,
                    schedule,
                    &classes::reduced::<dcbor_test_support::Instrumented, String>(),
                    |value| assert_eq!(value, &expected),
                )
            },
        );
    }
}

#[test]
fn malformed_inputs_keep_cleanup_custody_under_every_fault() {
    for wire in [
        &[0x62, b'a'][..],
        &[0x61, 0xff],
        &[0x18, 0x01],
        &[0x60, 0x00],
    ] {
        matrix(
            &format!("owned decode of malformed {wire:02x?}"),
            rigor(),
            Expected::Invalid,
            |schedule| {
                decode::<String>(
                    wire,
                    schedule,
                    &classes::reduced::<dcbor_test_support::Instrumented, String>(),
                    |value| panic!("malformed input published {value:?}"),
                )
            },
        );
    }
}

/// A type that accepts no text declares the quick-only text policy
/// (`InPlace::WIRE`), so its owned decode refuses a text the quick check
/// cannot prove normal, canonical though it is, inside the parse, before
/// construction begins: it ends at fewer boundaries than the same type's
/// decode of a quick-proven text, which the parse accepts and construction
/// refuses as the wrong type. Under strict validation both would pass the
/// parse and end alike in construction. A text type accepts the unproven
/// text (`every_admission_physical_failure_and_stop_of_an_owned_text_decode`).
#[test]
fn a_type_without_text_refuses_unproven_text_in_the_parse() {
    let run = |text: &str| {
        let wire = dcbor::CBOR::from(vec![dcbor::CBOR::from(text)]).to_cbor_data();
        decode::<Vec<u64>>(
            &wire,
            &Schedule::BASELINE,
            &classes::reduced::<dcbor_test_support::Instrumented, Vec<u64>>(),
            |value| panic!("a text published as {value:?}"),
        )
    };
    let unproven = run("\u{301}");
    let proven = run("x");
    for (name, report) in [("unproven", &unproven), ("proven", &proven)] {
        assert!(
            report.invalid && !report.complete && !report.failed,
            "{name}: refused as invalid"
        );
    }
    assert!(
        unproven.boundaries.len() < proven.boundaries.len(),
        "the unproven text reached construction: {} boundaries, the proven text's {}",
        unproven.boundaries.len(),
        proven.boundaries.len()
    );
}
