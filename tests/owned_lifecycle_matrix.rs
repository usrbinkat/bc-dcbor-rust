//! The owned typed decode of a custom input installed through the public
//! resource-binding interface: every admission refused once and resumed
//! without replay, every physical request failed, and at the boundaries the
//! layer selects ([`dcbor_test_support::rigor`]) the consumer retires,
//! unwinds or cancels; the input is released exactly once, by the drain.
use dcbor::bounded::decode::Options;
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
                    Options::normalizing(8),
                    schedule,
                    &classes::reduced::<String>(),
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
                    Options::normalizing(8),
                    schedule,
                    &classes::reduced::<String>(),
                    |value| panic!("malformed input published {value:?}"),
                )
            },
        );
    }
}

#[test]
fn quick_only_refuses_text_it_cannot_prove_normal() {
    let wire = dcbor::CBOR::from("\u{301}").to_cbor_data();
    let report = decode::<String>(
        &wire,
        Options::quick_only(8),
        &Schedule::BASELINE,
        &classes::reduced::<String>(),
        |value| panic!("unproven text published {value:?}"),
    );
    assert!(report.invalid && !report.complete && !report.failed);
}
