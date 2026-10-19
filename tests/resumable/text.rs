use super::support::*;
use dcbor::bounded::resumable::{Fault, QuickCheck, Value};
use unicode_normalization::{is_nfc_quick, IsNormalized};

#[test]
fn quick_check_matches_upstream_at_every_scalar_and_chunk_boundary() {
    for scalar in 0..=0x10ffff {
        let Some(ch) = char::from_u32(scalar) else {
            continue;
        };
        let text = ch.to_string();
        let mut check = QuickCheck::new(text.clone().into_boxed_str());
        assert_eq!(check.finish_with_quantum(1), is_nfc_quick(text.chars()));
    }
    for text in [
        "",
        "q\u{301}a",
        "a\u{301}",
        "q\u{301}\u{316}",
        "\u{301}a",
        "\u{1100}\u{1161}\u{11a8}",
        "é😀q\u{301}",
    ] {
        for quantum in [1, 2, 3, 4, 64] {
            let mut check = QuickCheck::new(text.into());
            assert_eq!(
                check.finish_with_quantum(quantum),
                is_nfc_quick(text.chars())
            );
        }
    }
    assert_eq!(is_nfc_quick("q\u{301}a".chars()), IsNormalized::Maybe);
}

#[test]
fn canonical_text_fixtures_are_independent_of_round_trip() {
    for text in [
        "",
        "abc",
        "é",
        "\u{301}a",
        "\u{1e0d}\u{307}",
        "\u{ac1c}",
        "😀",
    ] {
        let wire = text_wire(text);
        let mut decode = decoder(&wire, &pool());
        assert_eq!(finish(&mut decode), Value::Text(text.into()));
        refuse_each(&wire, Fault::Work);
    }
    for text in ["e\u{301}", "\u{2126}", "\u{1e0b}\u{323}", "q\u{301}\u{316}"] {
        assert_invalid(&text_wire(text));
    }
}

#[test]
fn long_maybe_sequence_has_bounded_progress_and_late_disorder_is_rejected() {
    let valid = format!("q{}", "\u{301}".repeat(100_000));
    let mut decode = decoder(&text_wire(&valid), &pool());
    assert_eq!(finish(&mut decode), Value::Text(valid.clone()));
    assert_no_replay(decode.events());
    assert_invalid(&text_wire(&(valid + "\u{316}")));
}
