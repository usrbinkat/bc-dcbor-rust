//! Unicode NFC conformance for the bounded and symbolic paths, independent
//! of their algorithms: the conformance file is the oracle.
#[path = "data/normalization_tests.rs"]
mod data;

use dcbor::{CBOR, bounded::*};

/// Every row's five forms normalize to the row's NFC (or NFKC) form on the
/// bounded path, the symbolic path encodes the same bytes, and those bytes
/// decode back to the form. A row's NFD form, where it differs from its NFC,
/// is rejected by the decoder as not normalized.
#[test]
fn unicode_nfc_conformance() {
    assert_eq!(data::NORMALIZATION_TESTS.len(), 20_034);
    let mut rejected = 0;
    for (index, row) in data::NORMALIZATION_TESTS.iter().enumerate() {
        for (input, expected) in [
            (row.source, row.nfc),
            (row.nfc, row.nfc),
            (row.nfd, row.nfc),
            (row.nfkc, row.nfkc),
            (row.nfkd, row.nfkc),
        ] {
            let actual = normalized(input);
            assert_eq!(
                actual, expected,
                "normalization row {index}, input {input:?}"
            );
        }
        if row.nfd != row.nfc {
            let result = CBOR::try_from_data(text_wire(row.nfd));
            assert!(
                matches!(result, Err(dcbor::Error::NonCanonicalString)),
                "normalization row {index}: NFD {:?} decoded as {result:?}",
                row.nfd
            );
            rejected += 1;
        }
    }
    assert!(rejected > 0, "no row has an NFD form distinct from its NFC");
}

/// `input` normalized and encoded on the bounded path, the symbolic path
/// required to encode the same bytes, decoded back to text.
fn normalized(input: &str) -> String {
    let prepared = prepare(input, &mut Limits::unlimited()).unwrap();
    let mut bytes = vec![0; prepared.len()];
    prepared
        .encode_into(&mut bytes, &mut Limits::unlimited())
        .unwrap();
    assert_eq!(
        CBOR::from(input).to_cbor_data(),
        bytes,
        "symbolic and bounded normalization of {input:?} differ"
    );
    CBOR::try_from_data(bytes).unwrap().try_into().unwrap()
}

/// `text`'s bytes as a CBOR text string, unnormalized: the shortest head of
/// its length, then its bytes.
fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut wire = match n {
        0..24 => vec![0x60 | n as u8],
        24..256 => vec![0x78, n as u8],
        256..65536 => vec![0x79, (n >> 8) as u8, n as u8],
        _ => {
            let mut head = vec![0x7a];
            head.extend(
                u32::try_from(n)
                    .expect("a conformance row fits in u32")
                    .to_be_bytes(),
            );
            head
        }
    };
    wire.extend_from_slice(text.as_bytes());
    wire
}

#[test]
fn long_runs_preserve_order_and_do_not_insert_characters() {
    // q has no composition with these marks. Classes are 1, 220 and 230.
    let low = "\u{334}".repeat(256);
    let middle = "\u{316}".repeat(256);
    let high = "\u{301}".repeat(256);
    let ordered = format!("q{low}{middle}{high}");
    assert_eq!(normalized(&ordered), ordered);
    assert_eq!(normalized(&format!("q{high}{middle}{low}")), ordered);
    let equal = format!("q{}", "\u{301}\u{302}".repeat(256));
    assert_eq!(normalized(&equal), equal);
    assert_eq!(
        normalized(&format!("{high}{middle}{low}")),
        format!("{low}{middle}{high}")
    );
    assert_eq!(normalized("\u{344}"), "\u{308}\u{301}");
    assert_eq!(normalized("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}");
}

#[test]
fn reversed_combining_runs_have_linear_reported_work() {
    fn measured(n: usize) -> WriteWork {
        let input = format!(
            "q{}{}{}",
            "\u{301}".repeat(n),
            "\u{316}".repeat(n),
            "\u{334}".repeat(n)
        );
        let mut limits = Limits::new(10_000_000, 100_000_000, 10_000_000);
        let before = limits.remaining();
        let result = encode(&input, &mut limits).unwrap();
        let after = limits.remaining();
        drop(result);
        assert_eq!(limits.live_bytes(), 0);
        WriteWork::new(before.values - after.values, before.bytes - after.bytes)
    }
    let small = measured(512);
    let large = measured(4096);
    assert!(large.values <= small.values * 9);
    assert!(large.bytes <= small.bytes * 9);
}
