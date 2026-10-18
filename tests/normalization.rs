//! Unicode NFC conformance for the bounded path, independent of its algorithm.
#[path = "data/normalization_tests.rs"]
mod data;

use dcbor::{CBOR, bounded::*};

struct Admit;
impl Budget for Admit {
    type Refusal = ();
    fn traverse(&mut self, _: u64, _: u64) -> Result<(), ()> {
        Ok(())
    }
}
impl Allocator for Admit {
    type Permit = ();
    fn allocate(&mut self, _: u64) -> Result<(), ()> {
        Ok(())
    }
}

#[test]
fn unicode_nfc_conformance() {
    assert_eq!(data::NORMALIZATION_TESTS.len(), 20_034);
    for (index, row) in data::NORMALIZATION_TESTS.iter().enumerate() {
        for (input, expected) in [
            (row.source, row.nfc),
            (row.nfc, row.nfc),
            (row.nfd, row.nfc),
            (row.nfkc, row.nfkc),
            (row.nfkd, row.nfkc),
        ] {
            let prepared = prepare(input, &mut Admit).unwrap();
            let mut bytes = vec![0; usize::try_from(prepared.len()).unwrap()];
            prepared.encode_into(&mut bytes, &mut Admit).unwrap();
            let actual: String = CBOR::try_from_data(bytes).unwrap().try_into().unwrap();
            assert_eq!(
                actual, expected,
                "normalization row {index}, input {input:?}"
            );
        }
    }
}

fn normalized(input: &str) -> String {
    let prepared = prepare(input, &mut Admit).unwrap();
    let mut bytes = vec![0; usize::try_from(prepared.len()).unwrap()];
    prepared.encode_into(&mut bytes, &mut Admit).unwrap();
    CBOR::try_from_data(bytes).unwrap().try_into().unwrap()
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
