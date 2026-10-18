#![no_main]
use dcbor::{CBORBoundedEncodable, CBOREncodable, CBOR};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, CBOREncodable, CBORBoundedEncodable)]
struct Record {
    #[cbor(n = 24)]
    text: Option<String>,
    #[cbor(n = 0)]
    number: f64,
    #[cbor(n = 1)]
    flags: [bool; 2],
}

fuzz_target!(|data: &[u8]| {
    // Fixed maximum nesting depth and at most 32 records.
    let records: Vec<Vec<Record>> = data
        .iter()
        .take(32)
        .map(|&byte| {
            vec![Record {
                text: (byte & 1 != 0).then(|| {
                    ["ascii", "e\u{301}", "\u{1100}\u{1161}", "\u{301}\u{316}"]
                        [(byte >> 1) as usize % 4]
                        .to_string()
                }),
                number: f64::from_bits(u64::from(byte) << 56),
                flags: [byte & 2 != 0, byte & 4 != 0],
            }]
        })
        .collect();
    let expected = CBOR::from(records.clone()).to_cbor_data();
    dcbor_fuzz::exercise(&records, &expected, None);
});
