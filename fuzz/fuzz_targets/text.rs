#![no_main]
use libfuzzer_sys::fuzz_target;
use unicode_normalization::UnicodeNormalization;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let normal: String = text.nfc().collect();
    let expected = dcbor::CBOR::from(normal.as_str()).to_cbor_data();
    dcbor_fuzz::exercise(text, &expected, None);
});
