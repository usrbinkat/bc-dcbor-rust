#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(header) = data.get(..2) else {
        return;
    };
    let refusal = usize::from(u16::from_le_bytes(header.try_into().unwrap()));
    let texts: Vec<String> = data[2..]
        .iter()
        .take(64)
        .map(|&byte| {
            let mut text = String::from("a");
            for _ in 0..usize::from(byte % 8) {
                text.push_str("\u{301}\u{316}");
            }
            text
        })
        .collect();
    let expected = dcbor::CBOR::from(texts.clone()).to_cbor_data();
    dcbor_fuzz::exercise(&texts, &expected, Some(refusal));
});
