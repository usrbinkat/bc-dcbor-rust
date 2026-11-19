#![no_main]
use dcbor::{BigInt, BigUint, CBOR, CBOREncodable, Sign, bounded::Tagged};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(256)];
    let schedule = data.first().map(|n| usize::from(*n));
    let map: BTreeMap<_, _> = data
        .chunks(2)
        .map(|pair| (pair[0], pair.last().copied().unwrap()))
        .collect();
    // The keys are `u8`, whose canonical encoding is injective in its value:
    // distinct tree keys never reduce to one, so the encoding cannot refuse.
    let symbolic = map
        .encode_cbor()
        .expect("u8 keys encode injectively into canonical CBOR");
    let expected = symbolic.to_cbor_data();
    dcbor_fuzz::exercise(&map, &expected, schedule);
    dcbor_fuzz::exercise(&symbolic, &expected, schedule);
    let unsigned = BigUint::from_bytes_be(data);
    dcbor_fuzz::exercise(&unsigned, &CBOR::from(&unsigned).to_cbor_data(), schedule);
    let negative = BigInt::from_biguint(Sign::Minus, unsigned);
    dcbor_fuzz::exercise(&negative, &CBOR::from(&negative).to_cbor_data(), schedule);
    let tag = Tagged {
        tag: 1000,
        value: Some(map),
    };
    let expected = CBOR::to_tagged_value(1000, symbolic).to_cbor_data();
    dcbor_fuzz::exercise(&tag, &expected, schedule);
});
