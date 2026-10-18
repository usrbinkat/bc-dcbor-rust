#![no_main]
use dcbor::CBOR;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(bytes) = data.get(..8) else {
        return;
    };
    let bits = u64::from_le_bytes(bytes.try_into().unwrap());
    let value = f64::from_bits(bits);
    let expected = CBOR::from(value).to_cbor_data();
    let decoded = f64::try_from(CBOR::try_from_data(&expected).unwrap()).unwrap();
    assert!(decoded == value || (decoded.is_nan() && value.is_nan()));
    dcbor_fuzz::exercise(&value, &expected, None);
    let single = f32::from_bits(bits as u32);
    let expected = CBOR::from(single).to_cbor_data();
    assert_eq!(expected, CBOR::from(f64::from(single)).to_cbor_data());
    let decoded = f64::try_from(CBOR::try_from_data(&expected).unwrap()).unwrap();
    assert!(decoded == f64::from(single) || (decoded.is_nan() && single.is_nan()));
    dcbor_fuzz::exercise(&single, &expected, None);
    let half = half::f16::from_bits(bits as u16);
    let expected = CBOR::from(half).to_cbor_data();
    assert_eq!(expected, CBOR::from(half.to_f64()).to_cbor_data());
    let decoded = f64::try_from(CBOR::try_from_data(&expected).unwrap()).unwrap();
    assert!(decoded == half.to_f64() || (decoded.is_nan() && half.is_nan()));
    dcbor_fuzz::exercise(&half, &expected, None);
});
