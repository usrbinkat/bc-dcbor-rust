#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dcbor_fuzz::exercise_decode_schedule(data);
});
