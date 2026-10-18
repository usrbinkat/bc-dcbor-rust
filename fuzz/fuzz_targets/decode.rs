#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(4096)];
    dcbor_fuzz::exercise_decode(data, None);
    if let Some((&schedule, payload)) = data.split_first() {
        dcbor_fuzz::exercise_decode(payload, Some(usize::from(schedule)));
    }
});
