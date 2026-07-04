#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = verax_core::VeraxPayload::decode(data);
    let _ = verax_core::is_strictly_deterministic(data);
});
