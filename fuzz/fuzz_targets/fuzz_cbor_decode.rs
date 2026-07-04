#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // All CBOR decode entry points must never panic.
    // catch_unwind ensures a panic is caught (the fuzzer can report it).
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::VeraxPayload::decode(data);
    }));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::is_strictly_deterministic(data);
    }));
});
