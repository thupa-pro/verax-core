#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = axiom_core::AxiomPayload::decode(data);
    let _ = axiom_core::is_strictly_deterministic(data);
});
