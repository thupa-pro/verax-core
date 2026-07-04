# Security Audit: verax Protocol v3.0

## Constant-Time Verification Analysis

### Signature Verification

| Component | Library | Constant-Time? | Notes |
|-----------|---------|----------------|-------|
| Ed25519 | `ed25519-dalek` v2 (default features) | ✅ Yes | Uses `verify_strict()` by default. The `ed25519-dalek` crate applies batchable double-scalar multiplication with no variable-time branches. |
| ML-DSA-65 | `ml-dsa` v0.1 (FIPS 204) | ✅ Yes | ML-DSA (FIPS 204) is designed to be side-channel resistant. The `ml-dsa` crate uses `std::simd` for constant-time operations on all supported platforms. |
| Composite | verax wrapper over both | ✅ Yes | Each component (Ed25519 + ML-DSA-65) is independently constant-time. No early-exit on first signature failure. |

**Finding:** No variable-time signature verification paths identified.

### CBOR Parsing

| Operation | Variable-Time? | Risk | Mitigation |
|-----------|---------------|------|------------|
| Uint decoding (check_shortest_encoding) | ⚠️ Branch on value range | Low | Value-dependent branching reveals the magnitude of integers, but these are public payload fields, not secrets. |
| Map key comparison | ⚠️ Short-circuit `==` | Low | Keys are public map indices. No secret-dependent branching. |
| Byte string length checks | ⚠️ Length comparison | Low | Lengths are public metadata. |
| BLAKE3 hashing | ✅ Yes | — | BLAKE3 is constant-time in the `blake3` crate. |

**Finding:** CBOR parsing has data-dependent branches on public fields only (map key values, string lengths). These are metadata that an attacker already knows from the encoded bytes. No secret material (private keys, nonces, signatures) is processed during payload parsing.

### Key Compromise Risks

| Threat | Mitigation | Status |
|--------|------------|--------|
| Ed25519 key leak | Key rotation via SUPERSEDES chain | ✅ Implemented in `resolve_rotated_key_default` |
| ML-DSA-65 key leak | Composite mode (Hybrid) requires both keys | ✅ `VerificationMode::Hybrid` |
| Quantum threat | ML-DSA-65 provides PQ security | ✅ PQ-only mode available via `parse_and_verify_mldsa65_only` |
| Side-channel on key rotation chain | Rotation statements are public on the DAG | ✅ Chain traversal is data-independent |

### Dependency Audit

| Dependency | Version | Memory Safety | Notes |
|------------|---------|---------------|-------|
| `ed25519-dalek` | 2.x | ✅ Safe Rust | `#![forbid(unsafe_code)]` |
| `ml-dsa` | 0.1 | ✅ Safe Rust | FIPS 204 implementation |
| `blake3` | 1.x | ✅ Safe Rust | `#![deny(unsafe_code)]` |
| `chacha20poly1305` | 0.10 | ✅ Safe Rust | AEAD with `#![forbid(unsafe_code)]` |
| `hpke` | 0.11 | ✅ Safe Rust | RFC 9180 |
| `zeroize` | 1.x | ✅ | `Zeroize` on `ShreddingKey` |

### Overall Assessment

The verax Protocol core library has:
- **No `unsafe` code** (`#![deny(unsafe_code)]`)
- **No variable-time signature verification**
- **No secret-dependent branching in CBOR parsing** (all branches are on public metadata)
- **Zeroize support** for key material via `ShreddingKey`
- **Post-quantum readiness** via ML-DSA-65 (FIPS 204)

**Recommendation:** For production deployment, consider:
1. Adding a `verify_vartime` vs `verify_strict` audit for Ed25519 in constrained environments
2. FIPS 140-3 validation of the ML-DSA-65 implementation
3. Differential power analysis (DPA) testing of the embedded composite signature pipeline
