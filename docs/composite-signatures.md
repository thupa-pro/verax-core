# Composite Signatures (Ed25519 + ML-DSA-65)

verax supports composite signatures that combine Ed25519 (classical) and ML-DSA-65 (post-quantum, FIPS 204) to provide dual-algorithm security.

## Algorithm

The composite signing algorithm works as follows:

1. **Input**: `payload_bytes` (CBOR-encoded `VeraxPayload`)
2. **Ed25519 sign**: `sigma_ed = Sign_ed25519(sk_ed, payload_bytes)`
3. **ML-DSA-65 sign**: `sigma_ml = Sign_ml-dsa-65(sk_ml, payload_bytes)`
4. **Composite signature**: The two signatures are concatenated: `sigma_ed || sigma_ml`
5. **Composite public key**: The two public keys are concatenated: `pk_ed (32) || pk_ml (1952)`

## COSE Encoding

Algorithm ID: `-39` (Composite Ed25519 + ML-DSA-65)

The composite signature is encoded in a standard COSE_Sign1 envelope. The `alg` protected header is set to `-39`. The `kid` protected header is set to `BLAKE3(pk_ed || pk_ml)` (first 8 bytes as key identifier).

## Verification Modes

| Mode | Description |
|------|-------------|
| `Hybrid` | Both signatures must verify (default) |
| `Ed25519Only` | Only check the Ed25519 component |
| `MLDSA65Only` | Only check the ML-DSA-65 component |

## Public Key Format

`CompositePublicKey` is a Rust struct:

```rust
pub struct CompositePublicKey {
    pub ed25519: [u8; 32],    // Ed25519 public key
    pub mldsa65: [u8; 1952],  // ML-DSA-65 public key (encoded)
}
```

Total composite public key size: 1984 bytes.

## Security Properties

- **Dual-algorithm security**: Attacker must break both Ed25519 and ML-DSA-65 to forge a signature.
- **Post-quantum readiness**: ML-DSA-65 is a FIPS 204 standard lattice-based signature scheme.
- **Backward compatibility**: Ed25519-only verification works on composite statements by extracting the Ed25519 component.
