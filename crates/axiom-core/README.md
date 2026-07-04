# axiom-core

Core protocol library for the Axiom provenance protocol.

`no_std` with `alloc`. Provides deterministic CBOR payloads, COSE_Sign1 signing/verification, CT anchoring, PII shredding, and full protocol verification.

## Usage

```rust
use axiom_core::{AxiomPayload, Predicate, Statement, hash::blake3};

// Create a payload
let artifact_hash = blake3(b"Hello, Axiom!");
let payload = AxiomPayload::new(artifact_hash, Predicate::Attests);

// Sign with Ed25519
let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
let stmt = Statement::sign_ed25519(&payload, &sk).unwrap();

// Verify
let vk = sk.verifying_key();
let decoded = axiom_core::verify_statement_ed25519(stmt.to_bytes(), &vk).unwrap();
```

## Key Types

- [`AxiomPayload`] — The signed data structure (subject, predicate, optional fields)
- [`Statement`] — A COSE_Sign1 signed statement
- [`TrustStore`] — Trait for key resolution, chain caching, revocation checking
- [`CompositePublicKey`] — Ed25519 + ML-DSA-65 hybrid public key
- [`TemporalAnchor`] — CT log anchor (inclusion proof + signed tree head)
- [`ShreddingKey`] — Key for PII shredding (encrypt/decrypt/commit)

## Features

- **Deterministic CBOR**: Canonical encoding prevents malleability
- **Ed25519 signing**: Standard single-algorithm signatures
- **Composite signing**: Ed25519 + ML-DSA-65 hybrid (post-quantum)
- **CT anchoring**: Bind statements to Certificate Transparency logs
- **Full verification**: Signature, lineage, key rotation, timestamps, revocation, CT anchors
- **PII shredding**: AEAD encryption + BLAKE3 commitment
- **Formal proofs**: TLA+, Coq, Lean 4, Kani

## Verification API

- `verify_statement_ed25519` — Simple signature-only verification
- `verify_statement_with_warnings` — Full protocol verification via `TrustStore`
