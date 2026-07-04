# Architecture

## Overview

verax is organized as a Rust workspace with five crates and additional binding layers:

```
verax/
├── crates/
│   ├── verax-core/          # Core protocol library (no_std)
│   ├── verax-cli/           # Command-line interface
│   ├── verax-core-ffi/      # C FFI (for Go and other languages)
│   ├── verax-core-python/   # Python bindings (PyO3)
│   ├── verax-core-node/     # Node.js bindings (napi-rs)
│   └── verax-core-go/       # Go bindings (cgo)
├── formal/
│   ├── tlaplus/             # TLA+ specification
│   ├── lean4/               # Lean 4 proofs
│   └── coq/                  # Coq proofs (in core crate)
├── test-vectors/            # Conformance test vectors
├── docs/                    # Design documentation
└── examples/                # Usage examples
```

## Core Crate (`verax-core`)

The core crate is `no_std` with `alloc`. It provides:

### Modules

```
src/
├── lib.rs          # Crate root, re-exports
├── cbor.rs         # Deterministic CBOR: AxiomPayload, encoding, decoding
├── cose.rs         # COSE_Sign1: signing, verification, composite
├── ct.rs           # CT anchoring: TemporalAnchor, LogInclusionProof, SignedTreeHead
├── statement.rs    # Statement: sign, verify, anchor
├── verify.rs       # Verification: TrustStore, lineage, key rotation, revocation
├── hash.rs         # BLAKE3 hashing utilities
├── shred.rs        # PII shredding: encryption, commitment, erasure
├── error.rs        # Error types
├── predicate.rs    # Predicate enum (attests, authors, ...)
├── artifact.rs     # Artifact content-hash verification
└── hsm.rs          # HSM abstraction (optional)
```

### Data Flow

```
Artifact → BLAKE3 hash → AxiomPayload (subject + predicate + metadata)
                                       ↓
                              Statement::sign_ed25519 / sign_composite
                                       ↓
                              COSE_Sign1 envelope (CBOR)
                                       ↓
                              Optional: CT anchor binding
                                       ↓
                              Verify: signature + lineage + key rotation
                                      + timestamps + revocation + CT anchor
```

### Crate Dependency Graph

```
verax-core (no_std)
    ├── ed25519-dalek
    ├── ml-dsa (ML-DSA-65)
    ├── blake3
    ├── sha2
    ├── hpke (HPKE for shredding)
    ├── chacha20poly1305 (AEAD for shredding)
    └── hex
```

## Verification Architecture

Verification uses the `TrustStore` trait, allowing different trust models:

```
                    ┌──────────────────────┐
                    │   TrustStore trait    │
                    ├──────────────────────┤
                    │ resolve_key()         │
                    │ resolve_composite_key │
                    │ fetch_statement()     │
                    │ is_revoked_in_log()   │
                    │ resolve_log_pubkey()  │
                    └──────┬───────────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
     CliTrustStore   PyTrustStore   NapiTrustStore
     (CLI verify)   (Python)       (Node.js)
```

`verify_statement_with_warnings` performs:
1. COSE envelope parsing and protected header determinism check
2. Signature verification (Ed25519 or composite)
3. Statement decoding and payload extraction
4. Temporal anchor verification (if present)
5. Lineage chain traversal (bounded iterative loop)
6. Key rotation chain resolution (bounded iterative loop)
7. Timestamp monotonicity checking
8. Revocation status check (via TrustStore)
9. Warnings collection (non-fatal issues)

## CLI Architecture

The CLI has 26 subcommands organized under `crates/verax-cli/src/commands/`:

```
init          — Create a new project
sign          — Sign an artifact (Ed25519, composite, or anchored)
verify        — Full protocol verification (with chain/key/revocation)
inspect       — Decode and display statement fields
lint          — Best-practice checking
graph         — Visualize provenance chains
key generate  — Generate signing keys
key list      — List stored keys
hash          — Hash an artifact
doctor        — System diagnostics
benchmark     — Performance benchmarks
test          — Built-in test suite
tutorial      — Interactive tutorial
```

## Security Model

- **Integrity**: Each statement is a signed COSE_Sign1 envelope. Signature covers the payload.
- **Determinism**: CBOR encoding is strictly deterministic — the same payload always produces the same bytes.
- **Non-repudiation**: Composite Ed25519 + ML-DSA-65 signatures provide dual-algorithm security.
- **Transparency**: CT anchors bind statements to a public log, enabling third-party verification.
- **Revocation**: Statements can be revoked by issuing a REVOKES statement in the log.
- **Privacy**: PII shredding uses AEAD encryption + BLAKE3 commitment for cryptographic erasure.
