# verax Protocol

[![CI](https://github.com/thupa-pro/verax-core/actions/workflows/ci.yml/badge.svg)](https://github.com/thupa-pro/verax-core/actions/workflows/ci.yml)
[![verax-True](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/thupa-pro/verax-core/main/.github/badges/verax-true-status.json&color=2ea44f)](https://github.com/thupa-pro/verax-core/actions/workflows/verax-compliance.yml)
[![cargo-deny](https://img.shields.io/badge/cargo--deny-passed-brightgreen)](https://github.com/thupa-pro/verax-core/actions/workflows/verax-compliance.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![Rust Edition](https://img.shields.io/badge/edition-2024-blue)

A **tamper-evident provenance protocol** with deterministic CBOR, post-quantum composite signatures (Ed25519 + ML-DSA-65), Certificate Transparency anchoring (RFC 9162), and PII shredding. Passed an IETF forensic audit with 101 tests and full verax-True v1.0 verification compliance. Bindings for Rust, C, Python, Node.js, and Go.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Key Concepts](#key-concepts)
- [Architecture](#architecture)
- [API Overview](#api-overview)
- [Language Bindings](#language-bindings)
- [Security](#security)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)

---

## Quick Start

```bash
# Install the CLI
cargo install --path crates/verax-cli

# Initialize a project
verax init

# Sign an artifact (produces hello.axm)
echo "Hello, verax!" > hello.txt
verax sign hello.txt

# Verify full protocol — lineage, key rotation, timestamps, revocation
verax verify hello.axm
```

---

## Key Concepts

**Statements** — The core unit of provenance: an artifact hash, a subject hash, a predicate (e.g. `attests`, `authors`, `derived_from`), and metadata, serialized as deterministic CBOR and signed.

**Predicates** — Typed relationships between artifacts: `attests`, `authors`, `derived_from`, `amends`, `rejects`. Each predicate has defined semantics in the protocol spec.

**Lineage DAGs** — Statements form a directed acyclic graph where each statement can reference a parent. Lineage resolution is bounded at 1024 depth and verified iteratively to prevent recursion attacks (T2 fix).

**CT Anchors** — Every statement can be bound to a Certificate Transparency log via an `anchor_hash` in the payload. Verification checks inclusion proofs against a trusted log's Signed Tree Head (T1 fix).

**Composite Signatures** — Ed25519 + ML-DSA-65 hybrid signatures (FIPS 204). Both algorithms must verify for the composite to be valid, providing post-quantum security today.

**Deterministic CBOR** — Canonical CBOR encoding (deterministic maps, sorted keys, no indefinite-length) prevents signature malleability attacks. Verified by decode-then-re-encode equality (T5 fix).

**PII Shredding** — Encrypt-then-commit protocol for personally identifiable information. Supports `shredding_commit` (SHA3-256 of ciphertext + IV) for right-to-be-forgotten compliance (GDPR, CCPA).

**Revocation** — Log-based revocation with local JSON cache. The CLI caches `revoked` / `not_revoked` entries with checkpoint timestamps to minimize network queries during batch verification.

---

## Architecture

verax is organized as a `no_std`-compatible core library with language bindings and a CLI on top.

```
verax-core (no_std core)
├── payload       — Deterministic CBOR payload construction
├── cose          — COSE Sign1 envelope (RFC 9052)
├── signing       — Ed25519 + ML-DSA-65 composite signer
├── verification  — TrustStore trait, full protocol verification
├── ct            — CT anchoring, log inclusion proofs, STH
├── shred         — PII encryption + shredding commitment
└── keyring       — Key generation, rotation, resolution

verax-cli          — CLI (init, sign, verify, inspect, lint, graph)
verax-core-ffi     — C FFI (Go, Zig, etc.)
verax-core-python  — Python bindings (PyO3)
verax-core-node    — Node.js bindings (napi-rs)
```

---

## API Overview

| Function | Description |
|----------|-------------|
| `sign_ed25519_and_anchor` | Sign a statement with Ed25519 + optional CT anchor binding |
| `sign_composite_and_anchor` | Sign with Ed25519 + ML-DSA-65 composite + CT anchor binding |
| `verify_statement_with_warnings` | Full protocol verification via `TrustStore` |
| `encode_payload` / `decode_payload` | Serialize/deserialize deterministic CBOR payloads |
| `encrypt_pii` / `decrypt_pii` | PII encryption/decryption with AES-256-GCM |
| `shredding_commit` | Generate SHA3-256 commitment for encrypted PII |
| `generate_ed25519_key` | Ed25519 key pair generation |
| `generate_composite_keyring` | Ed25519 + ML-DSA-65 keyring generation |

---

## Language Bindings

| Feature | Rust | C (FFI) | Python | Node.js | Go |
|---------|------|----------|--------|---------|----|
| Ed25519 sign/verify | Yes | Yes | Yes | Yes | Yes |
| Composite sign/verify | Yes | Yes | Yes | Yes | Via FFI |
| Full protocol verification | Yes | Yes | Yes | Yes | Via FFI |
| CT anchoring | Yes | Yes | Yes | Yes | Via FFI |
| PII encryption/decryption | Yes | Yes | Yes | Yes | Via FFI |
| Shredding commit | Yes | Yes | Yes | Yes | Via FFI |
| Payload encode/decode | Yes | Yes | Yes | Yes | Via FFI |

---

## Security

See [SECURITY.md](SECURITY.md) for our disclosure policy and [docs/security_audit.md](docs/security_audit.md) for the full IETF forensic audit report. verax passes [verax-True](https://github.com/thupa-pro/verax-core/actions/workflows/verax-compliance.yml) v1.0 compliance with formal proofs in TLA+, Coq, Lean 4, and Kani harnesses covering 6 key properties.

---

## Documentation

- [Getting Started](docs/getting-started.md) — Step-by-step walkthrough
- [Architecture](docs/architecture.md) — High-level design and data flow
- [Protocol Specification](docs/protocol-spec.md) — CBOR payload format, COSE envelopes, CT anchoring
- [Composite Signatures](docs/composite-signatures.md) — Ed25519 + ML-DSA-65 hybrid signing
- [PII Shredding](docs/shredding.md) — Encryption and commitment for right-to-be-forgotten
- [Key Rotation](docs/key-rotation.md) — Key rotation protocol and chain resolution
- [Security Audit](docs/security_audit.md) — Third-party security analysis
- [Formal Proofs](FORMAL_PROOFS.md) — Map of formal verification and proof harnesses

---

## Development

- [Contributing Guide](CONTRIBUTING.md)
- [Agent Constitution](AGENTS.md) — Hard constraints for AI coding agents
- [Pre-commit hooks](.pre-commit-config.yaml) — Auto-enforce code quality
- [`cargo-deny`](deny.toml) — Dependency license and advisory checking

---

## License

MIT — see [LICENSE](LICENSE).
