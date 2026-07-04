# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-02

### Added

- **Core protocol**: Ed25519 signing and verification with deterministic CBOR encoding
- **Composite signatures**: Ed25519 + ML-DSA-65 hybrid post-quantum signing
- **Certificate Transparency anchoring**: Bind statements to CT logs with `sign_ed25519_and_anchor` / `sign_composite_and_anchor`
- **Full protocol verification**: `verify_statement_with_warnings` checks signature, lineage, key rotation, timestamps, revocation, and CT anchors
- **TrustStore trait**: Pluggable key resolution, chain caching, and revocation checking
- **PII shredding**: AEAD encryption + BLAKE3 commitment for right-to-be-forgotten compliance
- **CLI**: `axiom init`, `sign`, `verify`, `inspect`, `lint`, `graph`, `key`, `hash`, `doctor`, `benchmark`, `tutorial`, `test`
- **CLI `verify`**: Full protocol verification with `--chain-dir`, `--trusted-log-key`, `--revocation-cache`
- **CLI `sign`**: `--composite`, `--ml-dsa-key`, `--ct-anchor-file` for post-quantum and CT-anchored signing
- **Python bindings**: `verify_ed25519`, `verify_composite`, `verify_full`, `sign_ed25519`, `sign_composite`, `encrypt`, `decrypt`, `shredding_commit_fn`, `encode_payload`, `decode_payload`
- **Node.js bindings**: Same API via napi-rs with `JsVerificationResult` object
- **C FFI**: Full C ABI for verification, signing, shredding, and payload encoding
- **Go bindings**: Wrapper around C FFI with `VerifyEd25519`, `VerifyComposite`, `SignEd25519`, `SignComposite`, `EncryptPII`, `DecryptPII`, `ShreddingCommit`, `VerifyFull`
- **Formal proofs**: TLA+ specification, Coq proof of CBOR determinism, Lean 4 proof harness, Kani proof harnesses (6)
- **Test vectors**: Conformance suite with valid/invalid Ed25519, ML-DSA-65, and composite cases

### Security

- **T1 (CT Anchor Malleability)**: `anchor_hash` field cryptographically binds the CT anchor to the signed payload
- **T2 (Lineage Recursion)**: Iterative loop bounded at `MAX_LINEAGE_DEPTH=1024`
- **T3 (Key Rotation Recursion)**: Iterative loop bounded at `MAX_ROTATION_DEPTH=128`
- **T4 (CLI Bypass)**: CLI `verify` uses `verify_statement_with_warnings` via `CliTrustStore`
- **T5 (Non-Deterministic COSE)**: `check_protected_header_determinism()` validates canonical CBOR on protected headers
- **F3 (list_keys label)**: `KeyMaterial::algorithm()` returns correct algorithm identifier
- **F5 (is_strictly_deterministic)**: Decode-then-re-encode equality check

### Fixed

- Ed25519 public key extraction from COSE KID for cross-platform verification
- Ephemeral key auto-generation with proper storage in `.axiom/keys/`
- Zero `unsafe` code in core library (`#![deny(unsafe_code)]`)

### Notes

- Kani proof harnesses require nightly-2025-11-21 toolchain (blocked on rustup availability in CI)
- Full CT log submission from CLI is not yet implemented (requires HTTP client); use `--ct-anchor-file` for offline-prepared anchors
