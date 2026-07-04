# Axiom Agent Constitution

Hard constraints for AI coding agents working on axiom-core.

## 1. Integrity Invariants

- **NO `unsafe` code** in `axiom-core`. The crate is `#![deny(unsafe_code)]`. FFI crates (`axiom-core-ffi`) may use `unsafe` only where absolutely required by the C ABI.
- **NO adding `std`** to `axiom-core`. The crate is `#![no_std]` with `extern crate alloc`.
- **NO `unwrap()` or `expect()`** in production code paths. Use `?` with proper error types. Panics are only acceptable in test code.
- **NO `panic!()`** in production code paths.
- **NO hardcoded secrets, keys, or passwords** in source code.

## 2. Security Invariants

- All secret comparisons MUST use `ConstantTimeEq` (from `subtle` or `ed25519-dalek`).
- All secret key material MUST implement `ZeroizeOnDrop`.
- Ed25519 verification MUST use `verify_strict()` (rejects malleable signatures), NOT `verify()`.
- COSE envelope parsing MUST check for canonical CBOR encoding (call `check_protected_header_determinism()`).
- Do NOT introduce new dependencies without checking their security posture, license compatibility, and maintenance status.

## 3. Dependency Invariants

- No GPL or copyleft-licensed dependencies.
- All new dependencies MUST be pre-approved for the `no_std` target (if added to `axiom-core`).
- Run `cargo deny check` after any dependency change. Do NOT add ignores without triage.

## 4. Build Invariants

- `cargo clippy --workspace -- -D warnings` MUST pass before any commit.
- `cargo test --workspace` MUST pass before any commit.
- `cargo fmt --check` MUST pass before any commit.
- Do NOT commit `Cargo.lock` changes without a corresponding `Cargo.toml` change.

## 5. Documentation Invariants

- Every new public function MUST have a `///` doc comment.
- Every new crate MUST have a `README.md`.
- Protocol-level changes MUST update `docs/`.

## 6. Contract

This constitution binds ALL AI agents working on this repository. If you cannot comply with a constraint, state the conflict explicitly and seek human approval before proceeding. Violations will be reverted.
