# Contributing to Axiom Protocol

## Getting Started

### Prerequisites

- **Rust** (stable) — via [rustup](https://rustup.rs/)
- **Rust nightly** (for Kani proofs) — `rustup toolchain install nightly-2025-11-21`
- **Go 1.22+** — for Go bindings
- **Python 3.11+** — for Python bindings
- **Node.js 20+** — for Node.js bindings
- **TLA+ Toolbox** — for TLA+ formal specification (optional)
- **Lean 4** — for Lean formal proofs (optional)
- **Coq** — for Coq proofs (optional)

### Building

```bash
# Build all Rust crates
cargo build --workspace

# Build release
cargo build --release --workspace

# Build specific crate
cargo build -p axiom-core
cargo build -p axiom-cli
cargo build -p axiom-core-ffi
```

### Testing

```bash
# Run all Rust tests
cargo test --workspace

# Run with release
cargo test --release --workspace

# Run specific test
cargo test -p axiom-core -- test_name

# Run Go tests (requires FFI shared library)
cargo build --release -p axiom-core-ffi
cd axiom-go && go test -v ./...
```

### Kani Proofs

```bash
cargo kani -p axiom-core --harness harness_name
```

Requires nightly toolchain. Kani proof harnesses are in `crates/axiom-core/src/verify.rs`.

## Code Style

- **No `unsafe` code** in the core crate. The entire `axiom-core` crate is `#![deny(unsafe_code)]`.
- Format with `cargo fmt` before committing.
- Run `cargo clippy -- -D warnings` before opening a PR.
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Use existing patterns: see neighboring files for conventions.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Make your changes with clear commit messages.
3. Run the full test suite: `cargo test --workspace`.
4. Run clippy: `cargo clippy --workspace -- -D warnings`.
5. Ensure any new public API has doc comments.
6. Update `CHANGELOG.md` with a description of your changes.
7. Open a PR against `main` with a clear description.

## Adding Test Vectors

Test vectors live in `test-vectors/` (JSON format). To add new vectors:

1. Add your test case to the appropriate JSON file.
2. Ensure both positive and negative test cases are included.
3. Run `cargo test` to verify the conformance suite passes.

## Documentation

- Public API must have `///` doc comments.
- Crate-level changes should update the crate's `README.md`.
- Protocol-level changes should update `docs/`.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
