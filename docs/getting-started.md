# Getting Started

## Installation

### Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs/)
- **Go 1.22+** — for Go bindings (optional)
- **Python 3.11+** — for Python bindings (optional)
- **Node.js 20+** — for Node.js bindings (optional)

### Build from Source

```bash
git clone https://github.com/anomalyco/axiom-core.git
cd axiom-core

# Build all crates
cargo build --release --workspace

# Install CLI
cargo install --path crates/axiom-cli
```

## Quick Walkthrough

### 1. Initialize a Project

```bash
axiom init
```

Creates a `.axiom/` directory with project configuration.

### 2. Create an Artifact

```bash
echo "Hello, Axiom!" > hello.txt
```

### 3. Sign It

```bash
axiom sign hello.txt
```

This generates:
- An ephemeral Ed25519 signing key (saved to `.axiom/keys/`)
- A signed `.axm` file (`hello.axm`)

### 4. Verify

```bash
axiom verify hello.axm
```

The verify command checks:
- Signature validity
- Canonical CBOR encoding
- Key binding

### 5. Full Protocol Verification

```bash
# With chain, trusted log key, and revocation cache
axiom verify hello.axm \
  --chain-dir ./chain \
  --trusted-log-key <hex_key> \
  --revocation-cache cache.json
```

### 6. Post-Quantum Signing

```bash
# Composite Ed25519 + ML-DSA-65
axiom sign hello.txt --composite

# With CT anchor binding
axiom sign hello.txt --composite --ct-anchor-file anchor.cbor
```

### 7. Inspect and Lint

```bash
axiom inspect hello.axm
axiom lint hello.axm
```

## Tutorial

Run the interactive tutorial:

```bash
axiom tutorial
```

## Using the Library

Add `axiom-core` to your `Cargo.toml`:

```toml
[dependencies]
axiom-core = { git = "https://github.com/anomalyco/axiom-core.git" }
```

Example:

```rust
use axiom_core::{AxiomPayload, Predicate, Statement, hash::blake3};
use rand::rngs::OsRng;

let payload = AxiomPayload::new(blake3(b"hello"), Predicate::Attests);
let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
let stmt = Statement::sign_ed25519(&payload, &sk)?;
```

## Next Steps

- [Architecture Overview](architecture.md)
- [Protocol Specification](protocol-spec.md)
- [Composite Signatures](composite-signatures.md)
- [PII Shredding](shredding.md)
