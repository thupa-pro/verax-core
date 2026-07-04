# axiom-cli

Command-line interface for the Axiom provenance protocol.

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release -p axiom-cli
./target/release/axiom --help
```

## Quick Start

```bash
# Initialize a project
axiom init

# Sign an artifact
echo "Hello!" > hello.txt
axiom sign hello.txt

# Verify the statement
axiom verify hello.axm

# Inspect the statement
axiom inspect hello.axm
```

## Commands

| Command                    | Description |
|----------------------------|-------------|
| `axiom init`               | Create a new project |
| `axiom sign <file>`        | Sign an artifact |
| `axiom verify <file>`      | Full protocol verification |
| `axiom inspect <file>`     | Decode and display statement fields |
| `axiom lint <file>`        | Check for best practices |
| `axiom graph <file>`       | Visualize the provenance chain |
| `axiom key generate`       | Generate a signing key |
| `axiom key list`           | List stored keys |
| `axiom hash <file>`        | Hash an artifact |
| `axiom doctor`             | System diagnostics |
| `axiom benchmark`          | Performance benchmarks |
| `axiom test`               | Built-in test suite |
| `axiom tutorial`           | Interactive tutorial |

## Sign Options

- `--composite` / `-c` — Use Ed25519 + ML-DSA-65 hybrid signature
- `--ml-dsa-key <file>` — ML-DSA-65 seed file (auto-generated if omitted with `--composite`)
- `--ml-dsa-key-hex <hex>` — ML-DSA-65 seed as hex
- `--ct-anchor-file <file>` — Embed a CT anchor (CBOR TemporalAnchor)
- `--key <file>` — Ed25519 signing key file
- `--key-hex <hex>` — Ed25519 signing key as hex

## Verify Options

- `--chain-dir <dir>` — Directory containing chain statements
- `--trusted-log-key <hex>` — Trusted CT log public key
- `--pubkey <hex>` — Public key for verification
- `--revocation-cache <file>` — JSON revocation cache

## Output Formats

- Human-readable report (default)
- `--json` — JSON output
