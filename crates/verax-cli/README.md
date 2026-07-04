# verax-cli

Command-line interface for the verax provenance protocol.

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release -p verax-cli
./target/release/verax --help
```

## Quick Start

```bash
# Initialize a project
verax init

# Sign an artifact
echo "Hello!" > hello.txt
verax sign hello.txt

# Verify the statement
verax verify hello.axm

# Inspect the statement
verax inspect hello.axm
```

## Commands

| Command                    | Description |
|----------------------------|-------------|
| `verax init`               | Create a new project |
| `verax sign <file>`        | Sign an artifact |
| `verax verify <file>`      | Full protocol verification |
| `verax inspect <file>`     | Decode and display statement fields |
| `verax lint <file>`        | Check for best practices |
| `verax graph <file>`       | Visualize the provenance chain |
| `verax key generate`       | Generate a signing key |
| `verax key list`           | List stored keys |
| `verax hash <file>`        | Hash an artifact |
| `verax doctor`             | System diagnostics |
| `verax benchmark`          | Performance benchmarks |
| `verax test`               | Built-in test suite |
| `verax tutorial`           | Interactive tutorial |

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
