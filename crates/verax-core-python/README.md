# verax-core-python

Python bindings for the Verax Protocol core library.

Built with [PyO3](https://pyo3.rs/).

## Installation

```bash
pip install verax-core-python
```

Or build from source:

```bash
cargo build --release -p verax-core-python
cp target/release/libverax_core_python.so /path/to/site-packages/verax_core_python.so
```

## Usage

```python
import verax_core_python as verax

# Sign
payload = verax.encode_payload(bytes(32), "attests")
key = bytes(32)
sig = verax.sign_ed25519(payload, key)

# Verify
result = verax.verify_full(sig, key, trusted_log_key=bytes(32))
print("Valid:", result["valid"])
print("Warnings:", result["warnings"])
```

## API

| Function | Description |
|----------|-------------|
| `verify_ed25519(cose, pubkey)` → bytes | Verify Ed25519 signature |
| `verify_composite(cose, ed_pk, ml_pk)` → bytes | Verify composite signature |
| `verify_full(cose, pubkey, ...)` → dict | Full protocol verification |
| `sign_ed25519(payload, key)` → bytes | Sign with Ed25519 |
| `sign_composite(payload, ed_key, ml_seed)` → bytes | Composite sign |
| `encode_payload(subject, predicate)` → bytes | Encode payload to CBOR |
| `decode_payload(cbor)` → Payload | Decode CBOR payload |
| `encrypt(key, plaintext)` → bytes | Encrypt PII |
| `decrypt(key, ciphertext)` → bytes | Decrypt PII |
| `shredding_commit_fn(key, plaintext)` → (ct, comm) | Shredding commit |

### verify_full Parameters

- `cose` — COSE statement bytes
- `pubkey` — 32-byte Ed25519 public key
- `chain_statements` — Optional list of chain statement bytes
- `trusted_log_key` — Optional 32-byte CT log public key
- `revoked` — Optional list of hex-encoded revoked hashes
- `not_revoked` — Optional list of hex-encoded non-revoked hashes
- `checkpoint_timestamp` — Optional STH timestamp for revocation cache

Returns dict: `{"valid": bool, "payload": dict, "warnings": [str], "error": str}`
