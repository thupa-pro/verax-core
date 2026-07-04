# axiom-core-ffi

C FFI bindings for the Axiom Protocol core library.

## Building

```bash
cargo build --release -p axiom-core-ffi
```

Produces `libaxiom_core_ffi.so` (Linux), `libaxiom_core_ffi.dylib` (macOS), or `axiom_core_ffi.dll` (Windows).

## API

See the header file at [`include/axiom_core.h`](include/axiom_core.h) for the complete C API documentation.

### Core Functions

| Function                    | Description |
|-----------------------------|-------------|
| `axiom_version()`           | Version string |
| `axiom_verify_ed25519()`    | Verify Ed25519 COSE statement |
| `axiom_verify_composite()`  | Verify composite Ed25519 + ML-DSA-65 statement |
| `axiom_verify_mldsa65_only()` | Verify ML-DSA-65-only statement |
| `axiom_verify_full()`       | Full protocol verification with chain + revocation |
| `axiom_sign_ed25519()`      | Sign a payload with Ed25519 |
| `axiom_sign_composite()`    | Sign with Ed25519 + ML-DSA-65 |
| `axiom_encrypt_pii()`       | Encrypt PII data |
| `axiom_decrypt_pii()`       | Decrypt PII data |
| `axiom_shredding_commit()`  | Encrypt + produce commitment |
| `axiom_encode_payload()`    | Encode a payload to CBOR |
| `axiom_payload_decode()`    | Decode CBOR into payload fields |
| `axiom_free()`              | Free allocated memory |

### Structs

- `FfiSlice` — Byte slice descriptor `{data, len}`
- `FfiVerifyResult` — Verification result `{return_code, payload, payload_len, warnings, warnings_len}`

### Error Codes

| Code | Error |
|------|-------|
| 0  | Success |
| 1  | MalformedCose |
| 2  | NonCanonicalEncoding |
| 3  | InvalidSignature |
| 4  | BrokenLineage |
| ... | See header file for full list |

### Linking

```c
#include "axiom_core.h"

// Link with: -laxiom_core_ffi -lm -ldl
```

## Go Usage

The Go bindings in [`crates/axiom-core-go`](../axiom-core-go) wrap this C FFI:

```go
import "github.com/anomalyco/axiom-core/crates/axiom-core-go"

payload, err := axiom.VerifyEd25519(coseBytes, pubkey)

payload, err := axiom.VerifyEd25519(coseBytes, pubkey)
```
