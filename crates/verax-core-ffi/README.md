# verax-core-ffi

C FFI bindings for the Verax Protocol core library.

## Building

```bash
cargo build --release -p verax-core-ffi
```

Produces `libverax_core_ffi.so` (Linux), `libverax_core_ffi.dylib` (macOS), or `verax_core_ffi.dll` (Windows).

## API

See the header file at [`include/verax_core.h`](include/verax_core.h) for the complete C API documentation.

### Core Functions

| Function                    | Description |
|-----------------------------|-------------|
| `verax_version()`           | Version string |
| `verax_verify_ed25519()`    | Verify Ed25519 COSE statement |
| `verax_verify_composite()`  | Verify composite Ed25519 + ML-DSA-65 statement |
| `verax_verify_mldsa65_only()` | Verify ML-DSA-65-only statement |
| `verax_verify_full()`       | Full protocol verification with chain + revocation |
| `verax_sign_ed25519()`      | Sign a payload with Ed25519 |
| `verax_sign_composite()`    | Sign with Ed25519 + ML-DSA-65 |
| `verax_encrypt_pii()`       | Encrypt PII data |
| `verax_decrypt_pii()`       | Decrypt PII data |
| `verax_shredding_commit()`  | Encrypt + produce commitment |
| `verax_encode_payload()`    | Encode a payload to CBOR |
| `verax_payload_decode()`    | Decode CBOR into payload fields |
| `verax_free()`              | Free allocated memory |

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
#include "verax_core.h"

// Link with: -lverax_core_ffi -lm -ldl
```

## Go Usage

The Go bindings in [`crates/verax-core-go`](../verax-core-go) wrap this C FFI:

```go
import "github.com/anomalyco/verax-core/crates/verax-core-go"

payload, err := verax.VerifyEd25519(coseBytes, pubkey)

payload, err := verax.VerifyEd25519(coseBytes, pubkey)
```
