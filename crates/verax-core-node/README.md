# verax-core-node

Node.js bindings for the Verax Protocol core library.

Built with [napi-rs](https://napi.rs/).

## Installation

```bash
npm install verax-core-node
```

Or build from source:

```bash
cargo build --release -p verax-core-node
```

## Usage

```javascript
const verax = require('verax-core-node');

// Sign
const payload = verax.encodePayload(Buffer.alloc(32), "attests");
const key = Buffer.alloc(32);
const sig = verax.signEd25519(payload, key);

// Verify
const result = verax.verifyFull(sig, key, null, [], [], [], 0);
console.log("Valid:", result.valid);
console.log("Warnings:", result.warnings);
```

## API

| Function | Returns | Description |
|----------|---------|-------------|
| `version()` | `string` | Version string |
| `verifyEd25519(cose, pubkey)` | `Buffer` | Verify Ed25519 signature |
| `verifyComposite(cose, edPk, mlPk)` | `Buffer` | Verify composite |
| `verifyFull(cose, pubkey, ...)` | `JsVerificationResult` | Full verification |
| `signEd25519(payload, key)` | `Buffer` | Sign with Ed25519 |
| `signComposite(payload, edKey, mlSeed)` | `Buffer` | Composite sign |
| `encodePayload(subject, predicate)` | `Buffer` | Encode payload |
| `decodePayload(cbor)` | `JsPayload` | Decode payload |
| `encrypt(key, plaintext)` | `Buffer` | Encrypt PII |
| `decrypt(key, ciphertext)` | `Buffer` | Decrypt PII |
| `shreddingCommitFn(key, plaintext)` | `Buffer[]` | Shredding commit |

### JsVerificationResult

```typescript
{
  valid: boolean,
  payload?: JsPayload,
  warnings: string[],
  error?: string
}
```

### JsPayload

```typescript
{
  subject: Buffer,
  predicate: string,
  object?: Buffer,
  timestamp?: number,
  lineage?: Buffer,
  nonce?: Buffer,
  anchor_hash?: Buffer
}
```
