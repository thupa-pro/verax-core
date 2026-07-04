# Protocol Specification

## VeraxPayload CBOR Format

The core data structure is the `VeraxPayload`, encoded as deterministic CBOR:

### Fields

| Key | Name            | Type               | Required | Description |
|-----|-----------------|---------------------|----------|-------------|
| 1   | subject         | bstr (32)           | ✅       | BLAKE3 hash of the referenced artifact |
| 2   | predicate       | uint                | ✅       | Predicate code (see below) |
| 3   | object          | bstr (32)           | ❌       | Optional BLAKE3 hash of a related artifact |
| 4   | timestamp       | uint                | ❌       | Unix epoch seconds |
| 5   | lineage         | bstr (32)           | ❌       | BLAKE3 hash of the previous statement |
| 6   | nonce           | bstr (32)           | ❌       | Random nonce for uniqueness |
| 8   | anchor_hash     | bstr (32)           | ❌       | BLAKE3 hash of the COSE unprotected header (CT anchor binding) |
| 10  | recovery_policy | bstr (CBOR-encoded) | ❌       | Key recovery policy (see §Recovery Policy) |

### Predicates

| Code | Name          | Description |
|------|---------------|-------------|
| 0    | attests       | Statement attests to the artifact |
| 1    | authors       | Subject is author of the artifact |
| 2    | derived_from  | Subject was derived from the object |
| 3    | supersedes    | Subject supersedes the previous statement |
| 4    | revokes       | Subject revokes the referenced statement |
| 5    | endorses      | Subject endorses the artifact |
| 6    | appends       | Subject appends to the chain |
| 7    | complies_with | Subject complies with a policy |
| 8    | recovers      | Guardian authorises replacement of a lost key |

## COSE_Sign1 Envelope

Statements are wrapped in a COSE_Sign1 envelope (RFC 8152):

```
COSE_Sign1 = [
    protected: bstr,
    unprotected: { * (int / tstr) => any },
    payload: bstr,
    signature: bstr,
]
```

### Protected Header

| Key | Value | Description |
|-----|-------|-------------|
| 1   | alg   | Algorithm ID |
| 2   | kid   | Key identifier |

### Algorithm IDs

| ID  | Algorithm |
|-----|-----------|
| -8  | Ed25519 (COSE pre-standard) |
| -39 | Composite Ed25519 + ML-DSA-65 |

### Unprotected Header

For anchored statements, the unprotected header contains:

| Key                    | Value           | Description |
|------------------------|-----------------|-------------|
| log_inclusion_proof    | bstr (CBOR map) | Merkle inclusion proof |
| log_sth                | bstr (CBOR map) | Signed tree head |

The `anchor_hash` field in the payload is BLAKE3(payload_hash). This cryptographically binds the unprotected header to the signed payload (T1 fix).

## Determinism Guarantees

All CBOR encoding is strictly deterministic:

- Map keys are encoded in ascending numerical order.
- Integer encoding uses the smallest encoding (e.g., 0–23 encoded as 0x00..0x17).
- `bstr` lengths use the smallest encoding.
- No indefinite-length encoding is used.
- `is_strictly_deterministic` verifies by decode-then-re-encode equality (F5 fix).

### String-Encoded Decimal Canonicalization

If the extensions map or any field uses a string-encoded decimal (e.g., `"1.5"`), implementations MUST apply a canonical form to guarantee identical hashes across all platforms:

1. **Strip leading zeros** from the integer part (e.g., `"01.5"` → `"1.5"`).
2. **Strip trailing zeros** after the decimal point (e.g., `"1.50"` → `"1.5"`).
3. **Strip trailing decimal point** (e.g., `"1."` → `"1"`).
4. **Use lowercase** for any exponent notation (e.g., `"1.5E2"` → `"1.5e2"`).

This canonical form is implementation-defined but MUST be consistent across all consumers to ensure deterministic hashing. The core payload does not use string-encoded decimals; this applies to private extensions only.

## CT Anchoring

CT anchoring binds a statement to a Certificate Transparency log:

1. The statement hash is submitted to a CT log.
2. The log returns a `SignedTreeHead` (signed tree root + timestamp) and a `LogInclusionProof` (Merkle audit path).
3. These are embedded in the COSE unprotected header.
4. The `anchor_hash` field in the payload is set to BLAKE3 of the unprotected header.
5. Verification checks: the unprotected header hash matches `anchor_hash`, the Merkle proof verifies, and the STH signature is valid against a trusted log key.

### LogInclusionProof

CBOR map:
| Key | Name       | Type         | Description |
|-----|------------|--------------|-------------|
| 1   | leaf_index | uint         | Index of the leaf in the Merkle tree |
| 2   | siblings   | [bstr (32)]  | Merkle audit path (sibling hashes) |

### SignedTreeHead

CBOR map:
| Key | Name               | Type        | Description |
|-----|--------------------|-------------|-------------|
| 1   | timestamp          | uint        | STH timestamp (Unix epoch seconds) |
| 2   | tree_size          | uint        | Number of leaves in the tree |
| 3   | root_hash          | bstr (32)   | Merkle tree root hash |
| 4   | signature          | bstr (64)   | Ed25519 signature over the STH |
| 5   | log_pubkey         | bstr (32)   | Log's Ed25519 public key |
| 6   | log_id             | bstr (32)   | BLAKE3(log_pubkey) |
| 7   | tree_hash_algorithm | uint       | 0 = SHA-256 |

## Revocation

Revocation is statement-based: a statement with predicate `revokes` references the hash of the revoked statement in its `object` field.

A revocation cache (JSON) can be used for offline verification:

```json
{
  "checkpoint_timestamp": 1700000000,
  "revoked": ["<hex_hash32>", ...],
  "not_revoked": ["<hex_hash32>", ...]
}
```

The `checkpoint_timestamp` is the STH timestamp at which the cache was built. Hashes in `not_revoked` are definitive proof of non-revocation up to that checkpoint.

> **IMPORTANT**: The absence of a REVOKES statement in a locally monitored log does **not** prove non-revocation.
> A verifier can only conclude non-revocation for statements specifically listed in `not_revoked` up to the
> `checkpoint_timestamp`. Any statement not covered by the cache has unknown revocation status,
> and the verifier SHOULD emit a `RevocationStatusUnknown` warning. This is inherent to CT-based
> revocation: CT logs do not provide content-based lookup, so a verifier cannot prove the absence
> of a revocation statement without a complete cache.

## Recovery Policy

The `recovery_policy` field (key 10) contains a CBOR-encoded `RecoveryPolicy` map:

```cddl
RecoveryPolicy = {
  1: [* bstr .size 32],     ; guardians: list of guardian key BLAKE3 hashes
  2: uint,                   ; threshold: number of guardian approvals needed
  ? 3: uint,                 ; recovery_delay: optional delay in seconds
}
```

When a statement with predicate `recovers` (8) is verified:
1. The subject MUST equal `BLAKE3(issuer_kid)` — binding the statement to the guardian.
2. The object MUST reference the lost key hash.
3. If the target statement (the lost key) carries a `recovery_policy`, the guardian's hash MUST appear in the `guardians` list.
4. Multiple RECOVERS statements for the same lost key can be collected to meet the threshold.

## Key Rotation

Key rotation is expressed as a chain of statements:

1. A statement with the old key attests to the new public key.
2. Verification follows the rotation chain: old → new, bounded by `MAX_ROTATION_DEPTH=100`.
3. The chain is resolved iteratively to prevent stack overflow (T3 fix).
