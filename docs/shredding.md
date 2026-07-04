# PII Shredding

Axiom provides cryptographic shredding for personally identifiable information (PII) — the "right to be forgotten" in practice.

## Overview

PII shredding encrypts sensitive data and produces a cryptographic commitment. The commitment proves the data existed at a point in time, but the encrypted data can be destroyed to achieve erasure.

## API

```
encrypt(key, plaintext) → ciphertext
decrypt(key, ciphertext) → plaintext
shredding_commit(key, plaintext) → (ciphertext, commitment)
```

The `commitment` is a 32-byte BLAKE3 hash. The `key` is a 32-byte `ShreddingKey`.

## Encryption Scheme

1. Derive an AEAD key from `ShreddingKey` using BLAKE3 key derivation.
2. Encrypt the plaintext using ChaCha20-Poly1305.
3. Return the ciphertext (nonce + AEAD tag + encrypted data).

## Commitment Scheme

The commitment is computed as:

```
commitment = BLAKE3("axiom-shred" || key_commitment || plaintext)
```

Where `key_commitment` is derived from the shredding key.

## Formal Theorem

The shredding module includes a formal theorem in its documentation:

> **Shredding Theorem**: Given a valid commitment `comm` and a candidate `(key, plaintext)`, the verifier can check whether `comm = BLAKE3("axiom-shred" || key_commit || plaintext)`. If the match holds, the (key, plaintext) pair is authentic. The commitment alone leaks no information about the plaintext (hiding) and cannot be opened to a different plaintext (binding).

## Metadata Leakage Awareness

While cryptographic shredding prevents plaintext PII from entering the DAG, **metadata** such as ciphertext hashes, timestamps, and statement predicates can still constitute personal data under GDPR Article 4(1).

Implementations SHOULD:

1. **Minimize ciphertext hash exposure** — Use a fresh encryption key per data subject to prevent correlation across statements.
2. **Avoid meaningful timestamps** — Use minimal precision timestamps when the exact time is unnecessary for the use case.
3. **Use opaque subject identifiers** — Never use a subject hash that could be pre-computed from a known-plaintext dictionary (always encrypt before hashing).

> **Legal note**: Under CJEU interpretations, ciphertext hashes have been considered pseudonymous data (not anonymous) when the encryption key exists. After key destruction, the ciphertext becomes computationally indistinguishable from random noise.

## Use Case: Right to Be Forgotten

1. Submit PII shredding commitment to a transparency log.
2. The commitment proves data existed at that point.
3. When erasure is requested, delete the ciphertext.
4. The commitment remains as proof of compliance without exposing the data.
