# Key Rotation in the verax Protocol

## Motivation

Signing keys have a finite lifespan. Key rotation allows an entity to
transition from one signing key to another while maintaining a verifiable
chain of custody.  This spec defines how key rotation works in the verax
protocol at the COSE/payload layer.

## Approach: Rotation Is a Statement

A key rotation IS an verax statement.  There is no special "ROTATE"
predicate — the existing `SUPERSEDES` predicate carries the semantics:

```
subject  = BLAKE3(new_public_key)     # the identity being introduced
predicate = SUPERSEDES
object   = BLAKE3(old_public_key)     # the identity being replaced
lineage  = hash_of_previous_rotation or None
```

The signature on this COSE message MUST be produced by the **old** private
key.  This proves that the old key authorizes the new one.

## Three Roles

| Role | Description |
|---|---|
| **Trust anchor** | A long-lived key pair whose public key is pre-distributed to all verifiers (e.g. embedded at application build time, or pinned via DNS / HPKP-style header). Rotation chains terminate here. |
| **Active signing key** | The key currently used to sign statements. |
| **Rotation statement** | An verax `SUPERSEDES` statement linking an active key to a predecessor. |

## Verification Flow

When a verifier encounters a COSE message with `kid` that is NOT the trust
anchor:

1.  **Fetch the rotation statement** — look up `kid` (the pubkey hash of the
    active key) in the TrustStore, which returns the rotation statement
    whose `subject == kid`.

2.  **Verify the rotation signature** — the rotation statement's COSE
    signature must verify against the **predecessor** key.

3.  **Recurse** — repeat with the predecessor key until the trust anchor is
    reached (the chain terminates at a self-signed anchor or a key known a
    priori).

4.  **Bound the chain** — a `MAX_ROTATION_DEPTH` constant (default: 8)
    prevents infinite loops.  If the anchor is not reached within the
    limit, verification fails.

5.  **Check revocation** — if any key in the rotation chain has been
    revoked (via the standard `REVOKES` predicate), verification fails.

## TrustStore API

A new method on `TrustStore` supports rotation resolution:

```rust
/// Resolve a signing key from its KID, following rotation chains.
/// Returns the terminal key (closest to the trust anchor), or None if
/// the KID is unknown.
fn resolve_rotated_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey>;
```

The default implementation follows:
1.  If `resolve_key(kid)` returns `Some(pk)`, return `Some(pk)` directly
    (the key is known without rotation).
2.  Otherwise, look for a rotation statement whose `subject == hash(kid)`.
3.  Decode the rotation statement, extract its COSE kid, and recurse.

## Security Properties

### Pre-image resistance
Since `subject = BLAKE3(pubkey)`, an attacker cannot craft a rotation
statement claiming a key they don't control — they would need to find a
second pre-image of BLAKE3.

### Authorization proof
The rotation COSE is signed by the old key. A compromise of the new key
alone does not allow an attacker to insert an unauthorized rotation.

### Auditability
Rotation statements are standard verax statements. They can be anchored in
a CT log like any other statement, providing public timestamp evidence.

### Revocation transparency
If the old key is explicitly revoked (via a REVOKES statement), any
rotation signed by that key after the revocation timestamp is invalid.

## Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_ROTATION_DEPTH` | `100` | Maximum key rotation chain depth |

## Implementation Plan

1. Add `TrustStore::resolve_rotated_key` with default implementation in
   `verify.rs`.
2. Update the `verify_statement_with_warnings` flow: before resolving
   `kid`, call `resolve_rotated_key` to handle chained keys.
3. Add a test that creates a 2-deep rotation chain and verifies a
   statement signed with the terminal key.

## Open Questions

- Should rotation statements carry a timestamp indicating when the old key
  expires / the new key becomes active?
- Should we support multiple trust anchors (federation)?
- Should the TrustStore cache resolved chains, or resolve fresh each time?
