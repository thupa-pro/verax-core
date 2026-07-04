# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ |

## Reporting a Vulnerability

We take the security of verax Protocol seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@verax.xyz** (replace with actual address).

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## Disclosure Process

1. The vulnerability report is received and acknowledged.
2. A fix is developed and tested internally.
3. The fix is released in a new patch version.
4. The vulnerability is publicly disclosed after the fix is available.

## Previous Audits

A full IETF Forensic Protocol Audit was conducted for the v1.0.0 release. See [docs/security_audit.md](docs/security_audit.md) for details. All 5 identified Trap Doors (T1–T5) and 2 findings (F3, F5) have been patched.

## Security Properties

- **Non-malleability**: Deterministic CBOR encoding prevents signature malleability.
- **Post-quantum readiness**: Composite Ed25519 + ML-DSA-65 signatures provide PQ security.
- **Accountability**: CT anchoring binds statements to a public transparency log.
- **Revocation**: Statements can be revoked via log-based revocation.
- **Right to be forgotten**: PII shredding provides cryptographic erasure.
