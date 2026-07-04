# Lean 4 Proofs

This directory contains Lean 4 formal proofs for the Axiom protocol.

## Files

- `AxiomProofs.lean` — Entry point with theorem statements
- `lakefile.lean` — Lake build configuration

## Usage

1. Install [Lean 4](https://leanprover.github.io/lean4/).
2. Build:

```bash
lake build
```

3. The proofs verify key invariants of the protocol.

## Proof Coverage

See `AxiomProofs.lean` for the full list of theorems.
