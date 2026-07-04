# Coq Proofs

This directory contains Coq formal proofs for the Axiom protocol core invariants.

## Files

- `AxiomCore.v` — Main proof file with theorems about:
  - CBOR determinism (encode is a function)
  - CLAIM lemma (decode(encode(p)) = Some(p))
  - DAG acyclicity (lineage hashes form a forest)
  - Predicate safety (REVOKES issuer matches target)

## Usage

1. Install [Coq](https://coq.inria.fr/) (8.18+).
2. Compile:

```bash
coqc AxiomCore.v
```

## Proof Strategy

The proofs assume functional correctness of the Rust implementation via axioms, and verify the higher-level protocol invariants. See `AxiomCore.v` header for details.
