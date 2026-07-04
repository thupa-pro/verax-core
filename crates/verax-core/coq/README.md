# Coq Proofs

This directory contains Coq formal proofs for the verax protocol core invariants.

## Files

- `VeraxCore.v` — Main proof file with theorems about:
  - CBOR determinism (encode is a function)
  - CLAIM lemma (decode(encode(p)) = Some(p))
  - DAG acyclicity (lineage hashes form a forest)
  - Predicate safety (REVOKES issuer matches target)

## Usage

1. Install [Coq](https://coq.inria.fr/) (8.18+).
2. Compile:

```bash
coqc VeraxCore.v
```

## Proof Strategy

The proofs assume functional correctness of the Rust implementation via axioms, and verify the higher-level protocol invariants. See `VeraxCore.v` header for details.
