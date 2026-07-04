/-
# Verax Protocol v3.0 — Formal Verification Entry Point

This file imports and checks all formal proofs for the Verax Protocol.
Run with: `lake build` to verify all theorems compile with no `sorry` axioms.

## Proven Theorems

### Whitepaper I1: Serialization Injectivity
  `theorem encode_injective (a b : StrictCBOR) : encode a = encode b → a = b`
    - Defined in: `VeraxProofs/SerializationInjectivity.lean`
  - Status: Proof skeleton with key lemmas. The structural case analysis is complete;
    the remaining `sorry` blocks are the byte-level injectivity lemmas for
    `encodeUIntHead`, `encodeBstr32`, and `encodeSortedMap`, which require
    additional lemmas about `Bytes32` and sorted list equality.
  - Invariant: `serialize(a) = serialize(b) ⇒ a = b`

### Whitepaper Ixx: Predicate Algebra Completeness
  `theorem predicate_completeness (op : ProvenanceOp) : ∃ (comp : Composition), evaluateComposition comp op = true`
    - Defined in: `VeraxProofs/PredicateCompleteness.lean`
  - Status: Complete. All 5 provenance operations (Transform, Version, Delegate,
    Merge, Revoke) have explicit composition witnesses.
  - Invariant: Every provenance operation maps to a composition of core predicates.
-/

import VeraxProofs.SerializationInjectivity
import VeraxProofs.PredicateCompleteness
