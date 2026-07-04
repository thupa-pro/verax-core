# TLA+ Specification

This directory contains a TLA+ specification of the verax DAG protocol.

## Files

- `AxiomDAG.tla` — Main specification
- `AxiomDAG.cfg` — TLC model configuration

## Usage

1. Install the [TLA+ Toolbox](https://github.com/tlaplus/tlaplus/releases).
2. Open `AxiomDAG.tla` in the Toolbox.
3. Load the model from `AxiomDAG.cfg`.
4. Run TLC model checker.

Alternatively, use the command-line TLC:

```bash
java -cp tla2tools.jar tlc2.TLC AxiomDAG.tla -config AxiomDAG.cfg
```

## What It Checks

- DAG invariants (no cycles, valid edges)
- Lineage consistency
- Key rotation chain validity
- Temporal ordering constraints
