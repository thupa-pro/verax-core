import Lake
open Lake DSL

package axiom_proofs where
  -- Add package configuration options here

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "master"

@[default_target]
lean_lib AxiomProofs where
  -- add library configuration options here
