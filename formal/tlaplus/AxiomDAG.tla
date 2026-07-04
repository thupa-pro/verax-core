-------------------------- MODULE AxiomDAG --------------------------
(*
 * Axiom Protocol v3.0 — Provenance DAG State Machine Model
 *
 * Models the Axiom provenance graph as a labeled transition system.
 * Invariants from the v3.0 Whitepaper:
 *   I1 (Determinism/Injectivity): serialized form is unique per payload
 *   I6 (Acyclicity): DERIVES and SUPERSEDES edges form no cycles
 *   I9 (Monotonicity): lineage chains have non-decreasing timestamps
 *   I11 (Revocation Authority): only the original issuer may revoke
 *
 * Each statement is a 5-tuple:
 *   <<subject, predicate, object, issuer, timestamp>>
 *
 * The Derives and Supersedes predicates (2, 3) form the DAG edges.
 * Revokes (predicate 4) has special issuer-matching rules.
 *)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    MaxStatements,          \* Maximum number of statements in the model
    MaxIssuers,             \* Maximum number of issuers
    MaxTimestamp,           \* Maximum timestamp value
    PredicateAttests,       \* = 0
    PredicateAuthors,       \* = 1
    PredicateDerivedFrom,   \* = 2
    PredicateSupersedes,    \* = 3
    PredicateRevokes,       \* = 4
    PredicateEndorses,      \* = 5
    PredicateAppends,       \* = 6
    PredicateCompliesWith   \* = 7

ASSUME
    /\ PredicateAttests = 0
    /\ PredicateAuthors = 1
    /\ PredicateDerivedFrom = 2
    /\ PredicateSupersedes = 3
    /\ PredicateRevokes = 4
    /\ PredicateEndorses = 5
    /\ PredicateAppends = 6
    /\ PredicateCompliesWith = 7

\* Type definitions
Subject == [1 .. MaxStatements]          \* Abstract subject identifiers
Object == Subject \cup {0}                \* 0 = no object
Issuer == [1 .. MaxIssuers]
Timestamp == 0 .. MaxTimestamp

Statement ==
    [subject   : Subject,
     predicate : 0 .. 7,
     object    : Object,
     issuer    : Issuer,
     timestamp : Timestamp]

StatementHash == 1 .. (2 * MaxStatements)  \* Abstract hash identifiers

(* --algorithm AxiomDAG

variables
    graph \in SUBSET Statement,                    \* Set of all statements
    revocations \in SUBSET StatementHash,           \* Set of revoked statement hashes
    shash \in [Statement -> StatementHash],         \* Hash mapping (injective)
    max_time \in [Issuer -> Timestamp],             \* Max timestamp per issuer
    key_chain \in [Issuer -> Issuer \cup {0}];      \* Key rotation mapping (0 = no successor)

define
    \* Edge relation: statements connected by DERIVES (predicate 2) or SUPERSEDES (predicate 3)
    Edge(a, b) ==
        /\ a \in graph /\ b \in graph
        /\ (a.predicate = PredicateDerivedFrom \/ a.predicate = PredicateSupersedes)
        /\ a.object = shash[b]

    \* Transitive closure of Edge relation
    TC ==
        [T \in SUBSET Statement |->
            LET EdgeSet == {<<a, b>> \in T \times T : Edge(a, b)}
            IN closure(EdgeSet)]

    closure(pairs) ==
        LET
            R == pairs;
            TransitiveClosure ==
                UNION { R^n : n \in 1 .. MaxStatements }
        IN TransitiveClosure

    \* --- Invariants ---

    \* I6: Acyclicity — no self-loop in the transitive closure
    InvAcyclic ==
        \A n \in graph :
            <<n, n>> \notin TC[graph]

    \* I11: Revocation Integrity — only the original issuer can revoke
    InvRevocationIntegrity ==
        \A r \in revocations :
            LET target == CHOOSE s \in graph : shash[s] = r
            IN target.issuer = (CHOOSE s \in graph : s.predicate = PredicateRevokes /\ s.object = r).issuer
        \* Simplified: a statement's issuer must match revoker's issuer

    \* I9: Temporal Monotonicity — timestamps are non-decreasing along lineage chains
    InvTemporalMonotonicity ==
        \A a, b \in graph :
            Edge(a, b) => a.timestamp >= b.timestamp

    \* Safety: graph hashes are injective
    InvHashInjective ==
        \A a, b \in graph :
            a # b => shash[a] # shash[b]
end define;

\* Add a new statement to the graph
macro AddStatement(s, p, o, i, t)
begin
    \* Check timestamp monotonicity for issuer
    assert t >= max_time[i];
    
    \* For DERIVES/SUPERSESDES, verify object exists in graph
    if (p = PredicateDerivedFrom \/ p = PredicateSupersedes) then
        assert \E existing \in graph : shash[existing] = o;
    end if;
    
    \* For REVOKES, verify issuer matches target's issuer
    if p = PredicateRevokes then
        assert \E target \in graph :
            shash[target] = o /\ target.issuer = i;
    end if;
    
    \* Create new statement and add to graph
    with new_hash \in StatementHash \ {shash[s2] : s2 \in graph} do
        graph := graph \cup {[subject |-> s, predicate |-> p, object |-> o,
                              issuer |-> i, timestamp |-> t]};
        shash[[subject |-> s, predicate |-> p, object |-> o,
               issuer |-> i, timestamp |-> t]] := new_hash;
        max_time[i] := t;
    end with;
end macro;

\* Revoke a statement by hash
macro RevokeStatement(target_hash, issuer)
begin
    \* Verify issuer matches target's issuer
    assert \E target \in graph :
        shash[target] = target_hash /\ target.issuer = issuer;
    
    revocations := revocations \cup {target_hash};
end macro;

\* Rotate a key (update key chain mapping)
macro RotateKey(old_issuer, new_issuer)
begin
    key_chain[old_issuer] := new_issuer;
end macro;

\* Initial state
begin
    graph := {};
    revocations := {};
    shash := [s \in Statement |-> 0];  \* empty mapping
    max_time := [i \in Issuer |-> 0];
    key_chain := [i \in Issuer |-> 0];
end begin;

\* State transitions
fair process (StateMachine = 1)
variables
    next_subject = 1;
    next_hash = 1;
begin
Loop:
    while next_subject <= MaxStatements do
        \* Choose an action
        with
            action \in {"add", "revoke", "rotate"}
        do
            if action = "add" then
                \* Pick a random statement
                with
                    p \in 0..7,
                    o \in Object,
                    i \in Issuer,
                    t \in Timestamp
                do
                    AddStatement(next_subject, p, o, i, t);
                    next_subject := next_subject + 1;
                end with;
            elsif action = "revoke" /\ graph # {} then
                with
                    target_hash \in {shash[s] : s \in graph},
                    i \in Issuer
                do
                    RevokeStatement(target_hash, i);
                end with;
            else \* rotate
                with
                    old_i \in Issuer,
                    new_i \in Issuer
                do
                    RotateKey(old_i, new_i);
                end with;
            end if;
        end with;
        next_hash := next_hash + 1;
    end while;
end process;
end algorithm; *)

\* ================================================================
\* Model checking configuration is in AxiomDAG.cfg
\* ================================================================
============================================================
