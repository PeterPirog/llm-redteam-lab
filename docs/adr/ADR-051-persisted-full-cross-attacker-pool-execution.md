# ADR-051: Persisted Full-Cross Attacker-Pool Execution

**Status:** Accepted  
**Date:** 2026-09-12

## Context

ADR-049 defined multi-attacker discovery estimands and ADR-050 added explicit attacker
variant routing under one shared campaign budget. Those changes intentionally did not
make an attacker pool a campaign runner. Without an execution contract, an operator could
still route favorable cases to particular attackers after seeing outcomes, lose the exact
trial order after a crash, or accidentally compare attackers that inherited different Blue
state.

Recent adaptive-attack research reinforces that multi-round adaptation and attacker-model
diversity can materially increase vulnerability discovery. That motivates a fixed pool,
but it does not justify relabeling the pool result as ordinary ASR. NIST AI 800-3 likewise
motivates explicit estimands and disclosed assumptions instead of one ambiguous aggregate.

## Decision

Add `PersistedAttackerPoolRunner` as the execution primitive for a predeclared
`AttackerPoolContract`.

The runner MUST:

1. execute the deterministic rotating full-cross schedule from the contract;
2. give every declared attacker every declared `(case, replicate)` opportunity exactly
   once;
3. use the existing `RedAttackerPoolRuntime`, so attacker memories remain separate while
   all variants consume the same `BudgetLedger`;
4. bind the contract to the actual Blue target snapshot, exact case-content fingerprints,
   attacker planner/mutator fingerprints and campaign budget fingerprint before any target
   interaction;
5. persist each allocation before target execution;
6. persist the resulting ordinary conversation/execution through `ExperimentRepository`;
7. persist per-trial target-interaction, planner/mutator-call and output-token deltas after
   successful completion;
8. leave an interrupted trial visibly `allocated` rather than deleting evidence that a
   scheduled trial started;
9. use variant-specific conversation/attack IDs so different attackers cannot collide on
   the same case/replicate;
10. preserve the rule that one bounded conversation is one security trial.

The allocation table is an extension over existing attack/execution facts. It does not
store raw prompts and does not create a finding fingerprint. A successful execution is not
considered a distinct finding until reproduction/minimization/forensics produces an
evidence-backed finding identity.

## Isolation boundary

The first implementation supports only `SessionMode.REPLAY`.

A target-managed agent or fixture-backed AGENT can preserve application memory, tool state,
workspace changes or session state outside the transcript. Running attacker A and attacker
B sequentially against that shared state would make the comparison order-dependent and
could falsely attribute attacker effectiveness to residual Blue state.

Therefore `TARGET_MANAGED` and fixture-backed attacker-pool execution fail closed until a
per-trial target lease/reset abstraction can prove clean state for every assignment.

This restriction is deliberate measurement integrity, not a missing permission to be
silently bypassed.

## Failure semantics

The runner does not own campaign terminal status. The surrounding lifecycle remains
responsible for marking a campaign failed or inconclusive. The runner does preserve the
last predeclared allocation as `allocated` if target execution aborts, making partial
execution auditable.

A pool that cannot fit within the remaining `max_attacks` budget fails before the first
trial. Other shared model/token/wall-clock limits remain enforced by the normal campaign
ledger; attacker-controlled content cannot expand them.

## Measurement consequences

Ordinary per-attacker ASR/MCR/SCR continue to use bounded conversations as trials.
Portfolio discovery success remains the separate ADR-049 opportunity-level estimand.
Attacker overlap and marginal unique-finding yield remain Red discovery diagnostics, not
Blue security rates.

## Consequences

### Positive

- outcome-driven routing is structurally prevented;
- crashes leave a reconstructable schedule prefix;
- exact case content and attacker configuration are bound before execution;
- per-attacker resource efficiency can be reconstructed from persisted facts;
- the same evidence/judgment path remains authoritative for compromise labels;
- no live Judge verdict is exposed to Red.

### Trade-offs

- target-managed/AGENT pool execution is intentionally deferred;
- the optional attacker-pool table is created on demand until the runner is wired into the
  top-level campaign lifecycle;
- finding-diversity reports still require the existing reproduction/minimization/forensic
  stage before successful executions receive finding fingerprints.

## Next step

Wire this runner into `CampaignLifecycleExecutor` behind an explicit campaign-plan pool
mode and add a per-trial target lease/reset interface for isolated `TARGET_MANAGED` and
fixture/OpenCode execution. The lease must preserve stable Blue policy identity while
issuing distinct per-run isolation evidence.
