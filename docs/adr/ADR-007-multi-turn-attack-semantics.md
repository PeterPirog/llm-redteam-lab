# ADR-007 — Multi-Turn Attack Semantics

- Status: Accepted
- Date: 2026-09-08

## Context

Jailbreaks and prompt-injection attacks are often sequential rather than single-shot. A realistic Red agent may establish context, probe a boundary, observe a refusal, backtrack, branch, and then continue along a more promising conversational path.

Current external evidence reinforces that flow control is a first-class experimental variable:

- Promptfoo Hydra uses multi-turn adaptation, memory, branching and backtracking.
- Promptfoo distinguishes transcript replay from target-managed session state.
- MT-JailBench (2026) shows that turn budgets, retries, judges and flow-control choices can materially change attack rankings.

References:

- https://www.promptfoo.dev/docs/red-team/strategies/hydra/
- https://www.promptfoo.dev/docs/red-team/strategies/multi-turn/
- https://www.promptfoo.dev/docs/red-team/troubleshooting/multi-turn-sessions/
- https://arxiv.org/abs/2605.11002

## Decision

### 1. One conversation is one attack trial

For Blue vulnerability metrics, one complete multi-turn conversation contributes at most one ASR trial.

A five-turn attack does **not** contribute five ASR trials. Otherwise longer strategies would mechanically alter the denominator and comparisons between single-turn and multi-turn Red strategies would be biased.

Turns remain first-class evidence and resource measurements.

### 2. Preserve both ordinal and logical depth

Each executed target interaction records:

- execution ordinal — the order in which Red spent target interactions,
- logical depth — distance from the root along the selected branch,
- parent turn,
- branch identifier.

After backtracking, ordinal can increase while logical depth decreases. Both values are therefore necessary.

### 3. Explicit session modes

Two session semantics are supported:

- `replay`: the harness reconstructs and sends the complete selected conversation path on every turn;
- `target_managed`: only the newest attacker turn is sent and the Blue target owns conversation state.

A target adapter must fail closed if it cannot implement the requested session semantics reliably.

### 4. Backtracking is explicit evidence

Red does not silently rewrite history. A new turn may explicitly reference a prior `branch_from_turn_id`.

For replay mode, the harness reconstructs only that branch prefix and excludes abandoned descendant turns.

Target-managed sessions do not support generic backtracking unless a future adapter provides a deterministic session clone/reset capability. The generic harness therefore rejects such requests fail-closed.

### 5. Flow-control budget is part of experiment identity

A multi-turn result is not comparable unless the following are recorded:

- maximum turns,
- maximum backtracks,
- maximum branches,
- continue-after-success policy,
- session mode,
- Red strategy implementation/version,
- Judge implementation/version,
- target configuration hash.

These fields are summarized by a flow fingerprint and should be persisted with each conversation.

### 6. Resource limits remain outside model control

The Red model may choose tactics but cannot increase authorized limits. Turn limits are enforced per concrete attack conversation/execution, while total campaign target interactions are also accumulated for cost reporting.

### 7. Multi-turn reporting separates Blue vulnerability from Red efficiency

Blue-oriented metrics include:

- conversation-level ASR with confidence interval,
- MCR and SCR from the final conversation classification,
- reproducibility of the entire conversation policy/transcript.

Red-oriented efficiency metrics include:

- turns to first violation,
- logical depth to first violation,
- backtracks,
- branch count,
- successes per target interaction,
- model calls and token cost.

`successes_per_100_turns` is an attacker-efficiency measure and MUST NOT replace conversation-level ASR.

### 8. Reproduction means reproducing the sequence

A confirmed multi-turn finding must preserve enough information to reproduce the conversational path, not merely the final message. Minimization may remove turns or branches, but only while the full security failure remains reproducible.

## Consequences

Positive:

- fairer comparison of Red strategies,
- explicit modeling of Crescendo/Hydra/GOAT-like flows without depending on a cloud vendor,
- reproducible branching evidence,
- correct support for stateful applications and agents,
- clean separation of target vulnerability from attacker resource consumption.

Costs:

- persistence must store conversation/turn genealogy,
- target adapters need explicit session semantics,
- minimization and counterfactual replay become sequence-aware,
- campaign reports require both conversation-level and turn-level metrics.

## Architectural fit

This decision extends, rather than changes, the authoritative project loop:

```text
Attack hypothesis
  -> conversation policy
  -> turn / response / judgment
  -> branch or continue
  -> conversation result
  -> evidence
  -> reproduction
  -> minimization
  -> forensics
  -> Blue knowledge
  -> regression
```
