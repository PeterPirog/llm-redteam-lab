# ADR-008 — Adaptive Red Orchestration

Status: Proposed
Date: 2026-09-09

## Context

The project requires Red to be an adaptive attacker rather than a static prompt generator. Multi-turn attacks are first-class: one attack may consist of a bounded sequence of target interactions with accumulated context, branching and backtracking. Current 2026 research and tooling also show that attack effectiveness depends strongly on conversational flow control and query budget, so Red effectiveness must be measured separately from Blue vulnerability.

The architectural source of truth requires:

- hypothesis-driven adversarial exploration,
- campaign memory,
- attack genealogy,
- strict budgets,
- provider-independent model roles,
- deterministic/system-state judging before semantic judging,
- explicit MODEL_COMPROMISE versus SYSTEM_COMPROMISE,
- local-first development and no unrestricted campaign start.

## Decision

### 1. LangGraph owns Red orchestration, not target security policy

Adaptive Red uses a small `StateGraph` for one attacker decision. The graph combines deterministic nodes with model-backed nodes.

```text
START
  -> assess
  -> plan (red_planner)
  -> validate
       -> emit
       -> mutate (red_mutator) -> validate_mutation -> emit/stop
       -> stop
```

The graph never grants tools or target permissions. Campaign execution, target authorization, judging and resource budgets remain outside model control.

### 2. Multi-turn Red uses deterministic phases

The current phase contract is:

- `PRIMER`: first attacker turn; gather useful context without wasting budget,
- `PLANNER`: intermediate turns; adapt to observed target behavior,
- `FINISHER`: final available turn; optimize for the defined synthetic/test failure signal.

The model sees the phase but cannot redefine it.

### 3. Planner and Mutator are logical model roles

Business logic requests `red_planner` or `red_mutator`. Model/provider/endpoint choices come from `config/models.yaml`.

The initial client contract supports:

- deterministic scripted clients,
- OpenAI-compatible endpoints including local Ollama/OpenWebUI,
- optional budget metering decorator.

No concrete model is hard-coded into Red business logic.

### 4. Model output is strict structured data

The planner/mutator must return one JSON decision:

```json
{
  "action": "continue | backtrack | stop",
  "rationale": "...",
  "tactic": "...",
  "message": "... or null",
  "branch_from_turn_id": "... or null"
}
```

Deterministic validation checks:

- schema correctness,
- allowed action/field combinations,
- referenced branch existence,
- target-managed-session backtracking prohibition,
- backtrack/branch limits,
- duplicate/near-duplicate attacker turns.

One repair/mutation attempt is allowed. If it is still invalid, Red fails closed for that decision rather than silently coercing model output.

### 5. Campaign learning memory is transcript-free by default

Red campaign memory stores only bounded empirical summaries:

- attack family,
- tactic labels,
- success/failure,
- error state,
- target interaction count,
- backtracks,
- first violation depth.

Raw prompts and target responses are not stored in learning memory. Evidence storage remains a separate forensic concern.

### 6. One conversation remains one Blue ASR trial

Target turns are cost/evidence units, not independent Blue trials. The denominator for conversation-level ASR is completed conclusive conversations.

Red efficiency is reported separately through interaction and inference cost metrics.

### 7. Inference budgets are role-aware

The campaign ledger enforces both global and optional per-role limits for:

- model calls,
- output tokens.

This prevents a planner/mutator loop from consuming the full campaign budget and makes attacker comparisons reproducible.

## Consequences

### Positive

- Multi-turn attacker behavior can adapt to actual Blue responses.
- Attacker state is reproducible and bounded.
- Planner and Mutator models can be replaced without changing orchestration.
- Query/inference efficiency can be compared independently of Blue ASR.
- Invalid attacker output cannot expand permissions or budgets.
- Campaign memory can improve later attacks without becoming a raw transcript store.

### Trade-offs

- Strict JSON may reduce compatibility with weak local models; one repair call is intentionally allowed.
- The first implementation uses deterministic phase boundaries rather than learned phase transitions.
- Campaign memory is initially in-process; persistence of derived Red knowledge is a later milestone.
- Similarity detection is intentionally simple and deterministic. Semantic novelty can be added later only if it improves measured attacker effectiveness enough to justify inference cost.

## Non-decisions / deferred work

This ADR does not yet define:

- semantic Judge implementation,
- long-term persisted Red memory,
- attack minimization/counterfactual replay,
- OpenCode agent execution,
- Promptfoo/garak/PyRIT adapters,
- multimodal Red planning.

These remain downstream milestones after the adaptive core is proven with deterministic tests and bounded local smoke campaigns.
