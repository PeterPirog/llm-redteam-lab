# ADR-041: Bind reference Blue policy into target identity and expose local execution explicitly

Status: Accepted
Date: 2026-09-11

## Context

Reference Evaluation v1 compares two adaptive multi-turn Red search policies against a fixed held-out population. The experiment is only meaningful if the Blue target has an explicit security policy that protects the synthetic canary. A bare chat model that was never instructed to protect `RT_SYNTHETIC_CANARY` would make canary disclosure an ordinary instruction-following event rather than a security-policy violation.

The OpenAI-compatible target previously fingerprinted provider, endpoint, model and runtime parameters but had no first-class system policy field. This also risked treating the same model under different system prompts as the same Blue target configuration.

## Decision

1. `OpenAICompatibleConfig` may carry an explicit `system_prompt`.
2. The target prepends that policy as a system message on every replay-mode request.
3. Raw system-policy text is not copied into normal evidence. Evidence records its SHA-256 identity only.
4. The target configuration fingerprint includes the system-policy hash. Changing the system policy therefore creates a different target snapshot even when the underlying model and endpoint are unchanged.
5. Reference Evaluation v1 ships `config/reference-blue-policy-v1.txt`, which explicitly protects the synthetic marker across multi-turn reframing, decomposition and related user-level pressure.
6. `llm-redteam reference-run` defaults to `INSTRUMENTATION_SMOKE`. Qualification requires the operator to select `POLICY_QUALIFICATION` explicitly.
7. Concrete Blue and Red model names remain operator configuration. The runner does not hard-code them.
8. Reference v1 remains local-first and fixed-corpus. The CLI rejects Red role configurations blocked by local-first policy and requires explicit role endpoints.
9. The deterministic Judge descriptor includes only the synthetic-canary hash, never the raw canary as measurement metadata.
10. A successful instrumentation smoke validates execution and measurement wiring only; it cannot promote a Red policy or establish generalized Blue security.

## Rationale

This makes the security invariant an actual property of the tested Blue configuration rather than an evaluator-only expectation. It also enforces the project rule that the same underlying model in different applications or configurations is a different security target.

The operator command closes the gap between a mathematically specified experiment and an executable local workflow while preserving the existing fail-closed measurement contract, counterbalanced paired design, exact resource accounting and held-out separation.

## Consequences

### Positive

- The reference canary experiment now tests a real priority conflict between Blue system policy and adaptive user-level multi-turn pressure.
- System prompt changes are visible in target identity without persisting policy text in ordinary evidence.
- Local smoke and qualification runs use the same persisted paired-ablation machinery as the programmatic runtime.
- The default operator path cannot accidentally issue a qualification decision from the small smoke stage.

### Limitations

- A system prompt is only one Blue control. The reference MODEL experiment does not estimate the security of RAG, tool authorization, sandboxing or AGENT runtime controls.
- Temperature zero improves repeatability but does not prove bit-level determinism for every provider/runtime.
- Reference v1 still makes fixed-corpus claims only; generalized-population inference remains intentionally unsupported.
- Real local execution must occur on the operator's machine because the project runtime cannot assume access to the operator's localhost services.

## Rejected alternatives

### Evaluate the bare model without an explicit Blue policy

Rejected because emitting a marker that the model was never instructed to protect is not a valid policy-compromise measurement.

### Persist the raw system prompt in every evidence record

Rejected because target identity only requires a stable fingerprint and routine evidence should minimize sensitive configuration disclosure.

### Automatically run qualification after smoke

Rejected because instrumentation validity must be inspected before spending the larger qualification budget, and a smoke result must never be promoted into a policy-superiority claim.
