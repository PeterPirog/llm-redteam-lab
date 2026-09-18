# ADR-079: The first HAL smoke has one fail-closed campaign orchestration boundary

- Status: Accepted
- Date: 2026-09-18

## Context

The repository now has independent trusted primitives for every critical boundary of the
first local HAL smoke:

- offline local-only admission and exact artifact qualification;
- stable exact Red artifact identity in attack-policy identity;
- stable exact Blue artifact/runtime identity in target identity;
- non-inference live Red artifact recheck;
- campaign-scoped isolated Blue Ollama infrastructure with exact runtime artifact proof;
- disposable per-trial OpenCode AGENT target leases;
- standard single-profile campaign execution with target isolation;
- immutable campaign execution provenance.

Leaving their ordering to manual operator steps would reintroduce the main class of errors
these components were built to prevent: evidence acquired too late, runtime state launched
before a drift check, direct use of a declared target, or incomplete cleanup hidden from the
operator.

## Decision

Add one `HalSmokeCampaignOrchestrator` for the bounded first smoke.

### Pre-runtime validation

Before any HAL runtime operation it requires:

- current `ModelsConfig` recomputes exactly the offline static smoke plan;
- local admission proof equals the offline composition;
- exact artifact-qualification proof equals the offline composition;
- qualification is bound to the same admission;
- campaign purpose is `DISCOVERY`;
- target is `CODING/AGENT`;
- Red policy is model-backed;
- at least one attack case exists;
- fixture-backed cases are excluded until compound fixture/target isolation exists.

### Runtime order

The runtime order is fixed:

1. live Red planner/mutator artifact recheck via non-inference `/api/tags`;
2. launch exact campaign-scoped Blue network + staged Ollama peer;
3. acquire hash-safe active Blue infrastructure provenance;
4. construct the per-trial OpenCode `DISPOSABLE_SANDBOX` provider;
5. verify the provider carries the exact Blue target measurement binding and declares a
   measurement-bound `CODING/AGENT` target;
6. construct the standard `CampaignLifecycleExecutor`;
7. bind four immutable provenance kinds into the campaign:
   - `local_model_admission_v1`;
   - `model_artifact_qualification_v1`;
   - `red_runtime_artifact_recheck_v1`;
   - `hal_blue_infrastructure_v1`;
8. run the bounded single-profile campaign; each statistical trial receives its own OpenCode
   container/workspace lease;
9. require all per-trial releases before campaign-scoped Blue teardown;
10. release the exact Blue peer and then its isolated network.

The declared/planning OpenCode target is never executed directly.

## Blue infrastructure provenance

The active Blue infrastructure supervisor exposes
`hal_blue_infrastructure_v1` only while the lease remains active. Its payload contains only
hash-safe identities/proofs:

- infrastructure lease hash;
- offline composition hash;
- stable target measurement binding;
- network profile and runtime network ID hashes;
- model-peer profile and container ID hashes;
- staged-store identity hash;
- exact runtime artifact proof hash;
- aggregate infrastructure proof hash.

No credential, raw environment, raw Docker inspect output or model prompt is persisted.

## Failure and teardown semantics

If campaign execution fails, orchestration attempts Blue infrastructure teardown before
re-raising the original failure. If cleanup also fails or remains incomplete, orchestration
raises a cleanup failure chained from the campaign failure.

If campaign execution has already reached a terminal status but campaign-scoped Blue teardown
is incomplete, orchestration does not rewrite immutable campaign history. Instead it fails the
outer smoke workflow and leaves the infrastructure lease active for explicit retry.

A successful `HalSmokeCampaignRunResult` is returned only after complete Blue
infrastructure teardown.

## Consequences

The first real HAL smoke has one auditable ordering contract rather than a runbook of
security-sensitive manual steps.

The orchestration layer itself remains testable in CI with fake HAL controls and scripted Red
models. Real HAL is still unnecessary until fresh evidence and the first actual smoke are
requested.
