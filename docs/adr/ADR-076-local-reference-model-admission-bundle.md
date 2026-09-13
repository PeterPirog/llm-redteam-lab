# ADR-076: Prepare one exact local Reference model admission bundle before inference

- Status: Proposed
- Date: 2026-09-13
- Related: ADR-068, ADR-072, ADR-073, ADR-075

## Context

The local-first workflow now has an offline Ollama artifact qualification report. That report
proves that a saved `/api/tags` observation matched predeclared local artifact digests, but it
does not by itself decide which artifacts will be used as Red or Blue in the first Reference
Evaluation run.

Runtime role labels stored in an artifact declaration are operator metadata only. They must not
become an authorization mechanism. The actual Red assignment must come from `ModelsConfig`,
while Blue remains campaign-selected.

The first local Reference Evaluation should also avoid unnecessary inference. Reference
Evaluation v1 already requires the deterministic synthetic-canary Judge, so no semantic Judge
model is needed for the initial instrumentation smoke.

## Decision

Add an offline `LocalReferenceAdmissionBundle` that binds:

- the exact offline Ollama qualification report identity;
- the exact saved inventory identity;
- the verified artifact-set identity;
- the Reference-relevant `ModelsConfig` identity;
- default `red_planner` configuration and exact artifact;
- default `red_mutator` configuration and exact artifact;
- one campaign-selected Blue model and exact artifact.

The bundle is prepared before any provider call or model inference.

## Red role authority

Red role assignment SHALL be resolved from `ModelsConfig`, not from artifact declaration role
labels.

For Reference Evaluation v1 the admission path requires:

- `local_first=true`;
- `allow_cloud_fallback=false`;
- attacker pool disabled;
- campaign-selected Blue;
- `red_planner` and `red_mutator` classified local;
- provider `ollama` for those roles;
- no role fallback chain;
- a direct loopback HTTP(S) endpoint;
- the configured provider/model pair present in the verified artifact report.

This makes artifact metadata incapable of expanding its own runtime role or permissions.

## Blue selection

Blue remains selected by the campaign/operator. The selected provider/model pair must exist in
the same verified local artifact report. The bundle records the exact artifact digest and
provider-neutral artifact identity hash.

The bundle deliberately does not require Blue to be a different model family from Red. Model
family separation is a useful experiment-design recommendation, not a universal security
invariant and therefore must not be hard-coded in business logic.

## Persisted report loading

The JSON emitted by `qualify-ollama-inventory` stores `artifact_set_sha256` and
`report_sha256`. A loader SHALL recompute both values and reject mismatches. It SHALL also verify
that every artifact observation references the report's inventory hash and provider/model
identity.

These self-hashes provide deterministic content identity, not authentication. A party able to
rewrite a report can also recompute its self-hashes. Therefore the loader accepts an optional
independently pinned `expected_report_sha256`; later campaign preparation SHOULD supply that hash
when an external trusted record is available.

## Bundle identity

`bundle_sha256` hashes the normalized bundle. It changes when any admitted exact artifact,
Reference-relevant Red role configuration, saved inventory identity or qualification-report
identity changes.

A mutable tag such as `blue:latest` therefore cannot retain the same bundle identity after its
verified artifact changes.

## Reference Evaluation v1 Judge

This bundle contains only model-backed Red roles and Blue. The v1 Reference experiment uses the
existing deterministic canary Judge. This is intentional:

- deterministic verification has higher evaluation priority than semantic Judge inference;
- it avoids unnecessary local model calls during the first smoke;
- it avoids introducing Judge-model variation into the paired Red-policy experiment.

A later protocol may add artifact-qualified semantic or multimodal Judge roles when the security
objective cannot be verified deterministically.

## Security consequences

Preparing the bundle:

- makes no Ollama/OpenWebUI request;
- performs no model inference;
- starts no Docker container;
- grants no network, filesystem, tool or agent permission;
- does not claim that the verified weights are currently loaded by a runtime;
- does not replace later Docker/model-peer attestation.

It is a control-plane admission artifact only.

## Testing

Deterministic tests cover:

- persisted report hash validation;
- optional independently pinned report hash;
- report observation/inventory consistency;
- role assignment from `ModelsConfig` rather than metadata labels;
- exact Red and Blue artifact binding;
- mutable Blue tag artifact drift;
- Red runtime-configuration drift;
- non-loopback endpoint rejection;
- role fallback rejection;
- missing selected Blue artifact rejection.

No local model, Ollama daemon, Docker daemon, GPU, external network or cloud API is required.

## Follow-up

The next operator-facing step is a thin offline CLI that loads:

1. `models.yaml`;
2. `qualification-report.json`;
3. the selected Blue model;

and emits the admission bundle plus `bundle_sha256`. It must remain separate from
`reference-run` until the exact Red/Blue runner-admission stacks have real test execution.
