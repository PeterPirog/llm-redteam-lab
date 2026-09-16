# ADR-073: Require exact local Blue artifact admission for Reference Evaluation

- Status: Proposed
- Date: 2026-09-13
- Depends on: ADR-072 artifact-qualified Blue target identity

## Context

Reference Evaluation v1 is intended to produce reproducible fixed-corpus evidence about a
specific local Blue security target while comparing Red search policies under controlled
conditions.

A configured model name is not sufficient measurement identity. Local runtimes commonly use
mutable tags such as `latest`; the same application configuration and model tag can therefore
resolve to different model weights at different times. If Reference Evaluation admitted such
a target using only the tag, two nominally identical runs could measure different Blue models.

The project already treats the same underlying model in different applications or
configurations as different security targets. The inverse is also required for reproducible
measurement: the same application/configuration using different exact model weights must be a
different target snapshot.

ADR-072 introduces `ArtifactQualifiedTarget`, which composes the existing application/runtime
`TargetIdentity` with an independently verified `ModelArtifactIdentity` and protects the
admitted base target identity against runtime drift before every target execution.

## Decision

Reference Evaluation v1 SHALL admit Blue only through an artifact-qualified target boundary.

The admission proof SHALL bind:

- reference experiment ID;
- qualified target ID and configuration hash;
- provider and configured model ID;
- exact model artifact digest;
- provider-neutral artifact identity hash;
- target/artifact binding hash;
- local-artifact classification and explicit local requirement.

The proof has its own canonical `admission_sha256` so it can later be persisted or embedded in
an operator qualification report without storing model bytes.

Reference Evaluation v1 SHALL require `require_local=true` and `local_artifact=true`. The
general `ArtifactQualifiedTarget` abstraction may support explicitly allowed remote artifacts,
but this first reference protocol intentionally does not. A future protocol version may define
a cloud/remote measurement contract separately.

## Admission ordering

The exact Blue admission SHALL be built before the existing paired reference runner is called.
Failure to establish exact target identity therefore occurs before any Blue target interaction
or Red model call initiated by the reference runner.

The existing paired runner remains the sole implementation of:

- baseline/treatment counterbalancing;
- per-arm budgets;
- bounded-conversation trial execution;
- paired statistical units;
- measurement snapshot persistence;
- paired estimators and policy qualification.

The Blue admission adapter delegates to that runner rather than copying its scheduler or
statistics. This prevents measurement drift.

## Runtime drift

`ArtifactQualifiedTarget` already compares the current base target identity with the identity
captured at artifact admission immediately before each `execute()` call. Reference admission
also verifies that the binding still matches the qualified identity before delegating to the
paired runner.

After the paired runner returns, the wrapper verifies that the runner preflight used the same
qualified target configuration hash. A mismatch invalidates the run result.

These checks protect application/configuration identity. Strong byte-level proof that the
runtime actually loaded the admitted weights remains a separate runtime-attestation concern
handled by the verified model-peer path.

## Provider boundary

This decision is provider-neutral. Reference admission consumes the trusted
`TargetModelArtifactBinding`; it does not inspect Ollama-specific response fields and performs
no network request.

For the initial local workflow, Ollama-specific manifest verification remains at the edge:

1. predeclared artifact contract;
2. saved or observed `/api/tags` inventory;
3. `OllamaArtifactContract` verification;
4. provider-neutral `ModelArtifactIdentity`;
5. `ArtifactQualifiedTarget`;
6. `ReferenceBlueArtifactAdmission`;
7. paired Reference Evaluation.

Future providers can supply equivalent verified `ModelArtifactIdentity` objects without
changing Reference Evaluation business logic.

## Security and measurement consequences

This admission step does not:

- grant target permissions;
- enable network access;
- execute Docker commands;
- invoke a model;
- alter `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE` semantics;
- change one bounded conversation as the statistical trial;
- change fixed-corpus inference scope;
- expose Judge verdicts to Red;
- modify counterbalancing or paired estimators.

It only strengthens the identity of the Blue target being measured.

## Testing

Deterministic tests SHALL prove at minimum:

- exact local artifact digest and binding are present in admission;
- an ordinary unqualified target is rejected before runner delegation;
- a remote artifact remains rejected even when the generic target wrapper explicitly permits
  it;
- target provider/class/mode must match the reference specification;
- changing weights under the same mutable model tag changes admission identity;
- delegation preserves the already-qualified target object;
- post-run target-configuration identity mismatch is rejected.

No model inference, Ollama daemon, Docker daemon, GPU, external network, or cloud API is
required for these tests.

## Follow-up

After this boundary is validated, the next local-readiness milestone is an offline
qualification report that consumes predeclared artifact contracts and a saved local inventory,
producing a hash-bound report before any inference. RED/Judge role-artifact identities from
ADR-069 can be composed into the same report once their stacked changes are validated.
