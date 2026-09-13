# ADR-072: Bind Blue target identity to the exact model artifact

- Status: Proposed
- Date: 2026-09-13

## Context

The laboratory treats a security target as the complete evaluated system, not merely a model
name. The same underlying model in a direct MODEL endpoint, a guarded PIPELINE and a tool-using
AGENT is therefore intentionally three different targets.

The converse problem also matters: the *same configured target* can silently change when a
mutable model tag such as `latest` resolves to different weights. `TargetIdentity` already has
an optional `model_digest`, but the historical `OpenAICompatibleTarget.configuration_hash`
is based on application/runtime configuration and the human-readable model ID. The repository
snapshot ID is derived from `target.id + configuration_hash`.

Therefore recording a digest as metadata without composing it into `configuration_hash` is
insufficient: two different model artifacts could otherwise map to the same target snapshot.

## Decision

Add a provider-neutral `TargetModelArtifactBinding` and `ArtifactQualifiedTarget` wrapper.

The binding requires exact agreement between:

- Blue target provider;
- Blue target model ID;
- independently verified `ModelArtifactIdentity.provider_id`;
- independently verified `ModelArtifactIdentity.model_id`;
- any pre-existing target `model_digest`.

For local qualification, `require_local=True` is the default. A remote artifact is rejected
unless a caller explicitly opts into a non-local experiment.

The qualified target identity sets:

```text
model_digest = exact artifact SHA-256 digest
configuration_hash = H(
    base target configuration hash,
    model artifact identity SHA,
    target/artifact binding SHA
)
```

As a result, changing weights under the same model tag changes both the target configuration
hash and `ExperimentRepository.target_snapshot_id()`.

## Separation from application identity

The base target's configuration hash remains the identity of the application/runtime policy:
endpoint, target mode, system prompt, tool/runtime settings and other adapter-specific
configuration.

The artifact-qualified hash composes rather than replaces that identity. Consequently:

```text
same weights + different application/runtime policy -> different Blue target
same application/runtime policy + different weights -> different Blue target
```

Both are required for meaningful security regression measurement.

## Provider independence

The wrapper consumes a verified `ModelArtifactIdentity`; it does not query Ollama, Docker or a
provider API. Provider-specific inventory verification remains at the edge. For the planned
local Ollama path:

```text
predeclared manifest digest
        ↓
OllamaArtifactContract / artifact registry
        ↓
ModelArtifactIdentity
        ↓
ArtifactQualifiedTarget
        ↓
exact TargetIdentity / target snapshot
```

A future provider can supply the same provider-neutral artifact object without changing target
business logic.

## Runtime drift / TOCTOU

Admission-time identity is not enough. The wrapped adapter might expose a different target
configuration after qualification due to configuration mutation, application restart or other
runtime drift.

`ArtifactQualifiedTarget.execute()` therefore compares the current base `TargetIdentity` with
the identity observed at artifact admission before every target call. Any difference fails
closed before delegation.

This check does not prove that an external model service kept identical bytes in memory; that
stronger claim is provided by the isolated model-peer/artifact-bundle/runtime-attestation path.
The target wrapper provides the provider-neutral measurement-identity boundary.

## Capabilities and authority

The wrapper delegates `TargetRequest` unchanged and does not add target capabilities,
permissions, tools, network access or filesystem access. Artifact qualification is identity,
not authorization.

## Relationship to MODEL_COMPROMISE and SYSTEM_COMPROMISE

This decision changes neither compromise semantics nor judgment:

- `MODEL_COMPROMISE` remains a behavioral violation by the model;
- `SYSTEM_COMPROMISE` still requires independently verified unauthorized system effect;
- sandbox containment can prevent system compromise after model compromise.

Exact Blue artifact identity only ensures the experiment can identify which model weights were
part of the evaluated security target.

## Reference Evaluation consequence

Reference Evaluation v1 must eventually require both:

1. artifact-qualified RED measurement roles (ADR-069/071); and
2. an artifact-qualified Blue target snapshot.

Otherwise a paired Red policy comparison could be reproducible on the attacker side while the
Blue weights changed under a mutable target tag.

## Tests

Deterministic tests require:

- different digests under the same target/model name produce different configuration hashes
  and target snapshot IDs;
- the same base target + same artifact is stable;
- provider/model/digest/locality mismatch fails closed;
- the wrapper delegates requests unchanged when identity is stable;
- post-admission base-target identity drift is rejected before execution.

No model inference, provider network access, Docker daemon or GPU is required.
