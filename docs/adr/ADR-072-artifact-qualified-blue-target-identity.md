# ADR-072: Bind Blue target identity to the exact model artifact

- Status: Proposed
- Date: 2026-09-13

## Context

The laboratory treats a security target as the complete evaluated system, not merely a model
name. The same underlying model in a direct MODEL endpoint, a guarded PIPELINE and a tool-using
AGENT is therefore intentionally three different targets.

The converse problem also matters: the *same configured target* can silently change when a
mutable model tag such as `latest` resolves to different weights. `TargetIdentity` already has
an optional `model_digest`, but historical target configuration hashes are primarily based on
application/runtime configuration and human-readable model IDs. Recording a digest as metadata
without composing it into `configuration_hash` is insufficient.

There is an additional identity distinction for application-backed targets. A direct MODEL can
have:

```text
TargetIdentity.provider = ollama
model artifact provider = ollama
```

while an OpenCode AGENT correctly has:

```text
TargetIdentity.provider = opencode
underlying model provider = ollama
```

Treating the application provider as though it were the artifact provider would make exact
model binding work for MODEL targets but fail for PIPELINE/AGENT targets.

## Decision

Add three provider-neutral primitives:

- `TargetModelReference` — the trusted reference from the evaluated application to the
  underlying model provider/model ID;
- `TargetModelArtifactBinding` — the immutable composition of target configuration, model
  reference and independently verified model artifact;
- `ArtifactQualifiedTarget` — a protocol-preserving runtime wrapper with TOCTOU checks.

For direct `MODEL` targets, the model reference may be derived from `TargetIdentity.provider`
and `TargetIdentity.model`. For `PIPELINE` and `AGENT`, an explicit model reference is required
from trusted application configuration. No heuristic parsing of a display string is accepted.

The binding requires exact agreement between:

- declared underlying model provider/model ID;
- independently verified `ModelArtifactIdentity.provider_id/model_id`;
- any pre-existing target `model_digest`;
- local/remote policy.

Application provider remains independently bound through the base target configuration. Thus
`provider=opencode` and `model provider=ollama` are valid and intentionally distinct facts.

For local qualification, `require_local=True` is the default. A remote artifact is rejected
unless the caller explicitly opts into a non-local experiment.

The qualified target identity sets:

```text
model_digest = exact artifact SHA-256 digest
configuration_hash = H(
    base target configuration hash,
    application provider,
    model reference hash,
    model artifact identity hash,
    target/artifact binding hash
)
```

Changing weights under the same model tag changes both target configuration hash and target
snapshot identity.

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
provider API. Provider-specific inventory verification remains at the edge. For the local
Ollama path:

```text
predeclared manifest digest
        ↓
Ollama artifact verification
        ↓
ModelArtifactIdentity
        ↓
TargetModelReference
        ↓
ArtifactQualifiedTarget
        ↓
exact TargetIdentity / target snapshot
```

For OpenCode the `TargetModelReference` comes from `OpenCodeConfig.model_provider_id/model_id`,
not from `TargetIdentity.provider`, because the latter identifies the application adapter.
Future providers can supply the same provider-neutral artifact object without changing target
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

Reference Evaluation v1 must require both artifact-qualified RED measurement roles and an
artifact-qualified Blue target snapshot. Application-backed targets additionally require an
explicit underlying model reference.

## Tests

Deterministic tests require:

- different digests under the same target/model name produce different target snapshots;
- the same base target + same artifact is stable;
- direct MODEL targets derive their model reference safely;
- application-backed targets fail closed without an explicit underlying model reference;
- `provider=opencode` can bind an `ollama` artifact only through that explicit reference;
- provider/model/digest/locality mismatch fails closed;
- requests are delegated unchanged when identity is stable;
- post-admission base-target drift is rejected before execution.

No model inference, provider network access, Docker daemon or GPU is required.
