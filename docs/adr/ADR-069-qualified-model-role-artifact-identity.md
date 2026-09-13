# ADR-069: Qualified model-role artifact identity

- Status: Proposed
- Date: 2026-09-13

## Context

The laboratory already separates Blue target identity from model artifact identity. That is necessary because the same base model in different applications, tool configurations or security controls is a different Blue security target.

The same reproducibility problem also exists for the models used *by the measurement apparatus*: Red planners, Red mutators, semantic/multimodal Judges and forensic analyzers. Their role configuration fingerprints include provider/model name, endpoint/profile, capabilities, temperature and output limits, but a mutable model tag such as `latest` can continue to have the same role configuration while resolving to different model weights.

That creates a provenance gap. Two campaigns could otherwise report the same configured Red or Judge policy even though the underlying local model artifact changed.

This is not a Blue `TargetIdentity` problem and must not be solved by collapsing Red/Judge models into the target identity.

## Decision

Introduce a provider-neutral `QualifiedModelRoleIdentity` that binds:

1. logical role (`red_planner`, `red_mutator`, `judge_semantic`, etc.);
2. optional explicit Red attacker-variant route;
3. provider and model ID;
4. the full `ModelRoleConfig.configuration_fingerprint`;
5. exact `ModelArtifactIdentity.identity_sha256`;
6. exact content digest;
7. artifact locality.

The resulting `qualification_sha256` changes if either runtime role configuration or model artifact identity changes.

Provider-specific inventory verification remains outside this layer. For Ollama, `OllamaArtifactContract` resolves `/api/tags`, rejects remote proxy records when local artifacts are required and verifies the predeclared manifest digest. Other providers may supply equivalent artifact identities later.

## Role sets

`QualifiedModelRoleSet` provides an order-independent fingerprint over one or more qualified role routes. Red attacker variants are namespaced by explicit route IDs such as:

```text
red-a:red_planner
red-a:red_mutator
```

so the same underlying model can be distinguished when it is intentionally configured as a different attacker variant.

Empty role sets, duplicate role routes, empty policy requirements and duplicate required routes fail closed.

## Policy binding

`bind_policy_descriptor_to_model_roles()` composes a qualified role set into an immutable policy descriptor only when the set of role routes exactly matches the caller's predeclared requirement.

Two small provider-neutral adapters apply that primitive to the measurement apparatus:

- `red.provenance.build_artifact_qualified_red_policy_descriptor()` binds the exact planner/mutator artifacts to the existing model-backed Red descriptor before `fingerprint_attack_policy()` is calculated;
- `judges.provenance.build_artifact_qualified_judge_policy_descriptor()` binds the exact semantic and/or multimodal Judge artifacts to an existing Judge policy descriptor before `fingerprint_judge_policy()` is calculated.

Deterministic Judges do not use this helper because they have no model artifact.

A mutable tag resolving to new weights therefore changes the bound policy identity even if the role configuration itself did not change. Historical unqualified policy descriptors remain unchanged unless a caller explicitly opts into artifact-qualified provenance.

## Ollama registry edge

`OllamaArtifactRegistry` is the versioned operator/runtime edge for local qualification. It loads a predeclared YAML registry, constructs the existing `OllamaArtifactContract` for each requested model, verifies one later `/api/tags` inventory payload and returns an `OllamaArtifactQualification` containing provider-neutral artifact observations.

The registry deliberately verifies only the explicitly requested model IDs. This allows a campaign to qualify exactly the Red/Judge/Blue models it needs without treating unrelated local models as part of campaign identity.

The registry itself performs no HTTP requests and no inference. Network acquisition of `/api/tags` remains a later runtime concern.

Role hints stored in the registry are operator metadata, not authorization. They are normalized into the registry fingerprint but never decide which role a model may execute; actual role selection still comes from `ModelsConfig` and campaign policy.

## Locality

Role configuration locality and artifact locality must agree:

- a role configured as `local` cannot bind an artifact observed as remote;
- a role configured as `cloud` cannot bind an artifact observed as local.

This check is intentionally provider-neutral. It supplements rather than replaces provider-specific verification.

For the planned local-only smoke profile, the practical path is:

```text
predeclared Ollama artifact registry
        ↓
local /api/tags payload
        ↓
OllamaArtifactContract verification
        ↓
ModelArtifactIdentity(local_artifact=true)
        ↓
resolved ModelRoleConfig
        ↓
QualifiedModelRoleIdentity
        ↓
artifact-bound Red/Judge policy fingerprint
```

## Security and measurement semantics

This binding does **not**:

- authorize inference;
- expand attacker permissions;
- expose Judge verdicts to live Red;
- alter campaign budgets;
- change MODEL_COMPROMISE or SYSTEM_COMPROMISE semantics;
- change ASR/MCR/SCR denominators;
- replace Blue `TargetIdentity`;
- make Red or Judge a statistical trial unit.

It is provenance for the measurement apparatus.

One bounded conversation remains one security trial.

## Consequences

### Positive

- mutable local model tags cannot silently preserve measurement identity after weight changes;
- Red and model-backed Judge fingerprints can include exact artifact identity;
- forensic roles can use the same primitive when their provenance is persisted;
- provider-specific artifact verification remains isolated from policy business logic;
- explicit attacker variants remain distinct;
- the local Ollama registry can be verified using deterministic payload fixtures before any real inference;
- the full registry → artifact → Red/Judge fingerprint path is testable without Ollama or GPU access.

### Costs

- local campaign preflight must collect and verify artifact identities before a role can be artifact-qualified;
- policy fingerprints will intentionally change after local model updates;
- cloud providers without stable artifact identifiers may require provider-specific provenance with weaker claims.

## Follow-up

1. Wire artifact-qualified Red/Judge descriptors into `CampaignLifecycleExecutor` behind an explicit fail-closed qualification contract rather than silently changing historical campaign behavior.
2. Use the local-only artifact manifest from the smoke profile to construct qualifications after actual Ollama inventory verification.
3. Persist forensic role qualification with forensic analysis provenance when model-backed forensics is invoked.
4. Keep the final Blue target/runtime lease separate and continue composing its own application/runtime/system-control identity.
5. Only after the deterministic qualification path is integrated should local model calls be used for smoke and reference campaigns.
