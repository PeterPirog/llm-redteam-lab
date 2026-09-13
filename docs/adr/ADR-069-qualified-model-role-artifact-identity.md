# ADR-069: Qualified model-role artifact identity

- Status: Proposed
- Date: 2026-09-13

## Context

The laboratory already separates Blue target identity from model artifact identity. That is necessary because the same base model in different applications, tool configurations or security controls is a different Blue security target.

The same reproducibility problem also exists for models used by the measurement apparatus: Red planners, Red mutators, semantic/multimodal Judges and forensic analyzers. Their role configuration fingerprints include provider/model name, endpoint/profile, capabilities, temperature and output limits, but a mutable model tag such as `latest` can retain the same role configuration while resolving to different weights.

That creates a provenance gap. Two campaigns could otherwise report the same configured Red or Judge policy even though the underlying model artifact changed.

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

Two provider-neutral adapters apply that primitive to the measurement apparatus:

- `red.provenance.build_artifact_qualified_red_policy_descriptor()` binds the exact planner/mutator artifacts to the existing model-backed Red descriptor before `fingerprint_attack_policy()` is calculated;
- `judges.provenance.build_artifact_qualified_judge_policy_descriptor()` binds the exact semantic and/or multimodal Judge artifacts to an existing Judge policy descriptor before `fingerprint_judge_policy()` is calculated.

Deterministic Judges do not use this helper because they have no model artifact.

A mutable tag resolving to new weights therefore changes the bound policy identity even if the role configuration itself did not change. Historical unqualified policy descriptors remain unchanged unless a caller explicitly opts into artifact-qualified provenance.

## Two-stage campaign qualification

EVALUATION already requires immutable attack/Judge fingerprints during ordinary campaign preflight. Artifact qualification must therefore support preparation before that preflight becomes ready; otherwise fingerprint generation and preflight would form a cycle.

The campaign contract is split into two deterministic stages:

### Preparation

`qualify_campaign_policy_descriptors()` receives:

- the exact model roles required by the intended campaign,
- `ModelsConfig`,
- already verified provider-neutral artifacts,
- the exact Red and Judge policy descriptors,
- whether Red is model-backed,
- optional explicit attacker-variant identity.

It returns `ArtifactQualifiedCampaignPolicies` containing:

- artifact-bound Red/Judge descriptors;
- attack-policy fingerprint;
- Judge-policy fingerprint;
- the exact typed qualified Red role set, when model-backed Red is required;
- the exact typed qualified Judge role set, when model-backed judging is required.

This stage does not require a ready preflight and makes no model call.

### Admission

The resulting fingerprints are placed in `CampaignPlan`. Ordinary campaign preflight can then validate the declared immutable measurement identity.

Immediately before execution, `validate_artifact_qualified_campaign_policies()` requires:

- a ready preflight;
- matching plan purpose, target class/mode and Red policy;
- exact equality between preflight-required model roles and the previously qualified roles;
- both Red roles whenever Red is model-backed;
- declared attack/Judge fingerprints for EVALUATION;
- exact equality between declared and freshly qualified fingerprints.

If a mutable local tag changes weights between preparation and admission, admission fails closed before campaign execution.

`build_artifact_qualified_campaign_policies()` remains a convenience path for DISCOVERY and for EVALUATION plans whose fingerprints were already prepared.

## Ollama registry edge

`OllamaArtifactRegistry` is the versioned operator/runtime edge for local qualification. It loads a predeclared YAML registry, constructs the existing `OllamaArtifactContract` for each requested model, verifies one later `/api/tags` inventory payload and returns an `OllamaArtifactQualification` containing provider-neutral artifact observations.

The registry deliberately verifies only explicitly requested model IDs. This lets a campaign qualify exactly the Red/Judge/Blue models it needs without treating unrelated local models as part of campaign identity.

The registry performs no HTTP request and no inference. Network acquisition of `/api/tags` remains a later runtime concern.

Role hints stored in the registry are operator metadata, not authorization. They are normalized into the registry fingerprint but never decide which role a model may execute; actual role selection still comes from `ModelsConfig` and campaign policy.

## Persisted campaign provenance

Policy fingerprints are sufficient for equality checks but are not sufficient for a human audit that asks which exact model weights participated in a historical campaign.

`campaign_model_role_qualifications` therefore persists the qualified measurement-side identities independently from Blue target snapshots.

Each immutable row records:

- campaign ID;
- policy scope (`attack`, `judge`, or future `forensic`);
- route ID and logical role;
- optional attacker variant;
- provider and model ID;
- role configuration fingerprint;
- artifact identity hash and exact digest;
- local/remote artifact classification;
- per-role qualification hash;
- role-set hash;
- campaign-scope provenance hash.

`save_campaign_model_role_provenance()` is idempotent for an exact repeat and rejects any later conflicting role/artifact set for the same campaign and policy scope. Loading reconstructs typed `QualifiedModelRoleIdentity` objects and re-verifies route IDs, per-role hashes, set hash and campaign-scope provenance hash.

This table is intentionally separate from `TargetSnapshotRow`: Red/Judge/forensic models are measurement actors, not the Blue security target.

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
artifact-bound Red/Judge policy fingerprints
        ↓
CampaignPlan immutable identity
        ↓
ready preflight + admission validation
        ↓
immutable campaign model-role provenance
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
- Red and model-backed Judge fingerprints include exact artifact identity;
- exact historical Red/Judge artifacts remain human-auditable rather than represented only by opaque hashes;
- forensic roles can reuse the same primitive when their provenance is persisted;
- provider-specific artifact verification remains isolated from policy business logic;
- explicit attacker variants remain distinct;
- the local Ollama registry can be verified using deterministic payload fixtures before any real inference;
- the complete registry → artifact → policy fingerprint → admission → persistence path is testable without Ollama or GPU access.

### Costs

- local campaign preparation must collect and verify artifact identities before a model-backed role can be qualified;
- policy fingerprints intentionally change after local model updates;
- one additional normalized provenance table is required;
- cloud providers without stable artifact identifiers may require provider-specific provenance with weaker claims.

## Follow-up

1. Wire the already-qualified policy object into `CampaignLifecycleExecutor` with the smallest possible change: validate admission, use its attack/Judge fingerprints, and persist attack/Judge role provenance before the first attack execution.
2. Use the local-only artifact manifest from the smoke profile to construct qualifications after actual Ollama inventory verification.
3. Persist forensic role qualification with forensic analysis provenance when model-backed forensics is invoked.
4. Keep the final Blue target/runtime lease separate and continue composing its own application/runtime/system-control identity.
5. Only after deterministic qualification is integrated should local model calls be used for smoke and reference campaigns.
