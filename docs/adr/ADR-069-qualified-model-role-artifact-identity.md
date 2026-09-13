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

Duplicate role routes fail closed.

## Policy binding

`bind_policy_descriptor_to_model_roles()` composes a qualified role set into an immutable policy descriptor only when the set of role routes exactly matches the caller's predeclared requirement.

This gives later campaign preflight a deterministic way to include exact Red/Judge artifact provenance in attack-policy and Judge-policy fingerprints without changing historical descriptors by default.

A mutable tag resolving to new weights therefore changes the bound policy identity even if the role configuration itself did not change.

## Locality

Role configuration locality and artifact locality must agree:

- a role configured as `local` cannot bind an artifact observed as remote;
- a role configured as `cloud` cannot bind an artifact observed as local.

This check is intentionally provider-neutral. It supplements rather than replaces provider-specific verification.

For the planned local-only smoke profile, the practical path is:

```text
predeclared Ollama manifest digest
        ↓
OllamaArtifactContract verification
        ↓
ModelArtifactIdentity(local_artifact=true)
        ↓
resolved ModelRoleConfig
        ↓
QualifiedModelRoleIdentity
        ↓
artifact-bound policy fingerprint
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
- Red/Judge/forensic provenance becomes comparable to Blue artifact provenance;
- provider-specific artifact verification remains isolated from policy business logic;
- explicit attacker variants remain distinct;
- the mechanism can be exercised using deterministic tests before any real inference.

### Costs

- local campaign preflight must collect and verify artifact identities before a role can be artifact-qualified;
- policy fingerprints will intentionally change after local model updates;
- cloud providers without stable artifact identifiers may require provider-specific provenance with weaker claims.

## Follow-up

1. Bind qualified Red roles into the persisted attack-policy fingerprint at campaign preflight.
2. Bind semantic/multimodal Judge roles into Judge-policy provenance only when those Judges are enabled/eligible for the campaign.
3. Persist the exact qualification-set hash with measurement provenance.
4. Use the local-only artifact manifest from the smoke profile to construct qualifications after actual Ollama inventory verification.
5. Keep the final Blue target/runtime lease separate and continue composing its own application/runtime/system-control identity.
