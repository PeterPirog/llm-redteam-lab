# ADR-070: Artifact-qualified campaign lifecycle admission

- Status: Proposed
- Date: 2026-09-13

## Context

ADR-069 introduces provider-neutral model-role artifact identity for Red, model-backed
Judges and forensic roles.  A qualified role identity is useful only if the campaign
lifecycle admits and persists it *before* target interaction.  Otherwise a caller could
prepare exact model provenance but still execute through the historical name/config-only
measurement path.

The existing `CampaignLifecycleExecutor` already owns the correct target execution,
budgeting, evidence, judgment, persistence and metric semantics.  Reimplementing that
loop would create a second security-measurement engine and unacceptable architectural
drift.

## Decision

Add `ArtifactQualifiedCampaignLifecycleExecutor` as a narrow lifecycle adapter over the
existing executor.

The adapter does not implement another attack loop.  It adds four gates around the
existing lifecycle:

1. **qualified preflight admission** — required model roles from campaign preflight must
   exactly match the prepared `ArtifactQualifiedCampaignPolicies`;
2. **runtime descriptor binding** — the actually constructed Red runtime descriptor and
   actual Judge descriptor must match the base descriptors used when artifact-qualified
   fingerprints were prepared;
3. **qualified policy exposure** — the existing lifecycle fingerprints the
   artifact-bound Red/Judge descriptors, not their name-only forms;
4. **pre-attack provenance persistence** — exact model-role provenance is persisted
   immediately before the measurement snapshot and therefore before the first attack or
   target interaction.

No provider call, Docker operation or model inference is added by the adapter.  It consumes
already verified `ModelArtifactIdentity` objects indirectly through
`ArtifactQualifiedCampaignPolicies`.

## EVALUATION preparation and admission

Held-out EVALUATION uses a two-phase contract.

### Preparation

Before ordinary preflight, the operator/runtime:

```text
verified model artifacts
        +
Red/Judge base descriptors
        ↓
ArtifactQualifiedCampaignPolicies
        ↓
attack_policy_fingerprint
judge_policy_fingerprint
```

Those exact fingerprints are written into `CampaignPlan`.

### Admission

Immediately before execution:

```text
CampaignPlan
    +
ready CampaignPreflight
    +
prepared ArtifactQualifiedCampaignPolicies
    +
actual runtime Red/Judge descriptors
        ↓
exact equality gates
        ↓
provenance persistence
        ↓
measurement snapshot
        ↓
first attack
```

Missing or stale held-out EVALUATION fingerprints fail closed.  The qualified executor
never silently fills EVALUATION measurement identity.

## DISCOVERY

DISCOVERY does not make comparative Blue claims and historical deterministic/mock
workflows remain useful during development.  The historical executor therefore remains
available for cheap mock and legacy discovery tests.

When the artifact-qualified executor is selected for DISCOVERY, it binds the prepared
qualified fingerprints into an immutable copy of the campaign plan.  This makes the
campaign configuration hash sensitive to changes in Red/Judge artifacts even though
DISCOVERY did not require the fingerprints to be predeclared by the operator.

## Runtime drift

Artifact digest equality alone is insufficient.  After preparation and before target
execution the adapter verifies the ordinary runtime descriptors against the qualified
base descriptors.  Drift in, for example:

- planner/mutator model configuration;
- endpoint/profile;
- temperature or output/context limits;
- Red runtime version, stopping policy or attacker variant;
- Judge implementation/policy metadata;

rejects the campaign before the target is called.

## Persistence ordering

`_persist_measurement_snapshot()` is the existing lifecycle hook that runs after the
campaign row exists but before the attack loop.  The qualified adapter uses this hook to
persist `campaign_model_role_qualifications` first and the measurement snapshot second.

If provenance persistence fails, the existing lifecycle exception path marks the campaign
`FAILED` and no target interaction occurs.

The stored model-role record contains exact provider/model/digest/configuration identity;
it is separate from Blue `TargetSnapshotRow` because Red and Judge are measurement
apparatus, not the security target.

## Security and measurement invariants

This integration does not change:

- one bounded conversation = one statistical security trial;
- `MODEL_COMPROMISE` vs `SYSTEM_COMPROMISE` semantics;
- target-visible-only live Red adaptation;
- the prohibition on a live Judge oracle;
- budget accounting;
- deterministic/system-state/semantic/multimodal Judge priority;
- ASR/MCR/SCR definitions or denominators;
- Blue target identity;
- attacker permissions.

## Migration rule

The intended production/reference path is:

- deterministic/mock development may continue through the historical lifecycle;
- any model-backed comparative EVALUATION must use artifact-qualified lifecycle admission;
- local reference tooling should be migrated to the qualified executor before the first
  real local Reference Evaluation v1 run;
- once existing callers are migrated and CI is healthy, the historical executor may gain
  an explicit guard that rejects unqualified model-backed EVALUATION globally.

This staged migration avoids breaking deterministic development while preventing the
legacy path from becoming the long-term measurement interface.

## Tests

Deterministic tests must prove:

1. exact Red artifact provenance exists before the first target call;
2. the persisted measurement snapshot uses artifact-qualified policy fingerprints;
3. held-out model-backed EVALUATION without predeclared qualified fingerprints is blocked
   before target interaction;
4. a correctly prepared held-out EVALUATION executes through the normal measurement loop;
5. Red/Judge runtime descriptor drift is rejected before target interaction.

No real model, Ollama daemon, Docker daemon, GPU, network access or cloud API is required.
