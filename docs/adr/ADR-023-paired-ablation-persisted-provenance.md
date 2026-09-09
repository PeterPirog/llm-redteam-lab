# ADR-023: Persisted Provenance for Paired Red Ablation

- **Status:** Accepted
- **Date:** 2026-09-09

## Context

ADR-022 introduced matched-pair Red component evaluation. Its provider-independent
runner can enforce pair identity, counterbalanced order, shared seeds when available,
policy fingerprints and resource accounting returned by a trial executor.

A callback boundary cannot, by itself, prove that the implementation actually used
the Blue target, Judge, campaign budget and persisted execution it claims to have
used. Treating callback metadata as authoritative would weaken the evidence chain and
allow a well-formed but incorrectly wired experiment to produce a comparative claim.

The laboratory already persists immutable campaign measurement provenance and held-out
evaluation manifests. Paired ablation should reuse those facts instead of creating a
parallel trust model.

## Decision

A comparative paired Red ablation may be promoted to an auditable experiment only
after both arms are bound to real persisted EVALUATION campaigns.

### Campaign measurement extensions

`CampaignMeasurementSnapshot` gains two optional canonical fingerprints:

- `judge_policy_fingerprint`,
- `budget_fingerprint`.

They remain optional for backward-compatible general campaign storage. A paired
ablation experiment requires both values on both arms and requires them to match the
ablation contract exactly.

This is intentionally more explicit than relying only on a broad
`campaign_configuration_hash`. A component ablation must demonstrate that Judge and
budget were controlled variables, not merely assume that they were encoded somewhere
inside a larger configuration hash.

### Experiment snapshot

`RedAblationExperimentSnapshot` immutably binds:

- the complete paired-ablation contract,
- baseline campaign ID,
- treatment campaign ID,
- baseline campaign measurement hash,
- treatment campaign measurement hash.

On save and load, the repository verifies for each arm:

- campaign purpose is `EVALUATION`,
- target snapshot equals the contract target,
- metric-definition version is identical,
- held-out manifest is identical,
- arm-specific frozen Red policy fingerprint is correct,
- Judge fingerprint equals the contract,
- budget fingerprint equals the contract,
- stored campaign measurement hash is unchanged.

The baseline and treatment campaigns must be distinct.

### Observation binding

Every `PairedRedObservation` is persisted against a real `execution_id` and the arm's
expected campaign. The repository follows the existing evidence graph:

```text
ablation observation
        -> execution
        -> attack instance
        -> campaign
        -> target snapshot
        -> persisted conversation
```

Before accepting the observation it verifies:

- execution belongs to the expected baseline/treatment campaign,
- case ID matches the persisted attack,
- target snapshot matches the experiment contract,
- outcome matches persistence,
- objective violation matches persistence,
- model compromise matches persistence,
- system compromise matches persistence,
- confidence and error state match persistence,
- conversation session mode matches the contract,
- turn count equals recorded target interactions,
- backtracks and branches match,
- first-violation ordinal/depth match.

The observation row stores resource counters and pairing metadata but no raw prompts,
Blue outputs or secrets.

### Immutable rows

Both experiment snapshots and observation rows are content-hashed and immutable.
Exact re-save is idempotent. A changed value under the same experiment/arm/case/
replicate identity is rejected.

### Reporting

`summarize_persisted_red_ablation()` reconstructs observations from persisted
execution truth and then invokes the standard ADR-022 paired summarizer. Therefore a
comparative report inherits both:

1. held-out/conclusive/balanced-replicate measurement gates, and
2. database-backed campaign/execution provenance checks.

## Seed limitation

A scheduled `pair_seed` is persisted as experiment metadata, but not every provider
exposes authoritative evidence that the exact seed was honored internally. Therefore
seed pairing is strongest when the target adapter records seed/config evidence that
can later be verified. Persisting a scheduled seed alone MUST NOT be described as
proof that an opaque provider used it.

## Consequences

### Positive

- callback declarations no longer suffice for comparative claims,
- Judge and budget equality become independently checkable campaign facts,
- MODEL_COMPROMISE and SYSTEM_COMPROMISE remain tied to persisted executions,
- altered in-memory results cannot rewrite database truth,
- paired reports can be reproduced from stored experiment facts without raw prompts,
- the design reuses the existing Target -> Attack -> Execution -> Evidence persistence
  chain rather than creating a second experiment database.

### Negative

- credible paired ablations require two persisted evaluation campaigns,
- campaign setup must explicitly fingerprint Judge and budget,
- older evaluation snapshots without these optional fields cannot be used as a strict
  paired-ablation arm without being rerun under explicit provenance,
- opaque-provider seed fidelity remains dependent on adapter evidence.

These restrictions are accepted because the goal is evidentiary confidence rather
than maximizing the number of reported Red wins.
