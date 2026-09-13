# ADR-071: Hold exact Red model artifacts constant in Reference Evaluation

- Status: Proposed
- Date: 2026-09-13

## Context

Reference Evaluation v1 is a paired, counterbalanced experiment comparing two Red search
policies. Its declared changed component is `red_search_policy`. The experimental claim is
invalid if baseline and treatment also differ in model weights, provider artifact, Judge
policy or stage budget.

Mutable local tags such as `latest` make this a practical risk. The same configured model
name can resolve to different weights after a local update while the original role
configuration remains textually unchanged.

ADR-069 introduced provider-neutral exact model-role identity. Reference Evaluation needs a
paired contract that applies that identity symmetrically to both arms before the runner is
allowed to construct its `PairedRedAblationContract`.

## Decision

Introduce `ArtifactQualifiedReferencePolicies` and
`qualify_reference_model_policies()`.

For the selected reference stage, preparation:

1. resolves the exact stage budget profile;
2. builds the ordinary baseline and treatment Red policy descriptors using the same
   `ModelsConfig` and effective budget;
3. binds both descriptors to the same verified planner/mutator
   `ModelArtifactIdentity` objects;
4. requires Reference Evaluation v1's deterministic Judge descriptor;
5. records exact attack-policy, Judge and budget fingerprints;
6. fails if the two arms do not share the same exact Red model-role-set identity.

The module performs no inference, network call or provider operation.

## Experimental control

The paired experiment intentionally varies:

```text
baseline Red search policy  <->  treatment Red search policy
```

while holding constant:

```text
Blue target snapshot
exact Red planner artifact
exact Red mutator artifact
Red role configuration
Judge policy
stage budget
held-out evaluation manifest
pairing design
```

The baseline and treatment attack-policy fingerprints must still differ because the search
policy itself differs.

If the model artifact differs across arms, the helper rejects the design rather than
reporting a confounded paired effect.

## Mutable model tags

A mutable tag is never the final measurement identity.

```text
planner-local / gpt-oss:latest
        ↓
verified ModelArtifactIdentity
        ↓
QualifiedModelRoleIdentity
        ↓
shared red_model_role_set_sha256
        ↓
baseline/treatment policy fingerprints
```

Changing the artifact digest under the same model tag intentionally changes both arm policy
fingerprints and the overall reference qualification hash.

## Judge policy

Reference Evaluation v1 requires the deterministic canary Judge. It has no model artifact
and therefore no `judge_model_roles` qualification set.

A future reference protocol may study a model-backed Judge, but that would add another
measurement-model artifact dimension and must be introduced explicitly rather than silently
changing v1.

## Stage budget

Instrumentation smoke and policy qualification may use different predeclared budget
profiles. The resolved stage budget fingerprint is part of
`ArtifactQualifiedReferencePolicies`; changing stage or budget therefore changes the
qualified reference identity.

## Runtime admission

`validate_reference_runtime_policy_descriptors()` compares the actual baseline Red runtime,
treatment Red runtime and shared Judge descriptor with the base descriptors used during
artifact qualification.

This detects configuration drift after preparation, including temperature, endpoint,
context/output limits, Red runtime/stopping-policy version or Judge metadata changes.

## Integration with the paired runner

The qualification object deliberately separates:

- `ablation_contract_fingerprints()` — only the four fingerprint fields directly accepted
  by the existing `PairedRedAblationContract`;
- `provenance_identity()` — the shared Red role-set hash and full reference qualification
  hash that should be persisted alongside the experiment.

The existing counterbalanced execution order must remain unchanged. Reference model
qualification is an admission/provenance layer around that runner, not a replacement for
its paired scheduling logic.

## Required runner integration before local Reference Evaluation

Before the first real local Reference Evaluation v1 run, the runner must:

1. require `ArtifactQualifiedReferencePolicies`;
2. use its baseline/treatment/Judge/budget fingerprints when building the paired contract;
3. validate actual runtime descriptors before the first pair;
4. persist the exact Red model-role provenance for both arm campaigns before target
   interaction;
5. persist the reference qualification hash with the ablation experiment provenance;
6. reject artifact or policy drift rather than falling back to name-only identity.

## Measurement invariants

This decision does not change:

- one bounded conversation = one security trial;
- paired statistical unit = matched case/replicate pair;
- counterbalanced arm execution order;
- held-out fixed-corpus inference scope;
- `MODEL_COMPROMISE` vs `SYSTEM_COMPROMISE` semantics;
- Red live-feedback boundary;
- ASR/MCR/SCR or paired-effect estimators.

It only strengthens the identity of the measurement apparatus.
