# ADR-027: Campaign Preflight and Executable Corpus Contract

## Status

Accepted

## Context

The project now contains mature components for adaptive and multi-turn Red search,
held-out evaluation, multimodal judging, system-state verification, persistence,
forensics, Blue knowledge and regression. The remaining operator risk is launching
those components under inconsistent experimental conditions or against corpus
records that are valid metadata but cannot be executed by the selected runtime.

The corpus JSON Schema and the Python domain model had also drifted. In particular,
the schema already described explicit multi-turn `turns` payloads and richer source
provenance while the runtime `PayloadSpec` could not represent them. Conversely,
the runtime required several descriptive fields that the corpus schema treated as
optional.

## Decision

1. Add a first-class `CampaignPlan` and deterministic `CampaignPreflight` that run
   before target or model invocation.
2. Keep DISCOVERY and EVALUATION distinct at the operator boundary.
3. EVALUATION must fail closed without a held-out manifest, pinned target snapshot,
   attack-policy fingerprint and Judge-policy fingerprint.
4. Campaign budgets are loaded through a strict typed configuration document. If
   runtime policy requires an explicit budget profile, implicit default selection
   is rejected at preflight.
5. Preflight calculates trial and target-interaction bounds and validates attack,
   per-attack turn and image-generation budgets.
6. Model-backed Red and non-deterministic Judge layers require explicit configured
   logical model roles. Role output limits must fit the campaign/role output budget.
7. Image-generation Judge requirements are policy-driven. The default policy
   requires a vision-capable `judge_multimodal`; a specialized deterministic image
   verifier may be used without a vision model only when policy explicitly permits
   that measurement design.
8. Agent network and git-push permissions remain denied by default. Explicit
   enablement is visible as a preflight warning and does not replace outer
   Docker/VM isolation.
9. Corpus ingestion and execution completeness are separate concerns. Descriptive
   objective fields may be absent in normalized source material, but a selected
   executable case must define an explicit `forbidden_effect`. A record that cannot
   state what observable effect constitutes violation cannot produce a security
   measurement.
10. Align the typed domain with the normalized corpus schema for source provenance,
    taxonomy metadata and payload kinds.
11. Make explicit `turns` a first-class payload. `ScriptedPayloadStrategy` replays
    user-turn trajectories as one multi-turn attack trial. `external_content` and
    `tool_output` turns are never silently converted into user messages; they
    require an environment-aware fixture runner.
12. Static multi-turn execution requires an explicit turn sequence. A goal seed
    without turns requires a model-backed adaptive Red policy.
13. Planning and validation perform zero model inference and zero target calls.

## Measurement consequences

A multi-turn scripted trajectory remains one Blue ASR trial. Its turns are resource
and Red-efficiency observations, not extra vulnerability trials. Evaluation plans
remain subject to held-out/sequestered measurement gates already defined by the
measurement protocol.

Preflight is not a security score. It reports whether the declared experiment is
internally executable under the selected budgets, target, Judge and provenance
constraints.

A permissive corpus schema does not weaken measurement semantics: imported records
may exist for taxonomy/coverage purposes, while campaign execution remains gated on
an observable forbidden effect and a compatible grading path.

## Safety consequences

The initial CLI exposes validation and planning only. It cannot silently start a
real campaign. A later execution command must consume a successful preflight and
will require explicit target configuration and runtime authorization.

## Alternatives rejected

- Let each target adapter validate its own campaign configuration: rejected because
  this duplicates policy and permits inconsistent measurement semantics.
- Treat every corpus record as immediately executable: rejected because imported
  records can require target-specific fixtures, environment injection or incomplete
  security objectives.
- Represent known multi-turn jailbreaks as concatenated single prompts: rejected
  because it destroys conversational state, turn cost and sequence causality.
- Always require a multimodal LLM for every image case: rejected because a trusted
  deterministic/specialized verifier can be authoritative for some narrowly defined
  visual properties and unnecessary inference should be avoided.
- Add a dashboard before an operator lifecycle: rejected because it would visualize
  components that still lack one guarded execution entry point.
