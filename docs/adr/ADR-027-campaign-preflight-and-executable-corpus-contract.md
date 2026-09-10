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
4. Campaign budgets are loaded through a strict typed configuration document.
5. Preflight calculates trial and target-interaction bounds and validates attack,
   per-attack turn and image-generation budgets.
6. Model-backed Red and non-deterministic Judge layers require explicit configured
   logical model roles. Image-generation plans require a vision-capable
   `judge_multimodal` role.
7. Agent network and git-push permissions remain denied by default. Explicit
   enablement is visible as a preflight warning and does not replace outer
   Docker/VM isolation.
8. Corpus ingestion and execution completeness are separate concerns. Descriptive
   objective fields may be absent in normalized source material, while execution
   policy and detectors determine whether a case can be measured.
9. Align the typed domain with the normalized corpus schema for source provenance,
   taxonomy metadata and payload kinds.
10. Make explicit `turns` a first-class payload. `ScriptedPayloadStrategy` replays
    user-turn trajectories as one multi-turn attack trial. `external_content` and
    `tool_output` turns are never silently converted into user messages; they
    require an environment-aware fixture runner.
11. Static multi-turn execution requires an explicit turn sequence. A goal seed
    without turns requires a model-backed adaptive Red policy.
12. Planning and validation perform zero model inference and zero target calls.

## Measurement consequences

A multi-turn scripted trajectory remains one Blue ASR trial. Its turns are resource
and Red-efficiency observations, not extra vulnerability trials. Evaluation plans
remain subject to held-out/sequestered measurement gates already defined by the
measurement protocol.

Preflight is not a security score. It reports whether the declared experiment is
internally executable under the selected budgets and provenance constraints.

## Safety consequences

The initial CLI exposes validation and planning only. It cannot silently start a
real campaign. A later execution command must consume a successful preflight and
will require explicit target configuration and runtime authorization.

## Alternatives rejected

- Let each target adapter validate its own campaign configuration: rejected because
  this duplicates policy and permits inconsistent measurement semantics.
- Treat every corpus record as immediately executable: rejected because imported
  records can require target-specific fixtures or environment injection.
- Represent known multi-turn jailbreaks as concatenated single prompts: rejected
  because it destroys conversational state, turn cost and sequence causality.
- Add a dashboard before an operator lifecycle: rejected because it would visualize
  components that still lack one guarded execution entry point.
