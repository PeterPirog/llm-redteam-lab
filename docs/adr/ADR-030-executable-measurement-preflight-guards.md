# ADR-030: Executable Measurement Preflight Guards

## Status

Accepted

## Context

The campaign lifecycle can now execute static and adaptive multi-turn Red policies,
persist measurement provenance, qualify Red policy changes with held-out paired
ablations, and calibrate automated Judges. That makes preflight correctness a
security and measurement boundary rather than only an operator convenience.

Three policy fields already existed but were not fully enforced by campaign
planning: explicit budget-profile selection, the configurable image multimodal-Judge
requirement, and model-role output limits. In addition, corpus ingestion permits
partially specified source records, while executable security experiments require an
observable definition of failure.

## Decision

1. If runtime policy requires an explicit budget profile, campaign preflight rejects
   implicit default selection.
2. Every selected executable case must define a non-empty `forbidden_effect`.
   Corpus records may remain less complete for taxonomy/import purposes, but they
   cannot become measurements until the violation condition is explicit.
3. Image-generation preflight follows
   `require_multimodal_judge_for_image_generation` instead of hard-coding a vision
   Judge requirement. The default remains enabled. A deterministic/specialized
   visual verifier may avoid multimodal inference only when runtime policy explicitly
   permits that design and the case itself does not request multimodal grading.
4. Required model roles are checked against both global and role-specific output
   token budgets before execution. A configured role whose single-call maximum
   cannot fit the authorized budget fails preflight.
5. These checks run before any target call or model inference.

## Measurement consequences

This preserves a strict distinction between corpus validity and measurement
validity. A benchmark record can be useful for coverage mapping without being
executable. Conversely, an executable campaign cannot rely on an implied or
post-hoc security objective.

The configurable image rule also preserves the Judge priority hierarchy:
deterministic/specialized verification can remain authoritative when it fully
measures the declared visual property, while semantic visual claims still require a
multimodal Judge or another validated visual classifier.

## Safety consequences

No target permission, model permission, network access, git access or campaign
budget is expanded. The change only adds fail-closed guards and can reduce
unnecessary inference.

## Research alignment

- NIST TEVV-Athlon 2026: measurement design should be explicit and tailored to the
  assessment objective.
- NIST AITE 2026: sequestered, contamination-resistant evaluation reinforces the
  distinction between discovery and measurement.
- MT-JailBench 2026: budgets and evaluators are major multi-turn comparison
  confounders.
- OWASP Agent Control Standard 2026: runtime policy and control state should be
  inspectable and enforceable outside agent-controlled content.
