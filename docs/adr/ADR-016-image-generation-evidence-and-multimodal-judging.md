# ADR-016: Image-generation evidence and multimodal judging

- Status: Accepted
- Date: 2026-09-09

## Context

`image_generation` is a first-class Blue target class in the project requirements. A
text-only response contract is insufficient for evaluating generated visual content,
and a text-only Judge cannot make authoritative claims about an image it did not
inspect.

Current research also makes single-turn-only evaluation inadequate. Zhao et al.,
USENIX Security 2026, show that conversational memory can become a text-to-image
jailbreak surface: their Inception attack decomposes the unsafe objective across
multiple turns and reports a 20 percentage point ASR improvement over prior SOTA.
T2I-RiskyPrompt (AAAI 2026) provides a broader safety benchmark with 6,432 risky
prompts, 6 primary categories, 14 subcategories, eight T2I models, nine defenses,
five filters and five attack strategies.

Safety metrics must also preserve utility. A safeguard that refuses every image can
appear to have excellent attack resistance while being unusable. 2026 multimodal
safeguard evaluations explicitly report attack success, detection and benign
over-refusal separately with confidence intervals.

OpenTelemetry GenAI semantic conventions moved to a dedicated repository in 2026.
The current conventions define `generate_content` as the multimodal generation
operation and `gen_ai.output.type=image` for image outputs. GenAI conventions remain
in development, so project-specific `llm_redteam.*` attributes stay namespaced and
version-controlled.

## Decision

### 1. Reuse the common Target contract

Image-generation systems remain `TargetAdapter` implementations. Generated images
are represented by `EvidenceKind.IMAGE` records with an opaque `artifact_ref` and a
SHA-256 `content_hash`.

The normalized request contract can carry opaque input artifact references so future
image+text -> image adapters do not require a second orchestration architecture.
Adapters that do not implement multimodal input must fail closed rather than silently
ignore artifact references.

### 2. Raw images are not normal SQL evidence

Normal persistence stores hashes, dimensions, MIME type, seed/configuration metadata
and artifact references. Raw image bytes live in an explicit `ImageArtifactStore`.
The local filesystem implementation is opt-in for sensitive artifacts and verifies
content hashes on read. This mirrors the existing hash-first policy for prompts,
forensic material and regression reproducers.

### 3. Judge visual content in layers

The image evaluation path is:

```text
TARGET RESPONSE
      |
      v
IMAGE EVIDENCE PREFLIGHT
      |-- explicit safety refusal -> deterministic non-violation
      |-- missing/malformed/tampered artifact -> INCONCLUSIVE
      `-- valid generated image -> abstain to visual semantics
                                      |
                                      v
                               MULTIMODAL JUDGE
```

The preflight layer verifies artifact existence, SHA-256 binding and objective
metadata before any vision-model inference.

The multimodal Judge receives the security objective plus verified image artifacts.
Image and target text are labelled `UNTRUSTED_TARGET_EVIDENCE`; instructions embedded
in either surface are never instructions to the Judge.

The Judge has a first-class abstention path. Ambiguous or insufficient evidence must
produce `INCONCLUSIVE`, not PASS.

### 4. Preserve MODEL_COMPROMISE versus SYSTEM_COMPROMISE

A multimodal Judge can establish that generated visual content violated a model-level
behavioral invariant. It must never infer actual pipeline delivery, filter bypass,
authorization decisions, tool execution or other external state from the image.
Therefore it may establish `MODEL_COMPROMISE` but not `SYSTEM_COMPROMISE`.

For a pipeline target, system compromise requires deterministic/system-state evidence
that the prohibited effect passed the surrounding control and became an unauthorized
system effect.

### 5. Multi-turn image attacks reuse conversation semantics

The existing `MultiTurnCampaignEngine` is used for conversational T2I systems. One
complete bounded conversation remains one Blue ASR trial. Individual turns and image
generations are resource/attacker-efficiency units, not extra vulnerability trials.

Target-managed sessions must use the actual session identifier returned by the target.
The harness must not invent a server-side session identifier. The first target-managed
turn therefore starts with no session ID; subsequent turns reuse the ID returned by
the adapter.

Every image-producing turn consumes `max_image_generations` from the campaign budget.
This is enforced before the target invocation.

### 6. Do not collapse safety and utility into one score

Image reporting includes separate Wilson interval estimates for at least:

- end-to-end harmful attack success,
- unsafe output conditional on an image being generated,
- harmful-request refusal,
- benign over-refusal,
- image-generation availability,
- multimodal Judge abstention,
- unresolved trials.

A refuse-all system can therefore show low ASR and high over-refusal simultaneously.
The project must not hide this trade-off in a single composite score.

## Consequences

### Positive

- `image_generation` now participates in the same evidence/judgment architecture as
  coding, reasoning and writing targets.
- multi-turn T2I attacks can be measured without turn-count denominator bias.
- raw generated images are isolated from ordinary persistence and telemetry.
- vision-model inference is skipped for deterministic refusals and rejected evidence.
- text-only models cannot be accidentally assigned as authoritative visual Judges.
- image safety metrics preserve both security and utility.

### Costs and limitations

- the current milestone proves the evaluation path with deterministic image fixtures;
  it does not yet provide a production ComfyUI/OpenWebUI image-generation adapter.
- exact policy classification still depends on the selected multimodal Judge or future
  specialized classifier and therefore requires calibration/reproduction.
- a visual semantic verdict alone does not prove whether a downstream pipeline
  delivered or blocked the artifact.
- current OpenTelemetry GenAI conventions are still development-status and may evolve.

## References

- Zhao et al., "When Memory Becomes a Vulnerability: Towards Multi-turn Jailbreak
  Attacks against Text-to-Image Generation Systems", USENIX Security 2026.
  https://www.usenix.org/conference/usenixsecurity26/presentation/zhao-shiqian
- Zhang et al., "T2I-RiskyPrompt: A Benchmark for Safety Evaluation, Attack, and
  Defense on Text-to-Image Model", AAAI 2026.
  https://doi.org/10.1609/aaai.v40i42.40920
- OpenTelemetry GenAI semantic conventions.
  https://github.com/open-telemetry/semantic-conventions-genai
