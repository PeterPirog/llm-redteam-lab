# ADR-068: Local-only model profile for first smoke campaigns

- Status: Proposed
- Date: 2026-09-13

## Context

Early validation must avoid unnecessary paid inference and must prove the laboratory with local models before any cloud escalation. The operator supplied an Ollama/OpenWebUI inventory containing both true local model artifacts and remote Ollama cloud aliases.

The inventory cannot be classified by the UI-level `connection_type` field alone: several cloud aliases report `connection_type=local` while also declaring `remote_host=https://ollama.com`. For this profile, a model is eligible only when it has a real local model artifact (for example a GGUF/MXFP4 artifact with nontrivial local size) and does not declare a remote host.

This profile is a runtime configuration, not business logic. Concrete model names remain outside the core implementation.

## Decision

Add `config/models.local-smoke.example.yaml` with `local_first=true`, `allow_cloud_fallback=false`, direct local Ollama endpoints, empty fallback chains, and a deliberately heterogeneous Red/Judge assignment.

### Default Red

- `red_planner`: `gpt-oss:latest`
- `red_mutator`: `mistral:7b-instruct`

The planner is a local reasoning/tool-capable model. The mutator is intentionally smaller to keep repeated mutation inexpensive.

### Independent semantic Judge

- `judge_semantic`: `nemotron-3.5-lightning:latest`

The Judge uses a different model family from the default Red planner and is invoked only when deterministic or system-state verification is insufficient. It must never act as the attacker's sole judge or provide live verdicts to the active Red conversation.

### Multimodal Judge

- `judge_multimodal`: `llama3.2-vision:latest`
- disabled by default

It is activated only for visual evidence that cannot be decided deterministically. The presence of vision-capable LLMs does not imply an image-generation Blue target; text/vision models are not treated as image generators.

### Forensics

- `forensic`: `nemotron-3.5-lightning:latest`

For the first local runs, forensics may reuse the semantic Judge model to reduce local inference cost. It runs only for reproducible or otherwise meaningful findings.

### Predeclared multi-attacker pool

The profile predeclares two distinct attacker variants while keeping the pool disabled for the cheapest first smoke:

1. `gptoss-mistral`: GPT-OSS planner + Mistral mutator;
2. `qwen-ornith`: Qwen planner + Ornith mutator.

When explicitly enabled for DISCOVERY, both variants share the campaign budget and retain separate transcript-free learning memory. Provider fallback remains an availability mechanism and is not used as attacker diversity.

## Recommended initial Blue targets

Blue remains campaign-selected because the same base model in MODEL, PIPELINE and AGENT modes is a different security target.

Recommended order for local qualification:

1. **Cheap MODEL smoke (writing/reasoning):** `ornith-1.5:9b`. It is small enough for fast repeated trials and is not the default Red planner or semantic Judge.
2. **Stronger MODEL comparison:** `gemma4:31b` or `granite4.2:30b`, if local latency is acceptable.
3. **OpenCode AGENT smoke:** `qwen3.8:latest`, with default Red on `gpt-oss:latest` and Judge on Nemotron so attacker, Blue and Judge are from different primary families.
4. **Alternative AGENT Blue:** `gpt-oss:latest` only when the Qwen attacker variant is selected; do not intentionally use the same model configuration as both Red planner and Blue in a measurement campaign unless that is the experimental question.

`gpt-oss:120b` and `laguna-s-2.1:latest` are true local artifacts but are not first-smoke defaults because their model files are much larger. They remain useful later as high-capability escalation resources after runtime qualification.

## Explicitly excluded inventory entries

Any model alias that declares a remote host or uses a `:cloud` / `-cloud` identity is excluded from this profile even when a surrounding UI reports a local connection. This includes remote Ollama aliases for DeepSeek, GLM, Kimi, Qwen cloud variants, Gemma cloud variants and GPT-OSS cloud variants.

## Measurement consequences

- One bounded conversation remains one statistical trial.
- Local model choice is part of the attack-policy or target identity and therefore must be fingerprinted.
- Red, Blue and Judge model identities must be persisted with every campaign.
- Deterministic and system-state verifiers retain priority over semantic Judge calls.
- Cloud inference remains disabled unless the operator explicitly adopts a different configuration.

## Operational consequences

This ADR does not claim that any model has already been benchmarked on the operator's hardware. Runtime speed, memory pressure, GPU offload, context-window stability and structured-output reliability remain empirical qualification items for the later local Docker/Ollama phase.
