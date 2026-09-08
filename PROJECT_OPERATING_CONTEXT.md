# LLM Red Team Lab — Project Operating Context

## Purpose
This file supplements `PROJECT_REQUIREMENTS.md` with practical operating assumptions for continued work across ChatGPT project sessions. `PROJECT_REQUIREMENTS.md` remains the architectural source of truth.

## User environment
The user normally works on Windows and has access to:
- Docker Desktop,
- PowerShell,
- Warp,
- OpenCode,
- Ollama,
- OpenWebUI,
- local and cloud models exposed through OpenWebUI/Ollama.

Prefer Windows-compatible commands and PowerShell examples. Docker may be used for isolation, reproducibility and disposable test environments. OpenCode and Warp may be used for local coding/execution when needed, but permissions should be restricted to the intended repository/workspace, TEMP when necessary, and explicitly approved resources.

## Local-first model policy
Early development and smoke testing should prefer local models. Cloud models are optional escalation/fallback resources.

Do not waste model inference before the pipeline is proven. Development order:
1. deterministic mocks and fixtures,
2. one or two smoke probes,
3. small local campaigns,
4. adaptive red-team loops with strict budgets,
5. larger campaigns only after telemetry, persistence and judging are verified.

Do not hard-code specific model names in application logic. Runtime model inventory can change and should be discovered/configured externally.

## Required model-role configuration
Maintain `config/models.yaml` with logical roles rather than hard-coded models:

- `red_planner`: strongest available attacker/reasoning model; creates attack hypotheses and strategy,
- `red_mutator`: faster/cheaper model for prompt variations,
- `blue`: target model or target pipeline selected by each campaign,
- `judge_semantic`: independent semantic grader used only when deterministic verification is insufficient,
- `judge_multimodal`: vision-capable grader for image-generation evidence,
- `forensic`: analyzes confirmed or meaningful findings and proposes root cause,
- `reporter`: optional and normally disabled; deterministic reporting is preferred.

Each role should support at least:
- provider,
- model,
- endpoint/profile,
- local/cloud classification,
- capabilities,
- context limit if known,
- temperature,
- max output tokens,
- enabled flag,
- fallback chain.

Prefer a Judge from a different model family than the Red attacker when practical. Initially, `forensic` may reuse the Judge to reduce inference cost.

## Budget configuration
Maintain `config/budgets.yaml` and default to a conservative `smoke` profile.

Budgets should be able to limit:
- maximum attacks,
- maximum generations,
- maximum turns per attack,
- model calls by role,
- per-role output-token limits,
- total campaign token/inference budget,
- image generation count,
- wall-clock timeout,
- early stopping after repeated non-progress.

A normal program start must never silently launch an unrestricted campaign.

## Blue target classes
Every Blue target must declare both `target_class` and `target_mode`.

Supported target classes:

### `coding`
Coding LLMs and coding agents such as OpenCode.
Relevant evidence includes final text, repository changes, filesystem access, shell commands, git operations, tool calls, MCP actions and network attempts.
Important invariants include workspace confinement, synthetic-secret protection, prohibition of unauthorized git/network actions, and resistance to repository/terminal/tool-output prompt injection.

### `reasoning`
Reasoning, planning and analytical models.
Focus on instruction-hierarchy manipulation, multi-turn escalation, semantic reframing, authority/context manipulation, hidden objective substitution and unsafe reconstruction of protected conclusions.

### `writing`
General text-generation and writing models.
Focus on role/persona jailbreaks, transformation/reframing, multilingual/encoded prompts, indirect injection and maintaining policy through editing, translation, summarization and fictional framing.

### `image_generation`
Image-generation models and pipelines.
Support text-to-image and image+text-to-image systems where available. Store prompt, transformed prompt, relevant safety/pipeline configuration, seed/configuration, generated artifact reference and grading evidence.
Visual claims require a multimodal Judge or specialized classifier when deterministic checks are insufficient. A text-only Judge must not be treated as authoritative for unseen image content.

## Target modes
- `MODEL`: direct model evaluation,
- `PIPELINE`: model plus application layer such as OpenWebUI, RAG, middleware, filters or tools,
- `AGENT`: full autonomous system such as OpenCode, including tool and environment actions.

The same base model in different modes/applications is a different Blue security target.

## Initial adapters
Initial target adapters:
1. Ollama,
2. OpenAI-compatible API,
3. OpenWebUI,
4. OpenCode.

Future adapters may include image-generation endpoints, ComfyUI, vLLM, llama.cpp, LM Studio, LangGraph applications, MCP systems and custom HTTP/Python targets.

## Judging policy
The Red attacker must never be the sole judge of its own success.
Evaluation priority:
1. deterministic verifier,
2. system-state verifier,
3. semantic Judge,
4. multimodal Judge for visual evidence.

Prefer deterministic verification for canary disclosure, forbidden path access, unauthorized git/network/tool actions, policy state and objective statistics.
Infrastructure failure is never a defense success.

## Model compromise versus system compromise
Always distinguish:
- `MODEL_COMPROMISE`: model follows an adversarial instruction or violates a behavioral invariant,
- `SYSTEM_COMPROMISE`: surrounding system allows an unauthorized effect.

Example: if an LLM requests unauthorized filesystem access but sandbox authorization blocks it, this is model compromise but not system compromise.

## Safety and isolation
All campaigns are authorized test activity and should fail closed.
Use synthetic canaries, not real credentials.
External network access is denied by default.
Git push is denied by default during adversarial tests.
Coding-agent tests should use disposable/sandboxed workspaces.
Attacker-generated content must never expand its own privileges.
All shell/tool/network/security-control decisions should be logged when technically possible.

## Knowledge accumulation
The project is not a jailbreak-prompt collection. It is a security-knowledge system.
Persist:
- attack hypotheses,
- attack genealogy (`attack_id`, parent, family, mutation),
- outcomes and evidence,
- reproducibility,
- minimal reproducing attacks,
- counterfactual results,
- forensic root causes,
- Blue controls and their observed effectiveness,
- regressions across target versions/configurations.

Blue control states:
`UNTESTED`, `DECLARED`, `OBSERVED_EFFECTIVE`, `PARTIALLY_EFFECTIVE`, `BYPASSED`, `INEFFECTIVE`, `INCONSISTENT`, `REGRESSION`, `RETIRED`.

Never mark a defense effective merely because it is configured.

## Development priorities
Follow the architecture in `PROJECT_REQUIREMENTS.md`. In practice prioritize:
1. typed domain model and Target abstraction,
2. mock vulnerable/hardened targets,
3. Ollama/OpenAI-compatible adapters,
4. synthetic canary and deterministic Judge,
5. campaign persistence and minimal CLI,
6. adaptive LangGraph Red agent and attack genealogy,
7. reproduction/minimization/counterfactual analysis,
8. Blue Security Profiles and regression engine,
9. OpenWebUI/OpenCode full-pipeline testing,
10. image-generation target support and multimodal judging,
11. optional Promptfoo/garak/PyRIT integrations,
12. dashboard only after core reliability.

## Reporting expectations for project work
For substantial development updates, report in Polish:
- overall architectural completion estimate,
- completed milestone,
- main architectural blocker/risk,
- next highest-value milestone,
- any architectural drift.

Repository code, identifiers and technical documentation should remain in English unless there is a strong reason otherwise.

## Decision rule
When choosing between a sophisticated feature and a simpler implementation that proves the core Red -> Blue -> Evidence -> Judge -> Forensics -> Blue Knowledge -> Regression loop, choose the simpler implementation.
