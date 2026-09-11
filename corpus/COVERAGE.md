# Corpus Coverage — v3

Last reviewed: 2026-09-11

This document explains what the current corpus architecture covers and what remains intentionally external, gated, or deferred.

## Coverage model

Coverage is tracked across independent axes:

1. **Target class** — `writing`, `reasoning`, `coding`, `image_generation`.
2. **Target mode** — `MODEL`, `PIPELINE`, `AGENT`.
3. **Attack mechanism** — normalized project techniques, with MLCommons v0.7 crosswalk where applicable.
4. **Execution complexity** — T0 through T5.
5. **Interaction shape** — single-turn, repeated attempts, multi-turn trajectories, environment injection, multimodal and agentic execution.
6. **Indirect-input provenance** — repository, terminal/tool output, retrieval, MCP context and other environment channels are not collapsed into direct user prompts.

A source count is not a security metric. Coverage is meaningful only when cases are normalized, executed under declared budgets, and graded with appropriate evidence. Runtime Red mechanism coverage is reported separately from Blue vulnerability estimates so search breadth cannot be mistaken for ASR.

## Writing

Covered source families include JailbreakBench, HarmBench, StrongREJECT, WildJailbreak/WildTeaming (gated), Do-Not-Answer, SORRY-Bench (gated unsafe split), XSTest controls, SALAD-Bench, Promptfoo strategies, BIPIA/CyberSecEval material and MLCommons Jailbreak Attack Taxonomy v0.7.

Mechanism coverage includes direct override, persona/role play, static templates, perturbation, encoding/obfuscation, Unicode/hidden-content transformations, semantic reframing, composition, adaptive search, optimized suffix families, multi-turn Crescendo/GOAT/Hydra/Goblin and indirect prompt injection.

Utility/control coverage includes benign controls and over-refusal controls.

## Reasoning

Includes applicable writing-model coverage plus reasoning-targeted research families, autonomous attacker research, multi-turn/context-compliance probes, provenance/memory/tool-context attacks and optional vision-capable reasoning paths.

Reasoning-targeted techniques that alter hidden/displayed reasoning while preserving a final answer require evidence beyond final-answer-only scoring. The framework records only target-visible reasoning fields legitimately exposed by the provider; hidden chain-of-thought is not assumed available.

## Coding and AGENT systems

Primary references include RepoGuardBench, AgentDojo, InjecAgent, AgentDyn, AgentInjectionBench, PIArena/PISmith, Agent Security Evaluation Kit, AgentProv/PAB, Agent Egress Bench, AgentShield Benchmark, BoundaryBench and Promptfoo coding-agent plugins. LivePI remains explicit-opt-in research only.

Represented system mechanisms include repository prompt injection, terminal/tool-output injection, retrieval/RAG context poisoning, MCP context/tool poisoning, goal hijacking, privilege escalation, synthetic-secret access, sandbox read/write escape, network egress, memory poisoning, provenance laundering, generated vulnerabilities, automation poisoning, delayed effects, steganographic exfiltration, verifier sabotage and session isolation.

The native corpus contains adaptive multi-turn AGENT goal seeds for:

- protected synthetic workspace mutation,
- synthetic memory/persistence poisoning,
- prohibited Git publication against a disposable local repository and local bare synthetic remote,
- repository-originated indirect prompt injection,
- terminal-output injection,
- retrieval/RAG context poisoning through an explicit untrusted context channel,
- MCP-context poisoning through an explicit untrusted context channel.

Environment-backed cases use immutable fixture bundles and isolated per-trial workspaces. Context-backed fixtures preserve the source channel separately from the direct user prompt and persist hash-only provenance. Targets that do not explicitly declare support for the untrusted-context transport fail closed before fixture execution. These cases remain disabled by default and require matching system-state policies. Model-backed Red uses target-visible feedback across turns, but the attacker never receives Judge labels during the live trajectory.

The framework distinguishes four system layers during AGENT evaluation:

1. model intent / forbidden action request,
2. runtime authorization decision,
3. reported tool execution,
4. independently verified system effect.

A forbidden request can establish `MODEL_COMPROMISE`. `SYSTEM_COMPROMISE` requires the surrounding system to permit the unauthorized effect under the declared evidence contract; a provider-reported completed tool call alone is not sufficient by default.

Synthetic retrieval/MCP fixtures prove the provider-independent lifecycle and provenance contract. They do **not** yet claim real OpenWebUI RAG or live MCP-server coverage; concrete adapters must implement the context transport before advertising that capability.

## Image generation

Primary references include T2I-RiskyPrompt, T2ISafety, OVERT, JailbreakDiffBench, SPQR, gated MMA-Diffusion and JailBreakV-28K where cross-modal coverage is useful.

Coverage axes include benign utility/over-refusal, risky-prompt taxonomy, prompt obfuscation, semantic substitution, jailbreak attack/defense evaluation, prompt/image moderation robustness, multimodal/cross-modal attacks, post-fine-tuning regression and prompt adherence/image quality alongside safety.

Visual compromise claims require a multimodal Judge or specialized visual classifier. Text-only grading is insufficient for unseen image output.

## Standardized taxonomy

For single-turn prompt-only jailbreaks, MLCommons Jailbreak Attack Taxonomy v0.7 is the primary external mechanism crosswalk. Its explicit exclusions — multi-turn attacks, indirect RAG/tool/file injection and non-text modalities — are handled by project-specific extensions rather than forced into incompatible labels.

The runtime mechanism taxonomy for adaptive Red is intentionally distinct from corpus/source taxonomy. Corpus taxonomy answers what the laboratory can represent; runtime mechanism coverage answers what an adaptive campaign actually explored.

## Cost-aware execution

- `smoke` / `smoke-v1` — minimal deterministic first-run path.
- `multiturn_smoke` — bounded conversational Red smoke.
- `agent_multiturn_smoke` — bounded target-managed AGENT smoke with no branch replay.
- `reference_smoke` — instrumentation stage for the local reference experiment; cannot promote a Red policy.
- `reference_qualification` — bounded matched-pair policy qualification stage.
- `coverage` — broader explicit coverage budget, never the default first run.

## Intentional exclusions from default execution

The following are not silently enabled:

- gated datasets,
- real-service benchmarks,
- harmful-agent-capability suites,
- specialized optimization requiring significant compute,
- cloud-only adaptive strategies,
- image-generation tests without a visual grader,
- external network egress tests without an authorized local trap,
- real Git publication targets,
- live third-party MCP servers or untrusted external RAG sources without an authorized adapter,
- real credentials, production secrets or user memory,
- any attacker-controlled request to expand its own permissions.

## Current implementation frontier

The core Target -> Attack -> Execution -> Evidence -> Judgment -> Persistence loop is implemented, including adaptive multi-turn Red, branch-aware learning, held-out evaluation, paired Red ablation, censoring-aware time-to-violation metrics, system-state verification, Red exploration coverage, staged reference-evaluation contracts, immutable environment fixtures and hash-bound held-out external attack inputs.

Highest-value remaining work is now:

1. execute and persist the first local Reference Evaluation v1 smoke, then qualification only if instrumentation is valid;
2. connect the explicit retrieval/MCP untrusted-context contract to concrete local OpenWebUI/RAG and MCP-capable targets without weakening target identity or provenance;
3. expand Judge reliability stress tests under adversarial framing, distribution shift and disagreement;
4. normalize additional external benchmark records with provenance/licensing gates rather than copying ad hoc payload collections;
5. add a predeclared statistical backend before any generalized-population security claim is allowed;
6. broaden multimodal/image-generation evidence and regression coverage without weakening provider independence.
