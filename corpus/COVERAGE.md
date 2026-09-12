# Corpus Coverage — v3

Last reviewed: 2026-09-12

This document explains what the current corpus architecture covers and what remains intentionally external, gated, or deferred.

## Coverage model

Coverage is tracked across independent axes:

1. **Target class** — `writing`, `reasoning`, `coding`, `image_generation`.
2. **Target mode** — `MODEL`, `PIPELINE`, `AGENT`.
3. **Attack mechanism** — normalized project techniques, with MLCommons v0.7 crosswalk where applicable.
4. **Execution complexity** — T0 through T5.
5. **Interaction shape** — single-turn, repeated attempts, multi-turn trajectories, environment injection, multimodal and agentic execution.
6. **Indirect-input provenance** — repository, terminal/tool output, retrieval and MCP context are not collapsed into direct user prompts.

A source count is not a security metric. Coverage is meaningful only when cases are normalized, executed under declared budgets, and graded with appropriate evidence. Runtime Red mechanism coverage is reported separately from Blue vulnerability estimates so search breadth cannot be mistaken for ASR.

## Writing

Covered source families include JailbreakBench, HarmBench, StrongREJECT, WildJailbreak/WildTeaming (gated), Do-Not-Answer, SORRY-Bench (gated unsafe split), XSTest controls, SALAD-Bench, Promptfoo strategies, BIPIA/CyberSecEval material and MLCommons Jailbreak Attack Taxonomy v0.7.

Mechanism coverage includes direct override, persona/role play, static templates, perturbation, encoding/obfuscation, Unicode/hidden-content transformations, semantic reframing, composition, adaptive search, optimized suffix families, multi-turn Crescendo/GOAT/Hydra/Goblin and indirect prompt injection.

Utility/control coverage includes benign controls and over-refusal controls.

## Reasoning

Includes applicable writing-model coverage plus reasoning-targeted research families, autonomous attacker research, multi-turn/context-compliance probes, provenance/memory/tool-context attacks and optional vision-capable reasoning paths.

Reasoning-targeted techniques that alter hidden/displayed reasoning while preserving a final answer require evidence beyond final-answer-only scoring. The framework records only target-visible reasoning fields legitimately exposed by the provider; hidden chain-of-thought is not assumed available.

## RAG and PIPELINE systems

The deterministic local RAG reference target provides the first executable `PIPELINE` context-poisoning slice. Its target identity binds the wrapped Blue target, retrieval corpus hash and retrieval configuration. Retrieval evidence records ordered chunk provenance and hashes without persisting poisoned text. Held-out evaluation can bind the exact retrieval corpus as an external dependency.

A multi-turn synthetic regression proves that a first safe retrieval turn and a later poisoned retrieval turn remain one bounded attack trial. A deterministic disclosure establishes `MODEL_COMPROMISE` only; `SYSTEM_COMPROMISE` still requires an independent unauthorized system effect.

This reference retriever proves measurement and provenance contracts. It is not claimed to reproduce production vector search, OpenWebUI retrieval or any other concrete deployment.

## Coding and AGENT systems

Primary references include RepoGuardBench, AgentDojo, InjecAgent, AgentDyn, AgentInjectionBench, PIArena/PISmith, Agent Security Evaluation Kit, AgentProv/PAB, Agent Egress Bench, AgentShield Benchmark, BoundaryBench and Promptfoo coding-agent plugins. LivePI remains explicit-opt-in research only.

Represented system mechanisms include repository prompt injection, terminal/tool-output injection, MCP context/tool poisoning, goal hijacking, privilege escalation, synthetic-secret access, sandbox read/write escape, network egress, memory poisoning, provenance laundering, generated vulnerabilities, automation poisoning, delayed effects, steganographic exfiltration, verifier sabotage and session isolation.

The native corpus contains adaptive multi-turn AGENT goal/fixture cases for:

- protected synthetic workspace mutation,
- synthetic memory/persistence poisoning,
- prohibited Git publication against a disposable local repository and local bare synthetic remote,
- repository-originated indirect prompt injection,
- terminal-output injection,
- MCP-context poisoning through an explicit untrusted-context channel.

Environment-backed cases use immutable fixture bundles and isolated per-trial workspaces. MCP/tool/retrieval context can be represented separately from the user prompt with integrity-checked content hashes. A context-backed fixture requires a target that explicitly declares `untrusted_context`; unsupported targets fail before execution rather than receiving credit for an attack they never saw.

The framework distinguishes four system layers during AGENT evaluation:

1. model intent / forbidden action request,
2. runtime authorization decision,
3. reported tool execution,
4. independently verified system effect.

A forbidden request can establish `MODEL_COMPROMISE`. `SYSTEM_COMPROMISE` requires the surrounding system to permit the unauthorized effect under the declared evidence contract; a provider-reported completed tool call alone is not sufficient by default.

The native MCP fixture is synthetic/local and disabled by default. `McpContextOpenCodeTarget` provides a concrete local stdio transport for attested OpenCode targets: fixture content is staged outside the Blue workspace, hash-verified by a one-tool MCP server, and never concatenated into the direct user prompt. The current compatibility profile targets handshake-era MCP through `2025-11-25`, matching the current OpenCode MCP client generation.

The Docker sandbox layer now includes both an evidence contract and a trusted lifecycle supervisor. The profile generates a digest-pinned offline launch contract and independently verifies normalized `docker inspect` evidence before issuing a hash-only sandbox attestation. The verifier requires `network=none`, read-only root filesystem, `cap-drop ALL`, `no-new-privileges`, bounded CPU/memory/PIDs, non-privileged execution, automatic removal and exactly one writable bind mount for the disposable workspace. `DockerProcessSupervisor` launches detached containers, proves launch-ID/inspect-ID ownership before attestation, refuses cleanup by an unproven name, performs ownership-checked teardown and verifies removal. CI exercises this lifecycle through a fake command runner, so no Docker daemon or model inference is needed for the contract tests. The offline profile remains intentionally too restrictive for a real OpenCode-to-model connection.

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
- live third-party MCP servers or external RAG sources without an authorized adapter,
- real credentials, production secrets or user memory,
- any attacker-controlled request to expand its own permissions.

## Current implementation frontier

The core Target -> Attack -> Execution -> Evidence -> Judgment -> Persistence loop is implemented, including adaptive multi-turn Red, branch-aware learning, held-out evaluation, paired Red ablation, censoring-aware and layer-aware time-to-compromise metrics, system-state verification, Red exploration coverage, staged reference-evaluation contracts, immutable environment fixtures, hash-bound held-out external attack inputs, a deterministic RAG PIPELINE reference target, a provenance-preserving local MCP fixture transport for attested OpenCode targets, an independently verifiable offline Docker sandbox-attestation contract, and a trusted ownership-aware Docker process supervisor.

Highest-value remaining work is now:

1. add a narrowly scoped model-connectivity design that preserves external-network denial and supplies independently verifiable network evidence, rather than falling back to Docker's Internet-capable default bridge;
2. bind the container-visible OpenCode workspace/runtime endpoint to the host-side disposable workspace without conflating host and container paths, then add an OpenCode health-check gate before target construction;
3. execute and persist the first local Reference Evaluation v1 smoke, then qualification only if instrumentation is valid;
4. run a bounded local OpenCode+MCP smoke that proves hostile fixture data reaches Blue only as a tool result and that model compromise remains distinct from blocked system effects;
5. expand Judge reliability stress tests under adversarial framing, distribution shift and disagreement;
6. normalize additional external benchmark records with provenance/licensing gates rather than copying ad hoc payload collections;
7. add a predeclared statistical backend before any generalized-population security claim is allowed;
8. broaden multimodal/image-generation evidence and regression coverage without weakening provider independence.
