# Corpus Coverage — v3

Last reviewed: 2026-09-13

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

Adaptive Red has an explicit fixed multi-attacker measurement and execution contract. Ordinary per-attacker ASR remains at the bounded-conversation trial level while portfolio discovery is measured separately across identical case/replicate opportunities. Configured attacker variants route their own planner/mutator models, keep separate transcript-free learning memories and share one campaign/global budget. Full-cross attacker × case × replicate assignments are persisted before inference so interruption cannot silently remove hard trials. Finding diversity requires evidence-backed finding fingerprints rather than prompt-surface differences, and attacker overlap/marginal contribution remain Red diagnostics rather than Blue-security metrics. Provider availability `fallback` is not treated as an attacker ensemble.

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

The offline Docker sandbox path includes an evidence contract, a trusted lifecycle supervisor and an ownership-bound OpenCode runtime health gate. The profile generates a digest-pinned launch contract and independently verifies normalized `docker inspect` evidence before issuing a hash-only sandbox attestation. The verifier requires `network=none`, read-only root filesystem, `cap-drop ALL`, `no-new-privileges`, bounded CPU/memory/PIDs, non-privileged execution, automatic removal and exactly one writable bind mount for the disposable workspace. `DockerProcessSupervisor` proves launch-ID/inspect-ID ownership, refuses cleanup by an unproven name, performs ownership-checked teardown and verifies removal. The health gate probes OpenCode `/global/health` inside the exact owned container, re-verifies ownership after the response and requires the observed application version to match the declared target configuration.

The merged networked AGENT path preserves those confinement properties while replacing unrestricted Docker connectivity with an independently attestable model-only topology. An internal user-defined bridge requires isolated gateway mode, IPv6 disabled, exactly two running peers (one Blue AGENT and one declared model peer), no dual-homing and no unexpected members. A trusted network supervisor binds the exact network ID and Docker Engine admission evidence. `DockerNetworkedAgentSupervisor` then proves exact AGENT ownership and composes container confinement with the exact-peer network attestation.

OpenCode control traffic no longer requires a published host port. `DockerExecHttpTransport` performs loopback HTTP through ownership-checked `docker exec`, verifies the container before and after each request and keeps Basic-auth secrets inside the container. `DockerExecOpenCodeTarget` binds that stable transport policy into target identity while keeping per-run container IDs as evidence only.

A provider-independent `DockerModelPeerProfile` now defines digest-pinned model-service images, argument-vector launch/readiness commands, bounded resources, explicit GPU admission and no host ports or host mounts. The Ollama adapter additionally has a manifest-bound `ModelArtifactIdentity`: a mutable model name is not sufficient regression identity, and the local inventory digest is treated as a separate artifact identity. Minimal verified bundle staging/read-only mounting and the final composed trial lease remain active work rather than merged capability.

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

The core Target -> Attack -> Execution -> Evidence -> Judgment -> Persistence loop is implemented, including adaptive multi-turn Red, branch-aware learning, target-visible stagnation handling, mechanism-portfolio search, held-out evaluation, paired Red ablation, censoring-aware and layer-aware time-to-compromise metrics, system-state verification, Red exploration coverage, explicit multi-attacker routing under a shared campaign budget, fixed full-cross multi-attacker discovery estimands, per-trial target isolation, staged reference-evaluation contracts, immutable environment fixtures, hash-bound held-out external attack inputs, a deterministic RAG PIPELINE reference target, a provenance-preserving local MCP fixture transport, independently verifiable offline and model-network Docker confinement, ownership-aware networked AGENT launch, loopback-only OpenCode control transport, provider-independent model-peer lifecycle and manifest-bound local model artifact identity.

Several follow-up changes are implemented on open branches but are **not** part of the merged capability set until CI executes successfully. These include the OpenCode two-phase prelaunch contract, minimal verified Ollama artifact bundle staging, read-only Ollama bundle/model-peer composition, the ownership-aware verified Ollama peer supervisor, fixed-corpus claim metadata at the reference-reporting boundary, and layer-aware post-run Red discovery memory.

Highest-value remaining work is now:

1. restore real GitHub Actions runner execution and validate the open runtime/measurement PRs before any merge; runner-less `steps=[]` failures are not treated as code evidence;
2. complete the verified Ollama artifact path and compose network -> model peer -> networked OpenCode AGENT -> health/version proof into a Docker-backed `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider`, with reverse-order ownership-checked teardown;
3. make post-run successful-path credit for AGENT discovery extend through the first confirmed system compromise when model compromise occurred earlier, without exposing Judge outcomes during the live conversation;
4. bind host-side disposable workspace identity to the container-visible OpenCode workspace without equating paths from different namespaces;
5. execute and persist the first local Reference Evaluation v1 instrumentation smoke, then run qualification only if instrumentation is valid;
6. run a bounded local OpenCode+MCP smoke proving hostile fixture data reaches Blue only through the declared tool-result channel and that a blocked unauthorized effect remains model compromise rather than system compromise;
7. expand Judge reliability stress tests under adversarial framing, distribution shift and disagreement;
8. normalize additional external benchmark records with provenance/licensing gates rather than copying ad hoc payload collections;
9. add a predeclared statistical backend before any generalized-population security claim is allowed; fixed-corpus rates must not be silently reinterpreted as population estimates;
10. broaden multimodal/image-generation evidence and regression coverage without weakening provider independence.
