# Corpus Coverage — v1

Last reviewed: 2026-09-08

This document explains what the current corpus architecture covers and what remains intentionally external, gated, or deferred.

## Coverage model

Coverage is tracked across three independent axes:

1. **Target class** — `writing`, `reasoning`, `coding`, `image_generation`.
2. **Attack mechanism** — normalized project techniques, with MLCommons v0.7 crosswalk where applicable.
3. **Execution complexity** — T0 through T5.

A source count is not a security metric. Coverage is meaningful only when cases are normalized, executed under declared budgets, and graded with appropriate evidence.

## Writing

Covered source families:

- JailbreakBench / JailbreakBench Artifacts
- HarmBench
- StrongREJECT and StrongREJECT attacks
- WildJailbreak / WildTeaming (gated)
- Do-Not-Answer
- SORRY-Bench (gated unsafe split)
- XSTest controls
- SALAD-Bench
- Promptfoo strategy catalog
- BIPIA / CyberSecEval prompt-injection material
- MLCommons Jailbreak Attack Taxonomy v0.7

Mechanism coverage:

- direct override
- persona/role play
- static jailbreak templates
- perturbations
- encoding/obfuscation
- Unicode and hidden-content transformations
- semantic reframing
- wrappers/composition
- adaptive single-turn search
- optimized adversarial suffix/search families
- multi-turn Crescendo/GOAT/Hydra/Goblin
- indirect prompt injection

Utility/control coverage:

- benign control
- exaggerated-refusal / XSTest-style controls

## Reasoning

Includes all applicable writing-model coverage plus:

- H-CoT / Malicious-Educator
- PRJA 2026 reasoning-targeted research
- autonomous reasoning-model attacker research
- multi-turn/context-compliance tests
- provenance/memory/tool-context attacks for reasoning agents
- optional vision-capable reasoning attack families

Important distinction:

Reasoning-targeted techniques that alter hidden/displayed reasoning while preserving a final answer require evidence beyond final-answer-only scoring. The final implementation must record target-visible reasoning fields only when the provider exposes them legitimately; hidden chain-of-thought is not assumed available.

## Coding

Primary references:

- RepoGuardBench
- AgentDojo
- InjecAgent
- AgentDyn
- AgentInjectionBench
- PIArena/PISmith
- Agent Security Evaluation Kit
- AgentProv/PAB
- Agent Egress Bench
- AgentShield Benchmark
- BoundaryBench
- Promptfoo coding-agent plugins
- LivePI as explicit-opt-in research only

Mechanism/control coverage:

- repository prompt injection
- terminal-output injection
- tool-output injection
- MCP context/tool poisoning
- goal hijacking
- privilege escalation
- environment/file/procfs synthetic-secret access
- sandbox read/write escape
- network egress
- data-loss prevention
- memory poisoning
- provenance laundering
- generated vulnerabilities
- automation poisoning
- delayed CI effects
- steganographic exfiltration
- verifier sabotage
- session isolation

The corpus distinguishes model compromise from system compromise. A model requesting an unauthorized operation is not equivalent to the operation being executed.

## Image generation

Primary references:

- T2I-RiskyPrompt (AAAI 2026)
- T2ISafety (CVPR 2025)
- OVERT (NeurIPS D&B 2025)
- JailbreakDiffBench (ICCV 2025)
- SPQR (ECCV 2026)
- MMA-Diffusion (gated/restricted)
- JailBreakV-28K where cross-modal coverage is useful

Coverage axes:

- benign utility / over-refusal
- risky-prompt taxonomy
- prompt obfuscation
- semantic substitution
- jailbreak attack/defense evaluation
- prompt and image moderation robustness
- multimodal/cross-modal attacks
- post-benign-fine-tuning safety regression
- prompt adherence and image quality alongside safety

Visual compromise claims require a multimodal judge or specialized visual classifier. Text-only grading is insufficient for unseen image output.

## Standardized taxonomy

For single-turn prompt-only jailbreaks, MLCommons Jailbreak Attack Taxonomy v0.7 is the primary external mechanism crosswalk:

- 4 families
- 8 categories
- 18 leaf mechanisms
- 113 documented attacks

Its explicit exclusions — multi-turn attacks, indirect RAG/tool/file injection and non-text modalities — are handled by project-specific extensions rather than forced into incompatible labels.

## Cost-aware packs

- `smoke-v1` — zero Red-model inference and zero external dataset download.
- `baseline-v1` — small external/static baseline before adaptive Red.
- `comprehensive-v1` — staged broad coverage across all four target classes.
- `2026-extensions` — advanced reasoning, dynamic agent, provenance, egress and research-only external tracks.

## Intentional exclusions from default execution

The following are not silently enabled:

- gated datasets,
- real-service benchmarks,
- harmful-agent-capability suites,
- specialized optimization requiring significant compute,
- cloud-only adaptive strategies,
- image-generation tests without a visual grader,
- network egress tests without a local/authorized trap,
- any use of real credentials or production secrets.

## Remaining implementation work

The corpus registry and native fixtures exist, but external data is not yet normalized into executable project-native `AttackCase` objects. The next implementation milestone should therefore be:

1. typed `AttackCase`, `AttackSource`, `AttackTechnique`, `CorpusPack` models,
2. corpus validator,
3. native smoke loader,
4. deterministic canary detectors,
5. importers for the first low-risk sources,
6. only then real Blue model execution.
