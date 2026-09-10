# Research update — 2026-09-10

This note records external evidence used to guide the next implementation milestones. It is not an architectural source of truth; `PROJECT_REQUIREMENTS.md` remains authoritative.

## Multi-turn Red

- **MT-JailBench (2026)**: multi-turn jailbreak rankings are materially confounded by turn/interactions budgets, retry rules, judges, prompt generation/refinement and flow control. Component comparisons should therefore freeze external conditions and report resource use separately from success.
- **RAMP (ACL Findings 2026)**: explicit multi-step planning, dialogue-state representation, mechanism composition and clue/evidence accumulation can improve bounded multi-turn red-teaming efficiency.
- **MultiBreak (2026)**: diverse multi-turn trajectories expose vulnerabilities that can be missed by single-turn evaluation, reinforcing the need for multi-turn cases as first-class statistical trials rather than counting each turn as a separate trial.

## Judge reliability

- **How Reliable Is Your Jailbreak Judge? (2026)** and **A Coin Flip for Safety (2026)** show that LLM-as-a-Judge measurements can suffer distribution-shift, framing and adversarial robustness failures. Judge identity must therefore be part of measurement provenance, abstentions/unresolved outcomes must not be counted as defensive success, and the laboratory should add a calibration/stress-test layer before treating semantic Judge output as a high-confidence measurement instrument.
- **Validity-Aware Jailbreak Evaluation (2026)** argues that semantically plausible but invalid or non-operational outputs can be false positives. For agentic/system targets, deterministic and post-state verification therefore remain authoritative over semantic plausibility.

## Standards

- **NIST AI 200-2 IPD, TEVV-Athlon (2026)** emphasizes customizable, evidence-producing TEVV matched to the system and measurement concept, including LLM, multimodal and agentic systems.
- **OWASP Agent Control Standard (2026)** emphasizes inspectability, traceability, instrumentability and runtime control boundaries for agents.

## Implementation consequences

1. Keep one complete multi-turn conversation as one Blue trial; turns/backtracks/branches are resource and Red-search units.
2. Persist/fingerprint the exact Red strategy, Red model-role configuration, flow-control budget and starting learning-memory state for evaluation.
3. Freeze cross-trial Red learning in held-out EVALUATION while allowing adaptation inside a bounded conversation.
4. Retain `MODEL_COMPROMISE` vs `SYSTEM_COMPROMISE`; semantic evidence alone must not create a system-effect claim.
5. Add Judge calibration/stress-test metrics as a separate measurement-instrument quality layer rather than folding Judge uncertainty into ASR silently.
