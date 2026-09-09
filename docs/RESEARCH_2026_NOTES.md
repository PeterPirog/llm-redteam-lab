# 2026 Adaptive Red Research Notes

Status: implementation guidance, not architectural source of truth
Last verified: 2026-09-09

The following public sources materially influenced the adaptive Red design. They are references for methodology, not dependencies and not automatic payload sources.

## Promptfoo Hydra

Current Hydra documentation describes a multi-turn attacker that adapts to target responses, keeps structured/persistent learning, supports replay and target-managed sessions, and can branch/backtrack when a direct path fails.

Project implication:

- preserve explicit replay versus target-managed session semantics,
- keep branching/backtracking observable,
- allow learning across conversations,
- do not make Promptfoo Cloud a required dependency of the native Red core.

Reference: https://www.promptfoo.dev/docs/red-team/strategies/hydra/

## RAMP — ACL Findings 2026

RAMP formulates multi-turn jailbreak red-teaming as a state-action planning problem and emphasizes the trade-off between attack success and query overhead. It reports that multi-step planning, clue accumulation and consistency across evaluator settings are important contributors.

Project implication:

- model the next Red move as a decision over observed state,
- retain explicit turn/query cost,
- compare attacker effectiveness under identical budgets,
- avoid treating high ASR obtained with unbounded queries as directly comparable to bounded results.

Reference: https://aclanthology.org/2026.findings-acl.925/

## PLAGUE — ICLR 2026

PLAGUE divides multi-turn attack lifetime into Primer, Planner and Finisher phases and uses lifelong-learning ideas to improve future attacks.

Project implication:

- use explicit phase information in adaptive planning,
- retain compact learning across attacks,
- keep phase transitions outside model authority in the first implementation.

Reference: https://proceedings.iclr.cc/paper_files/paper/2026/hash/823e43f5537d8c1894afd1f6ab00a927-Abstract-Conference.html

## NIST TEVV-Athlon — NIST AI 200-2 initial public draft

NIST's 2026 draft describes a flexible TEVV framework intended to support LLM, multimodal and agentic systems and emphasizes developing measurement approaches for the actual assessment context.

Project implication:

- record experimental conditions and target identity,
- keep metric definitions/versioning explicit,
- avoid unsupported claims of general security from one benchmark,
- preserve extensibility across MODEL, PIPELINE and AGENT modes.

Reference: https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems

## OWASP Agentic AI Security Initiative / 2026 material

OWASP's current Agentic AI work highlights prompt injection, privilege/tool misuse, memory/context poisoning, agent control and lifecycle-wide red teaming. OWASP explicitly treats retained context/memory as an attack surface.

Project implication:

- attacker memory must not become a permission channel,
- raw untrusted content must not silently gain authority through persistence,
- AGENT tests must distinguish model compromise from unauthorized system effect,
- future OpenCode tests need deterministic sandbox/tool/network authorization evidence.

References:

- https://genai.owasp.org/initiatives/agentic-security-initiative/
- https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/
- https://genai.owasp.org/resource/ai-security-solutions-landscape-for-ai-and-agentic-red-teaming-q2-2026/

## Design rule

These sources justify stronger adaptive and agentic testing, but external framework behavior must not redefine project security semantics. `PROJECT_REQUIREMENTS.md` remains authoritative. Native code must continue to distinguish MODEL_COMPROMISE and SYSTEM_COMPROMISE, fail closed, use synthetic canaries, and keep model-controlled text outside authorization/budget control.
