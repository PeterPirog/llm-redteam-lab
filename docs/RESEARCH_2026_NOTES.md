# 2026 Adaptive Red Research Notes

Status: implementation guidance, not architectural source of truth
Last verified: 2026-09-10

The following public sources materially influence the adaptive Red design. They are references for methodology, not dependencies and not automatic payload sources.

## Promptfoo Hydra

Current Hydra documentation describes a multi-turn attacker that adapts to target responses, keeps structured/persistent learning, supports replay and target-managed sessions, and can branch/backtrack when a direct path fails.

Project implication:

- preserve explicit replay versus target-managed session semantics,
- keep branching/backtracking observable,
- allow learning across conversations,
- do not make Promptfoo Cloud a required dependency of the native Red core.

Reference: https://www.promptfoo.dev/docs/red-team/strategies/hydra/

## MT-JailBench — 2026 modular multi-turn evaluation

MT-JailBench decomposes a multi-turn jailbreak into five interacting modules: evaluation function, attack strategy, prompt generation, prompt refinement and flow control. Its results show that turn/query budgets, retry rules and evaluators are major confounders and can materially change attack rankings. It also reports that prompt generation explains much of the observed variation while refinement and flow control provide smaller but still material gains.

Project implication:

- never compare Red strategies under different budgets or Judge configurations,
- persist attack strategy, prompt-generation/refinement and flow-control identities separately,
- treat one complete conversation as the security trial while turns/retries are resource observations,
- use paired held-out component ablations before promoting a more complex Red policy,
- retain a simple stochastic/fixed-strategy baseline because complexity alone does not prove stronger discovery.

Reference: https://arxiv.org/abs/2605.11002

## RAMP — ACL Findings 2026

RAMP formulates multi-turn jailbreak red-teaming as a state-action planning problem and emphasizes the trade-off between attack success and query overhead. It reports that multi-step planning, clue accumulation and consistency across evaluator settings are important contributors.

Project implication:

- model the next Red move as a decision over observed state,
- retain explicit turn/query cost,
- preserve useful bounded observations across turns without granting them authorization authority,
- compare attacker effectiveness under identical budgets,
- avoid treating high success obtained with unbounded queries as directly comparable to bounded results.

Reference: https://aclanthology.org/2026.findings-acl.925/

## PLAGUE — ICLR 2026

PLAGUE divides multi-turn attack lifetime into Primer, Planner and Finisher phases and uses lifelong-learning ideas to improve future attacks.

Project implication:

- use explicit phase information in adaptive planning,
- retain compact learning across attacks,
- keep phase transitions outside model authority in the first implementation.

Reference: https://proceedings.iclr.cc/paper_files/paper/2026/hash/823e43f5537d8c1894afd1f6ab00a927-Abstract-Conference.html

## NIST TEVV-Athlon — NIST AI 200-2 initial public draft

NIST's 2026 draft describes a flexible four-stage TEVV framework intended to support statistical ML, LLM, multimodal and agentic systems and emphasizes assessment methods customized to the actual measurement objective and context.

Project implication:

- record experimental conditions and target identity,
- keep metric definitions/versioning explicit,
- distinguish evaluation events, tools, evidence and measurement concepts,
- avoid unsupported claims of general security from one benchmark,
- preserve extensibility across MODEL, PIPELINE and AGENT modes.

Reference: https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems

## NIST AITE — sequestered evaluation

NIST announced the Artificial Intelligence Technology Evaluation (AITE) in 2026 as a sequestered testbed using blind data to reduce train/test contamination and support objective evaluation across datasets, modalities and domains.

Project implication:

- keep adaptive DISCOVERY separate from comparative EVALUATION,
- support a SEQUESTERED evaluation-set exposure class,
- prevent Red from observing evaluation content during discovery,
- bind reported comparative metrics to a frozen policy and exact evaluation manifest.

Reference: https://www.nist.gov/news-events/news/2026/07/announcing-nists-artificial-intelligence-technology-evaluation-aite

## OWASP Agent Control Standard — September 2026

The OWASP Agent Control Standard (ACS) states that agents should be inspectable, traceable and instrumentable and that runtime behavior should be controllable through enforceable middleware/policy hooks.

Project implication:

- record tool request, authorization decision, execution status and independently observed post-state as separate facts,
- never infer SYSTEM_COMPROMISE solely from model prose or a provider completion flag,
- keep authorization and sandbox policy outside attacker-controlled content,
- expose explicit agent permission changes at campaign preflight.

Reference: https://genai.owasp.org/resource/agent-control-standard-acs/

## MITRE ATLAS — current agentic attack surface

MITRE ATLAS is a living knowledge base and now exposes first-class Agentic AI techniques including AI Agent Tool Invocation, AI Agent Context Poisoning, AI Agent Tool Data Poisoning, AI Agent Tool Poisoning and Modify AI Agent Configuration alongside LLM Prompt Injection, LLM Jailbreak, RAG Poisoning and Escape to Host.

Project implication:

- maintain target-visible context, tools, memory and configuration as distinct attack surfaces,
- collect evidence for tool and context attacks even when the model is contained,
- keep ATLAS identifiers as versioned report mappings rather than hard-coded security truth.

Reference: https://atlas.mitre.org/

## Design rule

These sources justify stronger adaptive and agentic testing, but external framework behavior must not redefine project security semantics. `PROJECT_REQUIREMENTS.md` remains authoritative. Native code must continue to distinguish MODEL_COMPROMISE and SYSTEM_COMPROMISE, fail closed, use synthetic canaries, keep model-controlled text outside authorization/budget control, and separate vulnerability discovery from comparative measurement.
