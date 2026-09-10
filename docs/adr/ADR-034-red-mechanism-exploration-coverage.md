# ADR-034 — Measure Red Mechanism Exploration Separately from Blue Vulnerability

Status: Accepted
Date: 2026-09-10

## Context

The project already distinguishes Blue vulnerability metrics from Red search metrics and
implements mechanism-aware adaptive multi-turn strategies. However, a discovery policy
can still converge on one locally productive mechanism. A high observed attack yield does
not prove that the attacker explored the attack surface broadly enough to support later
claims about Red capability or benchmark coverage.

The repository also contains a broad project technique taxonomy in `corpus/techniques.yaml`.
That corpus taxonomy describes what can be represented by the laboratory. Runtime
`AttackMechanism` labels describe what a mechanism-aware multi-turn Red strategy actually
tries while attacking a target. These are related but different layers and must not be
silently collapsed.

Current external methodology reinforces this distinction:

- MLCommons Jailbreak Taxonomy v0.7 uses a mechanism-first taxonomy rather than prompt
  volume as the foundation for reproducible jailbreak benchmarking.
- OWASP's 2026 AI/Agentic Red Teaming taxonomy treats coverage as a set of lifecycle
  capabilities that should support gap analysis and repeatable evaluation.
- MT-JailBench shows that multi-turn results depend materially on budgets, strategy,
  refinement, flow control and evaluation choices, so attack coverage cannot be inferred
  from one aggregate success rate.

## Decision

Add a transcript-free Red mechanism exploration coverage layer for DISCOVERY diagnostics.

For every mechanism structurally eligible under the active session and conversation
budget, the framework records:

- conversations in which the mechanism was observed at least once,
- conversations in which that mechanism lay on a successful path,
- a Wilson summary of observed success among those conversation exposures,
- share of total mechanism-exposure mass,
- whether the mechanism is unobserved, observed, or has an observed success.

Across mechanisms, the framework additionally reports:

- fraction of eligible mechanisms observed,
- fraction with at least one observed success,
- normalized exposure entropy,
- effective mechanism count derived from Shannon entropy,
- maximum single-mechanism exposure share,
- number of observed transition signatures,
- number of observed sequence signatures.

One conversation may expose several mechanisms. Therefore mechanism-exposure counts may
sum above the number of conversations and are not an ASR denominator.

## Predeclared exploration readiness

`RedCoveragePolicy` can define, before interpreting a discovery run:

- required mechanisms,
- minimum conversation exposures per required mechanism,
- optional maximum single-mechanism exposure share,
- optional minimum normalized exposure entropy,
- optional minimum transition diversity,
- optional minimum sequence diversity.

The resulting status is `READY`, `INCOMPLETE`, or `NO_EVIDENCE`.

This status means only that Red exploration supplied the requested breadth for a later
controlled experiment. It never means that Blue is safe or vulnerable.

## Eligibility is structural

Branch diversification is considered eligible only when replay semantics and the
conversation budget permit branching/backtracking. It is not counted as a blind spot in a
`TARGET_MANAGED` session that cannot replay alternate branches.

Other mechanism availability remains explicit and versionable through the Red runtime.

## Statistical interpretation

Coverage and concentration diagnostics are descriptive properties of the observed Red
search process. They are not population estimates, not comparative Blue metrics, and not
substitutes for held-out paired ablation.

A mechanism-specific Wilson interval describes repeated conversation exposures under the
observed discovery process. Adaptive selection means it must not be presented as an
unbiased estimate of a target's vulnerability to that mechanism.

The production object therefore carries `comparable_blue_estimate = false`.

## Relationship to evaluation

DISCOVERY may use cross-trial learning and mechanism coverage to discover promising attack
hypotheses. EVALUATION remains frozen across trials and continues to use the held-out
measurement contract.

A more complex Red policy still earns promotion only through a controlled paired
comparison and the existing `RedPolicyQualificationPolicy`. Broad discovery coverage is a
readiness/gap-analysis signal, not evidence of superiority.

## Consequences

Positive:

- local-optimum collapse becomes visible,
- multi-turn mechanism breadth is measurable rather than documentary,
- sequence and transition diversity can be predeclared as discovery requirements,
- target-managed sessions are not unfairly penalized for impossible branching,
- coverage cannot silently become a Blue safety score.

Trade-offs:

- coverage currently reflects mechanism-aware DISCOVERY memory, not frozen EVALUATION
  traces,
- a future evaluation-trace layer should record the exact mechanism path independently of
  learning memory,
- mechanism diversity does not guarantee useful or semantically distinct prompts and must
  be interpreted together with effectiveness and novelty diagnostics.

## Architectural alignment

This decision strengthens the required adaptive Red loop, attack genealogy/coverage,
measurement credibility and later Red-vs-Blue knowledge accumulation without weakening
budget controls, target isolation, or the `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE`
distinction.
