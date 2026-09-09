# ADR-013 — Evidence-derived Blue security knowledge

- Status: Accepted
- Date: 2026-09-09

## Context

The project must accumulate defensible knowledge about why Blue controls work or fail.
A simple inventory of configured controls is insufficient: a target PASS does not prove
that a particular control caused the block, and an LLM statement that a sandbox or policy
was effective is not equivalent to observed control behavior.

This distinction matters especially for agentic systems. One agent execution can contain
many authorization, sandbox, guardrail or tool events. A single execution may therefore
contain both blocked and bypassed actions without those observations being logically
contradictory.

Current guidance supports an evidence-first design:

- OWASP Agent Control Standard (2026-09-01) emphasizes inspectable, traceable and
  instrumentable agents, visibility into what they accessed/did, and runtime control
  hooks: https://genai.owasp.org/resource/agent-control-standard-acs/
- NIST AI 200-2 initial public draft (TEVV-Athlon, 2026-08) is designed as an adaptable
  TEVV framework spanning LLM, multimodal and agentic systems and emphasizes explicit
  evaluation context and evidence: https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems
- OpenTelemetry GenAI semantic conventions expose one agent invocation with child LLM and
  tool operations, reinforcing the distinction between agent-run outcomes and individual
  control/tool events: https://opentelemetry.io/blog/2026/genai-observability/

## Decision

### 1. Blue control state is derived, not asserted

Required states are preserved exactly:

```text
UNTESTED
DECLARED
OBSERVED_EFFECTIVE
PARTIALLY_EFFECTIVE
BYPASSED
INEFFECTIVE
INCONSISTENT
REGRESSION
RETIRED
```

The current state is computed from persisted observations for one control, target snapshot
and attack family. It is not stored as an unqualified mutable label.

### 2. A PASS is not evidence that a control worked

`PRESENT_NO_ATTRIBUTION` records that a control existed during an execution without
claiming causality. Such observations do not enter the effectiveness denominator and do
not move a control from `DECLARED` to `OBSERVED_EFFECTIVE`.

A direct effectiveness claim requires one of:

```text
BLOCKED_BY_CONTROL
BYPASSED_CONTROL
CONTROL_TRIGGERED_NO_EFFECT
```

and must identify a concrete `control_event_id` plus supporting evidence references.

### 3. Only directly verified evidence changes effectiveness state

Evidence sources are separated into:

```text
SYSTEM_STATE
DETERMINISTIC_VERIFIER
SEMANTIC_FORENSIC
```

Only `SYSTEM_STATE` and `DETERMINISTIC_VERIFIER` observations are authoritative for state
transitions. Semantic forensic observations remain useful supporting context but cannot,
by themselves, establish that a control blocked or failed to block an attack.

This prevents an LLM from becoming the authority for Blue control effectiveness.

### 4. Authoritative references must resolve to execution evidence

When an authoritative observation is persisted, every evidence reference must resolve to
an `EvidenceRow` belonging to the same execution. The observation must also match:

- target snapshot,
- attack family,
- persisted execution,
- experiment fingerprint.

Any mismatch fails closed.

### 5. Control-event metrics are distinct from attack metrics

The Blue knowledge layer reports a `block_event_rate` over directly attributed control
events with a Wilson confidence interval.

This is deliberately NOT campaign ASR. One multi-turn/agent execution remains one attack
trial for ASR even if it contains many control events.

The assessment therefore reports both:

```text
authoritative_events
affected_executions
direct_blocks
bypasses
ineffective_events
block_event_rate + Wilson interval
```

Unattributed, unresolved and semantic observations are counted separately and excluded
from the direct-event denominator.

Per-event Wilson intervals are descriptive for enforcement opportunities and must not be
presented as independence-adjusted confidence for correlated events within one agent run.
A future clustered/run-level estimate can be added when enough real agent data exists.

### 6. State derivation is deterministic

For authoritative direct observations:

- only blocks -> `OBSERVED_EFFECTIVE`,
- blocks plus failures/bypasses -> `PARTIALLY_EFFECTIVE`,
- only bypass observations -> `BYPASSED`,
- only triggered-no-effect observations -> `INEFFECTIVE`,
- contradictory outcomes for the same `control_event_id` -> `INCONSISTENT`.

Different control events within the same execution may legitimately have different
outcomes and are not automatically inconsistent.

### 7. Regression is cross-snapshot evidence

`REGRESSION` is derived when the same control and attack family was previously
`OBSERVED_EFFECTIVE` on a different target snapshot and is now directly `BYPASSED` or
`INEFFECTIVE`.

A newly observed bypass on the same snapshot does not become a version regression merely
because an earlier subset of observations was successful.

### 8. Coverage matrices remain quantitative

The initial Blue-vs-Red coverage matrix exposes per-control/per-attack-family state,
evidence counts, event block rate and confidence interval. It does not convert sparse data
into subjective `HIGH/MED/LOW` labels.

MITRE ATLAS, OWASP and other taxonomy mappings may be added as downstream metadata, but a
mapping is not evidence that a control works.

## Consequences

Positive consequences:

- Blue claims remain auditable to concrete experiment evidence,
- semantic Forensic Analyst output cannot silently inflate defense effectiveness,
- multi-turn and agentic control events are represented at the correct granularity,
- ASR denominators remain independent from tool/control event counts,
- control regressions can be tracked across configuration snapshots,
- sparse evidence is represented honestly with explicit uncertainty.

Costs and limitations:

- adapters must emit stable control event identifiers for strongest attribution,
- control-event observations within one agent execution can be statistically correlated,
- current regression comparison assumes callers compare semantically equivalent control
  definitions across target snapshots,
- a future control-lineage identifier should make cross-version equivalence explicit,
- automated regression replay still requires a policy-controlled minimal reproducer
  artifact store containing executable attack content.

## Follow-on

The next milestone is the regression engine and controlled reproducer artifact store. It
must replay confirmed minimal attacks against new target snapshots and distinguish:

- security regression,
- security improvement,
- unchanged model compromise with successful system containment,
- model-to-system escalation,
- incomparable experiment configurations.
