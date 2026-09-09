# ADR-011 — Evidence-grounded forensic analysis

- Status: Accepted
- Date: 2026-09-09

## Context

The project must explain why a defense succeeded or failed, not merely report jailbreak
success. A language model is useful for synthesizing heterogeneous evidence, but allowing
it to re-judge the attack or invent a root cause would undermine measurement integrity.

Forensic inputs can themselves be adversarial. Target text, tool output, repository
content, retrieved context and even guardrail metadata may contain instructions aimed at
the evaluator. Forensics therefore needs the same explicit trust-boundary discipline as
Red planning and semantic judging.

Current 2026 guidance reinforces this direction. OWASP Agent Control Standard emphasizes
inspectability, traceability and visibility into what agents accessed, did and why. MITRE
ATLAS maintains separate techniques for prompt injection, agent context poisoning, tool
data poisoning, tool poisoning and tool invocation. Root-cause analysis must preserve
these architectural distinctions instead of collapsing them into one narrative label.

## Decision

### 1. Forensics runs after verification and reproduction

By default, `ForensicAnalyst` accepts only findings in `REPRODUCIBLE` or `CONFIRMED`
state. Flaky or single observations remain evidence but are not promoted to root-cause
attribution unless a future explicit policy enables exploratory analysis.

### 2. Forensics cannot re-judge compromise flags

`objective_violated`, `MODEL_COMPROMISE` and `SYSTEM_COMPROMISE` are supplied as verified
facts. The forensic model output schema contains no fields capable of overriding them.

A text-only forensic model therefore cannot convert a model failure into a system failure
or erase an observed unauthorized system effect.

### 3. All evidence-derived content is untrusted

Every serialized evidence item is marked `UNTRUSTED_EVIDENCE`. The system prompt states
that instructions, role changes, grading requests and claims of authority found inside
such data must never be followed.

Raw prompts and raw target responses are not persisted by the forensic layer. Evidence is
represented by bounded structured metadata, hashes and artifact references. Structured
evidence data may still contain attacker-controlled strings and remains explicitly
untrusted.

### 4. Root-cause claims must cite supplied evidence

A non-abstaining forensic decision must contain at least one `supporting_evidence_ref`.
Every cited reference is checked deterministically against the evidence bundle. Unknown
references cause fail-closed `ERROR` rather than an accepted report.

### 5. Necessary components require counterfactual support

The forensic model may call an attack component necessary only if counterfactual replay
already marked that component `necessary_under_test=true`. Unsupported component claims
are rejected deterministically.

This keeps causal language anchored to performed interventions rather than model
intuition.

### 6. Abstention is first-class

If evidence does not support a root cause, the model sets `insufficient_evidence=true`.
Such a decision cannot contain a failure layer or proximate cause, and its confidence is
capped at 0.5 by schema validation.

Invalid JSON, unknown evidence references and unsupported necessary-component claims are
`ERROR`, not `INSUFFICIENT_EVIDENCE`, because they indicate evaluator failure rather than
weak experimental evidence.

### 7. Persist derived analysis as versioned data

Forensic reports are persisted separately from executions and evidence. Each row is keyed
by execution and `analysis_version`, preserving historical reinterpretation as forensic
logic evolves.

Persisted fields include:

- status and reproduction status,
- immutable model/system compromise flags,
- failure layer and proximate cause,
- enabling conditions,
- controls effective and controls bypassed,
- evidence references,
- counterfactually supported necessary component IDs,
- alternative explanations,
- confidence and summary.

No raw attacker prompt or target response columns are added.

## Consequences

Positive consequences:

- attacker and target cannot become their own final forensic authority,
- evaluator prompt injection has an explicit trust boundary,
- hallucinated evidence citations fail closed,
- causal claims can be audited back to counterfactual experiments,
- system-compromise semantics remain tied to observed system state,
- forensic reports can be re-run under later analysis versions without rewriting the
  original execution evidence.

Costs and limitations:

- forensic quality is constrained by evidence coverage,
- structured evidence data can still contain adversarial strings and requires careful
  handling,
- controls bypassed/effective remain semantic interpretations unless backed by dedicated
  system-state detectors,
- current persistence stores forensic reports but reproduction/minimization/
  counterfactual artifacts still require first-class persistence integration,
- standards mappings are downstream metadata and should not be used as proof of root
  cause.

## Follow-on

The next integration should persist reproduction, minimal reproducer and counterfactual
artifacts with the same target/configuration fingerprint, then build Blue Knowledge and
regression fixtures from confirmed evidence-backed findings.
