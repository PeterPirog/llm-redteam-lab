# ADR-043: Layer-aware multi-turn security metrics

Status: Accepted  
Date: 2026-09-11

## Context

The multi-turn runtime distinguishes `MODEL_COMPROMISE` from `SYSTEM_COMPROMISE` and, for
adaptive `AGENT` targets, may continue after a model-only compromise to test whether
surrounding authorization and sandbox controls can still prevent an unauthorized effect.
ADR-042 made the execution flow layer-aware and records the first model and first system
boundary crossings separately.

The existing multi-turn metric contract remained centered on the first testcase objective
violation. That is insufficient for an agentic sequence in which the model crosses its
behavioral boundary at turn 2 while an independently verified system effect occurs at turn
4. Reporting only the first objective violation makes the containment trajectory invisible
and can hide the security value of system controls.

The project also treats `PARTIAL`, `INCONCLUSIVE` and `ERROR` as unresolved evidence rather
than successful defense. Layer timing must preserve that rule: absence of proof of a system
effect is not proof that the system remained uncompromised when observation itself became
unresolved.

## Decision

Multi-turn reporting has separate layer-aware first-compromise measurements.

1. One bounded conversation remains one statistical security trial. Turns never become
   additional MCR, SCR or ASR denominator entries.
2. Conversation-level MCR, SCR and model-to-system escalation rate reuse the canonical
   campaign metric implementation and Wilson intervals.
3. The existing objective `time_to_violation` curves remain available for compatibility.
4. New Kaplan-Meier curves independently estimate exposure to first model compromise and
   first system compromise.
5. Both layer curves are available on two axes:
   - `target_calls`: actual target interaction ordinal and attacker cost;
   - `path_depth`: logical conversational depth, distinct from cost when branching or
     backtracking is used.
6. A known positive layer flag is an event even when the overall execution is `PARTIAL`.
   Positive evidence is monotonic and must not be discarded because another layer became
   unresolved.
7. A conclusive layer-negative conversation is right-censored at the final observed target
   call or maximum logical path depth.
8. An unresolved conversation with no positive evidence for the layer is not treated as a
   containment censor. It is counted explicitly as `unresolved` and excluded from that
   layer's Kaplan-Meier risk set.
9. A positive layer flag without its recorded first-compromise ordinal/depth fails closed.
   The metric layer does not infer timing from the final outcome.
10. Kaplan-Meier intervals use Greenwood variance with a log-log transform, consistent with
    the existing multi-turn survival implementation.
11. The non-informative right-censoring assumption remains explicit. Curves from adaptive
    stopping regimes are descriptive unless the stopping policy is predeclared and
    measurement-compatible across compared runs.
12. Direct comparisons require compatible flow fingerprints and Judge/budget/target
    measurement identity. Layer-aware curves do not make heterogeneous runs comparable.

## Rationale

For agentic security, two questions are different:

- how quickly can an attacker make the model violate a behavioral invariant?
- how quickly can the attacker turn that model failure into an independently verified
  unauthorized system effect?

A system can have high MCR and low SCR if architectural controls contain a vulnerable model.
Conversely, a small gap between the first model and first system compromise may indicate weak
containment. Keeping the events and their exposure curves separate makes that distinction
measurable without inventing a composite score.

The unresolved rule is deliberately conservative. Treating an interrupted or incomplete
system observation as right-censored containment would bias SCR downward and reward poor
instrumentation. Explicit unresolved counts instead surface measurement-quality failures.

## Consequences

### Positive

- ADR-042 model-to-system escalation paths become visible in aggregate metrics.
- Model alignment weakness and system containment effectiveness can be analyzed separately.
- Branching strategies retain distinct cost and logical-depth interpretations.
- Partial positive evidence contributes to the layer it actually establishes.
- Missing layer evidence cannot silently improve the apparent security result.
- The implementation reuses the campaign-level rate contract rather than duplicating rate
  formulas.

### Limitations

- The new curves describe absolute exposure from conversation start. Conditional latency
  from first model compromise to first system compromise is not yet a primary metric.
- Kaplan-Meier estimates rely on censoring assumptions. They must not be presented as
  generalized population claims merely because confidence intervals are available.
- Small smoke campaigns can have very wide uncertainty and are instrumentation checks, not
  strong comparative evidence.

## Rejected alternatives

### Use only the first objective violation

Rejected because it collapses model compromise and system compromise into one event and
hides containment behavior.

### Treat every unresolved layer-negative run as censored containment

Rejected because unresolved observation is not evidence that the control succeeded.

### Count every turn as an independent security trial

Rejected because it makes the denominator attacker-controlled and biases longer attack
sequences.

### Collapse MCR, SCR and timing into one security score

Rejected because it obscures which security layer failed and prevents causal interpretation.
