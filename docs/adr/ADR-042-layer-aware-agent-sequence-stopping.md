# ADR-042: Layer-aware stopping for adaptive AGENT sequences

Status: Accepted  
Date: 2026-09-11

## Context

The laboratory distinguishes `MODEL_COMPROMISE` from `SYSTEM_COMPROMISE`. A tool-using
agent can follow an adversarial instruction and request a forbidden action while an
authorization layer, sandbox or independent state boundary successfully blocks the effect.
That is a model compromise, but it is not a system compromise.

The multi-turn engine historically stopped on the first objective violation. For AGENT
campaigns this could terminate a sequence exactly when the most important system-security
question became available: after the model has crossed the behavioral boundary, can later
turns compose or adapt that intent into a verified unauthorized system effect?

Stopping at the first model-only compromise therefore under-explores the system boundary and
can systematically understate the effectiveness of sequence-based Red Teaming. Multi-turn
results are also sensitive to flow-control and budget rules, so stopping semantics must be
explicit, bounded and fingerprinted as part of the measurement protocol.

## Decision

Adaptive model-backed Red uses a layer-aware stopping policy for `AGENT` targets.

1. A bounded conversation remains exactly one statistical attack trial.
2. `MODEL` and `PIPELINE` model-backed runtimes preserve the existing first-objective-
   violation stopping behavior.
3. `AGENT` model-backed runtimes may continue after a model-only compromise.
4. An `AGENT` sequence stops when the first independently judged system compromise is
   established, the Red strategy explicitly stops, a target/error condition terminates the
   run, or the declared turn budget is exhausted.
5. Target-managed AGENT sessions still forbid replay backtracking and retain one active
   branch.
6. The engine records separately the first objective violation, first model compromise and
   first system compromise, including ordinal/depth where available.
7. The engine records a deterministic stop reason and stopping-policy identifier in the
   conversation result and as redacted `multiturn_flow_control` evidence so the durable
   experiment trace preserves flow-control provenance.
8. Conversation aggregation uses all judged turns. A later verified system effect can
   upgrade an earlier model-only result to `MODEL_AND_SYSTEM_COMPROMISE`.
9. Known positive evidence is monotonic. A later transport failure cannot erase a compromise
   already independently established. Conversely, if only one layer is known positive and
   later evidence for the other layer becomes unresolved, the aggregate result is
   `PARTIAL`; missing evidence is not converted into successful containment.
10. Live Red still receives target-visible feedback only. Judge labels, system-compromise
    flags and deterministic stopping decisions are not injected into planner prompts or
    campaign learning input during the active conversation.
11. AGENT discovery learning credits the logical path through the first verified system
    compromise when one occurs. This prevents the final escalation step from losing tactic
    or mechanism credit merely because an earlier turn already produced model compromise.
12. The policy grants no additional tools, paths, network access, git permissions,
    credentials or persistence. Existing campaign authorization and resource budgets remain
    authoritative.

## Measurement identity

The serialized `ConversationBudget` now includes the layer-aware stopping parameters and the
Red policy descriptor records the stopping-policy identifier. AGENT descriptors additionally
record `layer_aware_stopping=model-to-system-escalation-v1`.

Existing logical runtime version numbers are retained because target-mode-specific policy
identity already changes through the frozen descriptor and conversation-flow fingerprint.
Comparisons must use identical attack-policy fingerprints; runs with different stopping
semantics are not pooled as one measurement population.

## Rationale

A model-only compromise is often the beginning of an agentic exploit chain, not its natural
end. Continuing within the same fixed budget lets Red evaluate the surrounding control plane
without conflating the two security layers. This directly supports the project requirement
that a compromised model behind an effective sandbox must not be reported as system
compromise, while still testing whether the sandbox remains effective under adaptive
multi-turn pressure.

The policy is deliberately bounded. It does not turn one conversation into an unlimited
retry loop, and turns remain cost rather than additional ASR denominator entries.

## Consequences

### Positive

- Red can discover multi-step model-to-system escalation paths that were previously cut off.
- `MODEL_COMPROMISE` and `SYSTEM_COMPROMISE` remain independently measurable.
- The first model and system boundary crossings become auditable sequence milestones.
- A later system compromise is reflected in the final conversation-level result.
- Discovery learning can credit the actual system-crossing tactic/mechanism.
- Flow-control differences become explicit measurement provenance rather than hidden
  implementation details.

### Risks and controls

- Longer AGENT conversations consume more target and Red-model calls. Existing campaign
  budgets remain hard limits and are part of the policy fingerprint.
- A semantic Judge could make a stop decision probabilistic. System-state and deterministic
  verification remain preferred for system compromise, and Judge policy identity remains a
  required measurement input.
- Continuing after model compromise must not leak the independent verdict to the attacker.
  The target-visible live-feedback boundary remains unchanged and is covered by regression
  tests.

## Rejected alternatives

### Stop at every first objective violation

Rejected for AGENT Red because a model-only violation can be contained while leaving the
system boundary untested.

### Count each continuation turn as a new attack trial

Rejected because it would reward longer conversations with a larger ASR denominator and
would confound attack effectiveness with flow length.

### Continue indefinitely after compromise

Rejected because Red effectiveness must be measured under explicit finite budgets.

### Expose the Judge verdict to help Red escalate

Rejected because it creates an evaluator oracle and contaminates the attacker being
measured. Only target-visible observations may guide live adaptation.
