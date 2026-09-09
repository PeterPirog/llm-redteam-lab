# ADR-018: Adaptive Red Discovery Is Separate from Held-Out Blue Evaluation

## Status

Accepted

## Context

The laboratory intentionally contains an adaptive Red attacker. It learns from prior attempts, selects tactics based on observed Blue behavior, mutates failed probes and can execute multi-turn sequences. This is desirable for vulnerability discovery but creates a measurement problem: attempts selected after observing earlier outcomes are not independent samples from a fixed attack distribution.

Reporting the success rate of an adaptive search directly as comparative Blue attack success rate can overstate precision, hide selection effects and make target-to-target comparisons unfair. Modern AI measurement guidance emphasizes explicit measurement targets, assumptions, uncertainty and controlled evaluation data. NIST evaluation programs also use held-out or sequestered data to reduce contamination and improve comparability.

At the same time, many real jailbreaks are sequential. The correct response is not to prohibit within-conversation adaptation. Instead, the lab must distinguish adaptation inside a frozen attack policy from learning that changes the policy between evaluation trials.

## Decision

Every serious campaign is conceptually one of two purposes:

### DISCOVERY

Purpose: find and explain weaknesses.

Allowed behavior includes:

- learning from earlier trials,
- changing attack-family allocation,
- learning tactic transitions and sequences,
- mutating prompts based on target responses,
- backtracking and branch search where supported,
- promoting promising attacks to reproduction/minimization.

Discovery may report:

- observed violation yield,
- unresolved/error rate,
- tactic success/trials,
- transition success/trials,
- sequence success/trials,
- time/turns/depth to first violation,
- inference and target-interaction cost.

These are Red search metrics. They are explicitly marked `comparable_blue_estimate = false` and must not be presented as unbiased comparative Blue ASR.

### EVALUATION

Purpose: compare or characterize a pinned Blue target using a controlled measurement protocol.

A valid comparative evaluation requires:

- attack policy frozen across trials,
- no learning from outcomes of the current evaluation campaign,
- held-out cases,
- pinned target snapshot/configuration.

A frozen policy may still be sequential and adaptive *within a conversation*. For example, a fixed policy can choose its next turn from the current response. What is prohibited is updating that policy from previous evaluation-trial outcomes.

Only a valid EVALUATION protocol may use the project's comparative Blue metrics such as ASR, model-compromise rate, system-compromise rate and model-to-system escalation rate as evaluation estimates.

## Sequence-aware Red memory

`RedCampaignMemory` remains transcript-free. It stores bounded aggregate records containing tactic identifiers and outcomes, not raw prompts or target responses.

Each emitted attacker step receives:

- a constrained tactic identifier,
- a Red phase (`primer`, `planner`, `finisher`).

Memory derives:

- tactic success/trial counts,
- ordered phase-aware transition counts,
- whole-sequence success/trial counts,
- median successful turn ordinal,
- median successful conversation depth.

Example structural memory:

```text
primer:context_probe
  -> planner:authority_shift
  -> finisher:objective_probe
```

This is intentionally different from replaying the successful prompt text. The latter would increase prompt-injection/memory-poisoning risk and turn the project into a jailbreak-string collection.

Tactic identifiers are short lowercase tokens with a restricted character set. Free-form tactic labels are rejected before entering memory.

## Statistical semantics

Sequence and transition rates use Wilson confidence intervals, including when an observed rate is 0% or 100%. Small samples therefore retain visibly wide uncertainty.

Adaptive sequence metrics describe the performance of the observed search policy. They do not correct for adaptive selection bias and are not labeled Blue ASR.

Held-out EVALUATION continues to use the existing campaign metrics with explicit denominators:

- ERROR, PARTIAL and INCONCLUSIVE are not counted as defensive success,
- unresolved outcomes are separately reported,
- `trials == 0` produces an unavailable estimate rather than 0%,
- MODEL and SYSTEM compromise remain distinct.

## Consequences

### Positive

- Red can become more effective across campaigns without corrupting Blue measurement semantics.
- Multi-turn jailbreak sequences become learnable objects rather than incidental transcripts.
- Target comparison and regression claims have a stronger experimental contract.
- Small-sample uncertainty remains explicit.
- Memory retains less attacker/target text, reducing poisoning and sensitive-content persistence.

### Negative

- Discovery and evaluation require separate campaign phases or runs.
- A successful discovery campaign cannot automatically be quoted as an unbiased target ASR.
- Held-out case management and attack-policy freezing add operational complexity.

## Required workflow

```text
ADAPTIVE DISCOVERY
      |
      v
candidate finding
      |
      v
reproduction + minimization
      |
      v
freeze attack/policy
      |
      v
HELD-OUT EVALUATION
      |
      v
comparative Blue metrics
      |
      v
forensics / Blue knowledge / regression
```

## Follow-up

1. Persist campaign purpose and measurement protocol with campaign metadata.
2. Add held-out corpus partitions and contamination checks.
3. Add target-version paired evaluation where the same frozen attack policy and cases are replayed against both snapshots.
4. Report sequence metrics alongside cost metrics, never collapsed into one opaque score.
