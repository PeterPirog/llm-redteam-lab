# ADR-052: Explicit Attacker-Pool Campaign Lifecycle

**Status:** Accepted  
**Date:** 2026-09-12

## Context

PR #54 introduced explicit attacker variants and PR #55 introduced persisted fixed
full-cross execution. A production-facing laboratory still needs a campaign boundary that
preflights the complete pool, pins the Blue target and measurement policy, owns the shared
budget, writes a campaign measurement snapshot and produces correctly named metrics.

Simply enabling all configured attackers implicitly would make normal program startup more
expensive and would violate the project's requirement that campaigns never silently expand
their inference budget. Likewise, aggregating every attacker conversation into one value
called ASR would conflate a predeclared search portfolio with a single attack policy.

## Decision

Add `AttackerPoolCampaignPlan` and `AttackerPoolCampaignLifecycleExecutor` as an explicit
opt-in DISCOVERY lifecycle.

The lifecycle reuses ordinary campaign preflight and then applies pool-specific gates:

- at least two enabled, distinct attacker variants are required;
- only model-backed Red policies are accepted;
- the initial lifecycle supports `SessionMode.REPLAY` only;
- selected fixture-backed cases fail closed until clean per-trial target leases exist;
- `planned_trials`, minimum interactions and maximum interactions are multiplied by the
  number of enabled attackers;
- the full-cross allocation must fit `max_attacks` before inference;
- the minimum unavoidable planner-call count must fit global and Red-planner call limits;
- because the budget client reserves each model configuration's declared
  `max_output_tokens`, the minimum first-planner-call reservation for every scheduled
  trial must fit global and Red-planner output-token limits.

The campaign attack-policy fingerprint binds:

- the underlying Red policy kind,
- fixed-full-cross execution mode,
- session mode,
- pool fingerprint,
- exact descriptors for all enabled variants,
- the rule that live Judge feedback is not exposed to Red.

The campaign configuration additionally binds the exact case-content scope hash, Blue
target snapshot, Judge fingerprint and budget fingerprint.

## Measurement naming

Before reproduction/minimization/forensics has established distinct finding identity, the
lifecycle reports **trial yield**, not unique vulnerabilities.

`AttackerPoolTrialMetrics` includes:

- per-attacker `DiscoveryMetrics`, preserving the bounded-conversation trial denominator;
- aggregate search yield across all scheduled conversations, explicitly non-comparable as
  a Blue estimate;
- `opportunity_violation_rate`: for each predeclared `(case, replicate)` opportunity,
  whether at least one attacker produced a conclusive invariant violation;
- unresolved opportunity rate;
- persisted target-interaction, planner/mutator-call and output-token totals per attacker.

A successful opportunity takes precedence over an unresolved sibling attacker trial for the
opportunity-level violation signal. If no attacker succeeds and at least one trial is
unresolved, the opportunity is unresolved rather than silently counted as safe.

None of these trial metrics is a distinct-finding count. ADR-049's finding-diversity report
still requires evidence-backed finding fingerprints from the later forensic pipeline.

`comparable_blue_estimate` remains `False` for attacker-pool DISCOVERY.

## Evaluation boundary

The first lifecycle rejects `CampaignPurpose.EVALUATION`. A multi-attacker held-out Blue
comparison requires a separate predeclared inference contract specifying the attacker-pool
mixture/estimand, frozen cross-trial policy and balanced held-out allocation. Reusing the
single-policy evaluation estimator would be statistically ambiguous.

## Consequences

### Positive

- pool execution is an explicit operator choice;
- full-cross resource impossibility is detected before the first model call;
- attack-policy and case scope are pinned into campaign measurement provenance;
- multi-attacker search strength increases without silently changing ordinary ASR
  semantics;
- per-attacker efficiency can be compared from persisted resource facts;
- the lifecycle remains local-first and no external inference is required by CI.

### Trade-offs

- pool EVALUATION is intentionally deferred;
- TARGET_MANAGED / OpenCode AGENT pools remain blocked until target leases isolate every
  trial;
- the lifecycle is a specialized extension while the stable single-attacker lifecycle
  remains unchanged.

## Next step

Introduce a `TargetLeaseProvider` abstraction that can issue clean per-trial targets with a
stable Blue policy identity and distinct run/isolation evidence. Implement the first trusted
provider for disposable OpenCode/Docker workspaces before enabling TARGET_MANAGED or
fixture-backed attacker-pool campaigns.
