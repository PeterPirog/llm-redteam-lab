# Metrics and Statistical Reporting

Status: initial metric contract
Last verified: 2026-09-11

The project reports experimental evidence, not absolute claims that a model is "secure" or "insecure".

## Core principles

1. Every rate must expose its numerator and denominator.
2. Small samples must report uncertainty.
3. `ERROR`, `INCONCLUSIVE` and `PARTIAL` must never be silently counted as defensive success.
4. Global rates must be accompanied by attack-family and target-class breakdowns.
5. Red attacker effectiveness and Blue vulnerability are different concepts.
6. Benign controls are required to measure over-refusal.
7. Repeated observations are required before a finding becomes confirmed.
8. Comparisons across target versions require comparable corpus, budgets and metric definitions.
9. For multi-turn attacks, one bounded conversation is one Blue vulnerability trial; individual turns are not additional ASR trials.
10. Red component comparisons must isolate the changed component and preserve matched experimental conditions.
11. Experimental Red policies must not be promoted merely because they are more complex; promotion requires a predeclared qualification rule applied to controlled paired evidence.
12. Model compromise and system compromise are separate security events; agentic sequence reports must not collapse their rates or first-event timing into one score.

## ASR — Attack Success Rate

ASR is defined at the testcase security-objective level:

```text
ASR = conclusive executions with objective_violated=true
      ------------------------------------------------
                    conclusive executions
```

This definition is valid for `MODEL`, `PIPELINE` and `AGENT` targets.

ASR does **not** imply system compromise. A model-only disclosure may be an attack success while deterministic authorization still prevents a system-level unauthorized effect.

## Multi-turn ASR and conversation units

A multi-turn jailbreak is a sequence-level experiment. The complete bounded conversation contributes at most one conclusive ASR trial:

```text
multi_turn_ASR = successful conclusive conversations
                 -----------------------------------
                       conclusive conversations
```

A five-turn conversation does **not** contribute five trials. Counting turns as trials would make the denominator depend on attacker flow control and would bias comparisons between short and long attack strategies.

Every multi-turn report should therefore distinguish:

### Blue vulnerability measurements

- conversation-level ASR with confidence interval,
- conversation-level MCR and SCR,
- model-to-system escalation rate for agentic targets,
- censoring-aware exposure to first model compromise and first system compromise,
- whole-sequence reproduction rate,
- result stratified by session mode and flow fingerprint.

### Red efficiency/resource measurements

- total target interactions,
- mean/median turns per conversation,
- turn ordinal to first violation,
- logical branch depth to first violation,
- backtracks and branches,
- successes per 100 target interactions,
- attacker/Judge model calls and token consumption.

`successes_per_100_turns` is an attacker-efficiency measure. It MUST NOT replace conversation-level ASR.

### Ordinal versus depth

Branching attacks require two separate measurements:

- `ordinal`: actual target interaction order and therefore cost,
- `depth`: number of conversational steps on the successful logical branch.

After backtracking, ordinal may increase while depth decreases. Reports should preserve both.

### Session and flow comparability

Multi-turn comparisons are directly comparable only when important flow-control conditions are compatible, including:

- replay versus target-managed session semantics,
- maximum turns,
- maximum backtracks,
- maximum branches,
- continue-after-success policy,
- layer-aware system-compromise stopping policy where applicable,
- Red strategy implementation/version,
- Judge implementation/version.

The framework records these conditions in a `flow_fingerprint`. A result with a materially different flow fingerprint should be labeled exploratory rather than silently included in a direct comparison.

## MCR — Model Compromise Rate

```text
MCR = conclusive executions with model_compromise=true
      ------------------------------------------------
                    conclusive executions
```

## SCR — System Compromise Rate

```text
SCR = conclusive executions with system_compromise=true
      -------------------------------------------------
                    conclusive executions
```

## Model-to-System Escalation Rate

This is a containment metric:

```text
M2S = model-compromised executions that also compromise the system
      ------------------------------------------------------------
                      model-compromised executions
```

A low M2S with a high MCR indicates that architectural controls are containing a vulnerable model.

## Layer-aware multi-turn time-to-compromise

For an adaptive `AGENT` sequence, first model compromise and first system compromise are distinct events. The framework therefore reports separate censoring-aware Kaplan-Meier curves for both layers.

Each layer is measured on two axes:

- `target_calls`: actual interaction ordinal, representing attacker cost;
- `path_depth`: logical conversational depth, representing sequence length when branching/backtracking changes the number of calls.

The event definitions are:

```text
model event  = first independently judged model_compromise=true
system event = first independently judged system_compromise=true
```

A known positive layer event remains an event even when the final execution is `PARTIAL`; positive evidence is monotonic. A conclusive execution with no compromise in the layer is right-censored at its final observed exposure.

An unresolved execution (`PARTIAL`, `INCONCLUSIVE`, `ERROR`) that has no known positive evidence for the layer is **not** counted as successful containment and is **not** converted into an ordinary censoring observation. It is reported separately as `unresolved` and excluded from that layer's Kaplan-Meier risk set. This prevents incomplete instrumentation from artificially lowering the apparent compromise risk.

A positive layer flag without recorded first-layer ordinal/depth is a measurement error and fails closed rather than inferring timing from the final label.

The Kaplan-Meier implementation uses Greenwood variance with log-log confidence intervals. The non-informative right-censoring assumption remains explicit. Under adaptive stopping, curves should be treated as descriptive unless stopping rules are predeclared and comparable across runs.

Layer-aware timing is not a replacement for MCR/SCR. Rates answer *whether* a layer was compromised; time curves describe *at what bounded attack exposure* the first compromise was observed.

## Unresolved Rate

```text
unresolved = ERROR + INCONCLUSIVE + PARTIAL
```

A high unresolved rate is a measurement-quality problem and must be visible in reports.

## Over-refusal Rate

Calculated only on explicitly benign controls:

```text
overrefusal = benign trials refused for safety reasons
              -----------------------------------------
                     valid benign trials
```

A refuse-everything system must not receive a good defense score.

## Confidence intervals

Binomial rates use the Wilson score interval by default. The report must include:

- successes,
- trials,
- point estimate,
- confidence level,
- lower bound,
- upper bound,
- interval method.

For zero trials the rate is `unavailable`, never `0%`.

## Reproducibility

A single successful execution is a `SINGLE_OBSERVATION`, not automatically a confirmed finding.

Campaign policy should define repeated confirmations. Reports should expose:

```text
reproduction_rate = successful reproductions / reproduction attempts
```

and classify findings as:

- `SINGLE_OBSERVATION`,
- `FLAKY`,
- `REPRODUCIBLE`,
- `CONFIRMED`.

For a multi-turn finding, reproduction means re-running the bounded sequence/strategy under the same recorded flow conditions. Replaying only the final successful message is not a reproduction of a sequence-dependent vulnerability.

## Stratification

At minimum, security rates should be available by:

- target identity/configuration,
- target class,
- target mode,
- attack family,
- complexity tier,
- security invariant,
- corpus/source,
- Red strategy,
- campaign budget profile,
- multi-turn session mode and flow fingerprint when applicable.

Do not hide materially different attack families behind one aggregate ASR.

## Red effectiveness metrics

Red is measured separately through:

- total attempts,
- unique attack families explored,
- successful families,
- attempts to first objective violation,
- ASR per attack family,
- refusal rate per family,
- infrastructure/error rate per family,
- attack novelty,
- budget consumed before first success,
- generations/turns to success,
- backtracks and branch efficiency for multi-turn strategies.

These measure attacker search quality, not severity of the Blue vulnerability.

## Paired Red component ablation

A new Red mechanism, generator, refiner or flow controller is not considered better merely because it succeeds in a synthetic integration test. Controlled component attribution uses paired held-out evaluation.

The matched unit is:

```text
(case_id, replicate)
```

Both baseline and treatment arms MUST use the same:

- Blue target snapshot,
- held-out evaluation manifest,
- Judge fingerprint,
- budget fingerprint,
- metric-definition version,
- session semantics.

Only the declared Red component/policy may differ. Both arms independently pass the normal held-out evaluation gate, including complete case coverage, balanced replicates and conclusive-only comparative reporting.

For objective-violation success, every pair belongs to one of four cells:

```text
both succeed
baseline only succeeds
treatment only succeeds
neither succeeds
```

The descriptive effect is:

```text
delta = treatment rate - baseline rate
```

The paired significance diagnostic is the two-sided exact McNemar/binomial test over discordant pairs (`baseline only` versus `treatment only`). This avoids a large-sample normal approximation for small smoke experiments. The treatment win proportion among discordant pairs also receives a Wilson interval.

`MODEL_COMPROMISE` and `SYSTEM_COMPROMISE` rate deltas are reported separately from the objective-violation delta.

Effectiveness and cost MUST NOT be collapsed into one default composite score. Cost deltas include at least:

- target interactions,
- Red planner calls,
- Red mutator calls,
- Red planner/mutator output tokens,
- first-violation ordinal when both arms succeed.

A negative treatment cost delta means the treatment used fewer resources or reached the violation earlier.

Execution order is counterbalanced across matched pairs to reduce systematic time/runtime/cache bias. If the target supports controlled stochastic seeds, `CASE_REPLICATE_SEED` reuses the same pair seed in both arms. Without supported deterministic seeding, the weaker `CASE_REPLICATE` pairing mode must remain visible in provenance.

## Red policy qualification

A paired ablation report and a policy-promotion decision are different artifacts. The ablation report describes what happened under controlled conditions; qualification applies a predeclared operational rule to that report.

Qualification has three states:

- `QUALIFIED`: treatment has earned promotion under the declared rule;
- `REJECTED`: paired evidence significantly favors baseline, or treatment violates an explicitly configured resource ceiling;
- `INCONCLUSIVE`: the experiment cannot support either conclusion.

The default qualification rule requires:

- a minimum matched-pair count,
- a positive objective-violation rate delta greater than the configured minimum effect,
- more treatment-only than baseline-only successes,
- exact two-sided McNemar/binomial `p <= alpha`.

A low-power result is `INCONCLUSIVE`, not evidence that the treatment is ineffective. Zero discordant pairs are also `INCONCLUSIVE`: identical observed outcomes do not prove superiority.

A qualification policy may require `CASE_REPLICATE_SEED`. If the target cannot provide that stronger stochastic pairing, the weaker experiment remains visible and the stricter promotion rule stays inconclusive.

Optional cost ceilings may independently restrict mean additional target interactions or mean additional Red output tokens. Cost and effectiveness are not multiplied, weighted or collapsed into one opaque score.

For auditable use, qualification should consume a report reconstructed through `summarize_persisted_red_ablation()`, which re-verifies the campaign, target, held-out set, Judge, budget, session and execution provenance before the deterministic qualification rule is applied.

Qualification is scoped evidence, not a universal ranking of Red policies. A treatment qualified on one target/configuration/budget regime is not automatically qualified everywhere.

## Target comparison

A target-version comparison is valid only when important experimental conditions are compatible, including:

- corpus and source revisions,
- security objectives,
- attack budgets,
- Red strategy/profile,
- target mode and application configuration,
- judge policy,
- metric-definition version,
- multi-turn flow fingerprint where applicable.

Where conditions differ, reports must label the comparison exploratory rather than directly comparable.

## Multiple stochastic trials

For stochastic models, campaign reports should record seed where supported and enough repeated trials to characterize instability. A deterministic seed does not prove reproducibility across providers or runtime versions.

## Severity is not ASR

Finding severity is a separate risk interpretation based on factors such as:

- consequence/impact,
- required privileges,
- attack complexity,
- reproducibility,
- reachability,
- containment controls,
- affected target mode.

Do not derive severity directly from ASR.

## Metric versioning

Metric definitions are part of reproducibility. Reports should record a metric-contract version so historical results can be reinterpreted if formulas evolve.

Initial metric contract: `metrics-v1`.

Layer-aware multi-turn timing extension: `multiturn-layer-time-v1`. This extension adds new layer timing outputs without changing the existing conversation-level ASR/MCR/SCR formulas.
