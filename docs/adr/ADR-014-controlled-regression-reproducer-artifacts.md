# ADR-014 — Controlled regression reproducer artifacts

- Status: Accepted
- Date: 2026-09-09

## Context

A confirmed finding is useful only if it can be re-run against later target
configurations. The project already persists minimal-attack component hashes, but hashes
alone cannot execute a regression test. Conversely, storing raw adversarial sequences in
normal SQL or committing generated reproducers to Git would unnecessarily broaden access
to executable attack content.

Multi-turn findings make this requirement stricter: the regression artifact must preserve
the ordered successful conversation path while keeping exploratory branches in genealogy
and evidence rather than replaying them blindly.

## Decision

### 1. Regression artifacts are built only from verified findings

An executable regression artifact requires:

```text
objective_violated = true
reproduction status = REPRODUCIBLE or CONFIRMED
minimization status = COMPLETE
matching attack case and target identity
```

This prevents one-off, flaky or unfinished minimization results from becoming permanent
regression tests.

### 2. The artifact preserves the minimal ordered attack

The artifact stores the minimized ordered components, including multi-turn `TURN`
components. It also records:

- attack ID and family,
- interaction mode,
- security objective hash,
- source target identity and snapshot,
- baseline execution and compromise layer,
- reproduction status,
- content integrity hash.

For branched attacks, the minimized successful path is the executable reproducer. Branch
history remains forensic/genealogy evidence and is not automatically replayed.

### 3. Raw reproducer content is a sensitive local artifact

Normal SQL persistence remains hash-first and does not gain raw prompt columns.

`LocalRegressionArtifactStore` refuses sensitive writes by default. Callers must explicitly
set:

```text
allow_sensitive_artifacts = true
```

The artifact schema fixes `sensitive=true`; it cannot be toggled off in artifact data to
bypass the store policy. The artifact ID derives from the content hash and both are
validated on load.

Generated artifacts are expected under `regression/artifacts/`, which is ignored by Git.
Local `.env`, `config/models.yaml` and private reports are also ignored.

The initial local store uses filesystem permissions and integrity checking; it does not
claim encryption at rest. Synthetic canaries remain mandatory. Stronger encrypted artifact
storage can be added later without changing the regression-domain contract.

### 4. Replay is provider-independent

The regression engine receives a caller-supplied async runner:

```text
RegressionArtifact + TargetIdentity -> ExecutionResult
```

Target adapters therefore remain responsible for MODEL, PIPELINE or AGENT execution and
for correct replay-vs-target-managed multi-turn session semantics.

This avoids coupling regression logic to Ollama, OpenWebUI, OpenCode or any particular
provider.

### 5. Only comparable target lineage is replayed automatically

The current target must preserve:

```text
logical target_id
target_class
target_mode
```

The target configuration hash may intentionally differ because regression testing exists
to compare changed configurations. A different target lineage/class/mode is
`INCOMPARABLE`, and the runner is not invoked.

A future target-lineage identifier may replace the current logical `target_id` convention
when more complex deployment histories exist.

### 6. MODEL and SYSTEM compromise remain separate in regression classification

Regression comparison does not reduce security to a Boolean pass/fail. It distinguishes:

```text
SECURITY_IMPROVEMENT
SECURITY_REGRESSION
UNCHANGED_VULNERABLE
MODEL_TO_SYSTEM_ESCALATION
SYSTEM_CONTAINMENT_IMPROVEMENT
INCONCLUSIVE
INCOMPARABLE
```

For example, a previous MODEL-only compromise that now reaches an unauthorized system
effect is `MODEL_TO_SYSTEM_ESCALATION`, even if the textual jailbreak itself is unchanged.

Likewise, a previous model+system compromise reduced to model-only compromise is a
containment improvement rather than a complete fix.

### 7. Measurement failures never become security improvements

`ERROR`, `INCONCLUSIVE`, `PARTIAL` or unresolved objective judgments produce
`INCONCLUSIVE`. They are never interpreted as a fixed vulnerability.

This preserves the metric contract already used by campaign and reproduction layers.

## Consequences

Positive consequences:

- confirmed findings become executable long-term knowledge,
- raw attack content stays outside normal database and Git workflows,
- artifact tampering is detected,
- multi-turn attack ordering survives into regression replay,
- provider independence is preserved,
- model compromise and system containment changes remain visible,
- measurement errors cannot create false security improvements.

Costs and limitations:

- generated artifact files are sensitive and require local access controls,
- the initial store provides integrity and best-effort restrictive file permissions but
  not encryption at rest,
- regression runner integration with actual OpenWebUI/OpenCode session handling remains a
  follow-on,
- current comparison is one replay result at a time; repeated stochastic regression runs
  and confidence aggregation should reuse the reproduction policy rather than infer from
  one sample,
- exact target lineage across renamed deployments needs a future explicit lineage model.

## Standards alignment

The design supports the continuous-evaluation direction of NIST TEVV-Athlon and preserves
runtime traceability required by OWASP Agent Control Standard. Multi-turn artifacts retain
conversation sequencing consistent with contemporary adaptive red-team strategies such as
Hydra while keeping provider/session mechanics in the target adapter.

## Follow-on

Next work should connect regression artifacts to repeated replay, persistence of regression
run metadata, and real AGENT system-state telemetry. A regression finding should be
confirmed with the same evidence/reproduction discipline as an original finding.
