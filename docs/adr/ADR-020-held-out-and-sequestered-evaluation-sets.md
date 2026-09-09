# ADR-020: Held-Out and Sequestered Evaluation Sets

Status: Accepted
Date: 2026-09-09

## Context

`llm-redteam-lab` has two different objectives that must not be conflated:

1. **DISCOVERY** — maximize the probability that an adaptive Red Team finds a real weakness.
2. **EVALUATION** — estimate or compare Blue security under a controlled measurement protocol.

A strong Red attacker is intentionally allowed to learn from previous discovery outcomes. That same cross-trial adaptation creates measurement leakage if the resulting success rate is later reported as an unbiased target Attack Success Rate (ASR).

A boolean such as `held_out_cases=true` is insufficient evidence that an evaluation set was actually isolated. Case IDs may overlap, the same content may be copied under a new ID, definitions may change after a run, or the evaluation content may have been exposed to the adaptive Red policy before measurement.

NIST's Artificial Intelligence Technology Evaluation (AITE) uses blind/sequestered evaluation data to reduce train/test contamination. The project adopts the same methodological direction while supporting a weaker internal-held-out mode for normal engineering workflows.

## Decision

Introduce `HeldOutEvaluationManifest` as a first-class, hash-bound measurement artifact.

The manifest records only normalized identifiers and fingerprints, never raw attack payloads:

- `manifest_id`,
- `schema_version`,
- `exposure`,
- `split_strategy`,
- exact `corpus_snapshot_hash`,
- `red_can_access_evaluation_content`,
- optional opaque `sequestered_source_id`,
- discovery case IDs and content hashes,
- evaluation case IDs and content hashes,
- discovery/evaluation case-set hashes,
- canonical manifest `content_hash`.

### Exposure levels

`INTERNAL_HELD_OUT`
: Evaluation definitions may exist inside the engineering repository or other operator-visible storage, but the running adaptive Red policy must not receive them during discovery or cross-trial learning. This supports controlled internal comparisons but does not claim strong protection against pretraining or external contamination.

`SEQUESTERED`
: Evaluation definitions are held outside the discovery runtime/repository view and are identified only by an opaque `sequestered_source_id` in the manifest. This is the preferred mode for high-confidence benchmarking when operationally possible.

### Partition integrity

A valid manifest must satisfy all of the following:

```text
DISCOVERY_CASE_IDS ∩ EVALUATION_CASE_IDS = ∅
DISCOVERY_CONTENT_HASHES ∩ EVALUATION_CONTENT_HASHES = ∅
```

The content hash intentionally excludes the external case ID. Therefore identical normalized case content copied under a different ID is still detected as overlap.

The manifest is immutable after persistence. The same exact manifest may be re-saved idempotently; the same `manifest_id` with changed content is rejected.

### Comparative metric gate

`summary_evaluation(...)` may produce `comparable_blue_estimate=true` only when:

1. the campaign uses an `EVALUATION` `MeasurementProtocol`,
2. the attack policy is frozen across trials,
3. no learning occurs from current evaluation outcomes,
4. the target snapshot is pinned,
5. a valid held-out manifest is supplied,
6. every execution belongs to the manifest's evaluation partition,
7. every evaluation case is executed,
8. every case has the same number of repetitions,
9. all attempts are conclusive.

If any gate fails, the framework fails closed instead of silently computing a comparative ASR from incomplete evidence.

Unresolved attempts (`ERROR`, `INCONCLUSIVE`, `PARTIAL`) remain useful diagnostics, but they must be resolved or repeated before the run can support a comparable Blue estimate.

### Measurement provenance binding

A persisted EVALUATION `CampaignMeasurementSnapshot` must reference a previously persisted evaluation manifest and bind:

```text
campaign_id
  ↓
target_snapshot_id
  ↓
campaign_configuration_hash
  ↓
metric_definition_version
  ↓
MeasurementProtocol
  ↓
frozen Red policy fingerprint
  ↓
evaluation_manifest_hash
  ↓
evaluation_case_set_hash
  ↓
corpus_snapshot_hash
  ↓
evaluation exposure
```

Persistence verifies these links before accepting the measurement snapshot. A report cannot claim a held-out set by supplying arbitrary hashes that have no corresponding stored manifest.

## Consequences

### Positive

- adaptive Red remains free to optimize discovery,
- Blue comparison becomes reproducible and auditable,
- case renaming cannot hide discovery/evaluation overlap,
- changed case definitions invalidate prior fingerprints,
- uneven repeated trials cannot silently bias pooled comparative ASR,
- internal engineering evaluation and stronger sequestered evaluation are explicitly distinguished,
- measurement provenance can later prove what split was actually used.

### Costs

- evaluation preparation requires an explicit manifest,
- incomplete or unresolved evaluation runs cannot immediately produce comparative ASR,
- truly sequestered evaluation requires operator-managed storage outside the discovery runtime,
- current repository-native cases are only `INTERNAL_HELD_OUT` unless moved to an external sequestered store.

## Rejected alternatives

### Only store evaluation case IDs

Rejected because case definitions can change under stable IDs and duplicate content can be renamed.

### Allow adaptive learning between evaluation trials

Rejected for comparative metrics. Cross-trial adaptation is desirable in DISCOVERY but contaminates the target estimate.

### Treat any held-out repository folder as sequestered

Rejected. Repository visibility is not equivalent to blind/sequestered evaluation.

### Compute pooled ASR with unequal per-case repetition counts

Rejected for comparable reporting because high-repetition cases receive disproportionate weight.

## Follow-up

1. Add a campaign runner that consumes a manifest and prevents EVALUATION cases from entering Red learning memory.
2. Add a local operator workflow for generating and storing sequestered manifests outside Git-controlled corpus content.
3. Add report fields for exposure level and manifest hash.
4. Add regression comparison checks requiring compatible manifests or an explicit exploratory override.
