# ADR-019: Comparative Metrics Require Immutable Measurement Provenance

## Status

Accepted

## Context

ADR-018 separates adaptive vulnerability discovery from controlled Blue evaluation. That distinction is not auditable if it exists only in runtime code or report prose. A persisted campaign currently identifies its target snapshot, campaign configuration hash and metric-definition version, but those fields alone do not prove whether Red learned between trials, which held-out cases were used, or which exact corpus content and frozen attack policy produced the reported rates.

A future reader must be able to determine from persisted facts whether a reported ASR-like metric came from a valid EVALUATION protocol rather than an adaptive DISCOVERY search.

## Decision

Each campaign may have exactly one immutable `CampaignMeasurementSnapshot` persisted in `campaign_measurement_protocols`.

The canonical snapshot binds:

- schema version,
- campaign ID,
- target snapshot ID,
- campaign configuration hash,
- metric-definition version,
- complete `MeasurementProtocol`,
- frozen attack-policy fingerprint when applicable,
- held-out case-set hash when applicable,
- exact corpus snapshot/content hash when applicable.

The entire structure receives a canonical SHA-256 `content_hash` using sorted compact JSON.

### Evaluation requirements

For `purpose = EVALUATION`, the snapshot must contain all of:

- `attack_policy_fingerprint`,
- `held_out_case_set_hash`,
- `corpus_snapshot_hash`.

The associated `MeasurementProtocol` already requires:

- attack policy frozen across trials,
- no learning from current evaluation outcomes,
- held-out cases,
- pinned target snapshot.

The persisted snapshot therefore records both the declared experimental semantics and the identifiers required to reproduce them.

### Campaign binding

Before persistence, the snapshot must match the already persisted campaign's:

- target snapshot ID,
- campaign configuration hash,
- metric-definition version.

A mismatch fails closed.

### Immutability

The first measurement snapshot persisted for a campaign is authoritative.

- Writing the exact same hash again is idempotent.
- Writing a different snapshot for the same campaign is rejected.
- Loading recomputes the canonical hash and verifies schema version and campaign purpose.

Measurement conditions cannot therefore be silently rewritten after results are known.

### Discovery

`DISCOVERY` snapshots may omit frozen-policy, held-out-set and corpus fingerprints because adaptive search is not presented as a comparable Blue estimate. Persisting a discovery snapshot is still useful for provenance and future promotion of findings into a separate held-out evaluation.

### Fingerprints

The persistence API provides canonical helpers for:

- frozen attack policy/configuration,
- held-out case sets,
- corpus snapshots.

The held-out case-set fingerprint is order-independent and deduplicates repeated IDs. The corpus snapshot fingerprint separately binds the test content/version so reuse of the same case ID with changed content cannot masquerade as the original evaluation set.

## Consequences

### Positive

- comparative security metrics become auditable,
- adaptive discovery cannot be relabeled after the fact as held-out evaluation,
- target/config/metric-version drift is detectable,
- evaluation cases and attack policy can be reproduced by hash,
- report generation can fail closed when measurement provenance is missing or invalid.

### Negative

- evaluation orchestration must construct the provenance snapshot before reporting comparative metrics,
- corpus partitioning needs a stable content-hash manifest,
- production deployments will eventually need explicit database migration tooling rather than relying only on `create_all` during development.

## Follow-up

1. Add deterministic held-out corpus partition manifests with content hashes.
2. Make comparative report generation require a verified EVALUATION measurement snapshot.
3. Include measurement snapshot hash in regression/version-comparison reports.
4. Introduce schema migrations before the first production database deployment.
