# ADR-012 — Experiment fingerprints for reproduction and derived analysis

- Status: Accepted
- Date: 2026-09-09

## Context

Reproduction, minimization and counterfactual replay are meaningful only when the
experimental conditions under which their executions were produced are known and
compatible.

The base persistence schema already stores target snapshots, campaigns, attack instances,
executions and multi-turn flow fingerprints. Before this ADR, derived analysis objects
existed only in memory and the execution persistence path verified that referenced attack
and target rows existed, but did not enforce that the target snapshot belonged to the
attack's campaign. That gap could allow evidence from different Blue configurations to be
mixed and later presented as one reproduction or causal analysis.

This is a measurement-integrity problem, not merely a database-normalization issue.

## Decision

### 1. Enforce execution-to-campaign target consistency

An execution may be persisted only if:

- the attack instance exists,
- the target snapshot exists,
- the attack's campaign exists,
- the execution target snapshot equals the campaign target snapshot,
- `ExecutionResult.attack_id` equals the persisted attack case ID,
- `ExecutionResult.target_id` equals the persisted target snapshot target ID.

Any mismatch fails closed.

### 2. Define an environment fingerprint

The environment fingerprint identifies the Blue-side experimental conditions relevant to
comparison while permitting intentional attack mutations. It hashes:

```text
target_snapshot_id
+ target configuration_hash
+ campaign configuration_hash
+ metric_definition_version
```

The target snapshot already distinguishes the same underlying model used in different
applications/configurations, as required by the project architecture.

The campaign configuration hash must include all experiment-relevant configuration that
is not already represented by the target snapshot, including Judge configuration,
attacker-role configuration and sampling settings when those affect comparability.

### 3. Define a stricter reproduction fingerprint

Reproduction must additionally preserve the tested attack identity and conversation-flow
semantics. The reproduction fingerprint hashes:

```text
environment_fingerprint
+ attack_fingerprint
+ multi-turn flow_fingerprint (or single_turn marker)
```

The attack fingerprint contains:

```text
case_id
attack_family
interaction_mode
payload_hash (preferred) or attack_instance_id fallback
```

Therefore a repeat from another Blue configuration, another attack payload, or another
multi-turn flow cannot silently confirm the original finding.

### 4. Keep minimization and counterfactual replay in the same causal cohort

Minimization and counterfactual replay intentionally change the attack payload, so they
compare candidate executions using the environment fingerprint rather than the strict
reproduction fingerprint.

Payload variation does not authorize cross-test evidence mixing. Every candidate execution
used for causal analysis must preserve the reference:

```text
case_id
attack_family
interaction_mode
environment_fingerprint
```

The in-memory result must also declare the same `attack_id`/case identity as the reference.
This prevents a successful execution from another security objective or attack family from
being accepted as evidence that a component of the current attack is necessary,
sufficient or removable.

### 5. Persist derived artifacts as first-class versioned records

The persistence layer stores:

- reproduction run and attempt execution IDs,
- reproduction rate, Wilson interval, denominator and unresolved count,
- minimization run status and target-execution cost,
- hashed minimized components and component ordering,
- minimization candidate assessments and execution IDs,
- counterfactual run metadata,
- per-component necessary/sufficient results and execution IDs.

Every run records the relevant target snapshot, attack instance, experiment fingerprint
and analysis version.

### 6. Do not persist raw minimal attack content by default

Minimized components are stored as IDs, kinds, required flags and SHA-256 content hashes.
The analysis tables do not add raw prompt/component columns.

A future regression artifact store may retain explicit reproducer content only under a
separate policy-controlled artifact mechanism. This keeps normal persistence aligned with
the project's existing prompt-redaction posture.

## Consequences

Positive consequences:

- findings cannot be confirmed by executions from a different Blue configuration,
- multi-turn flow changes are visible to reproduction,
- minimization and counterfactual evidence remains comparable while allowing payload
  interventions,
- causal evidence cannot silently cross security objectives, attack families or
  interaction modes,
- derived findings are auditable back to concrete execution IDs,
- historical analysis can be re-run with new analysis versions without rewriting raw
  execution evidence,
- the Blue Security Knowledge Base can later aggregate control evidence using stable
  target/configuration identity.

Costs and limitations:

- payload hashes must be populated for the strongest cross-attack reproduction identity;
  otherwise the attack instance ID is used as a conservative fallback,
- the environment fingerprint currently relies on campaign configuration hash and target
  snapshot completeness; adapters must include all security-relevant target settings in
  `configuration_hash`,
- campaign creation currently trusts the supplied `configuration_hash`; a future typed
  campaign manifest should compute it canonically from Red/Judge/budget/sampling policy,
- model sampling seed/temperature and provider response nondeterminism must be included in
  target/campaign configuration when they are relevant to a specific experiment,
- raw minimal reproducer content still needs a separate controlled artifact-store design
  before automatic regression execution can be fully self-contained.

## Follow-on

After these artifacts are stable in persistence, the next core-loop milestone is the Blue
Security Knowledge Base and Blue-vs-Red coverage matrix. Control-state transitions must be
derived from persisted experimental evidence rather than LLM assertions.
