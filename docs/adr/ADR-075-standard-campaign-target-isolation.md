# ADR-075: Standard campaigns use the same per-trial Blue isolation contract

- Status: Accepted
- Date: 2026-09-18

## Context

The repository already enforced fresh Blue state in explicit attacker-pool experiments through
`TargetTrialLeaseProvider`. The ordinary `CampaignLifecycleExecutor`, however, executed its
declared target directly.

That asymmetry is unsafe for the first HAL instrumentation smoke. The smoke intentionally uses
one Red planner/mutator profile rather than an attacker pool, while the Blue target is an
OpenCode `AGENT`. Transcript replay does not reset an agent workspace, application process,
tool state or other mutable system state. Therefore an AGENT trial still requires
`DISPOSABLE_SANDBOX` isolation even with a single attacker profile.

The isolation persistence table was also coupled to `attacker_pool_trials`, preventing the
same trusted evidence from being recorded for ordinary campaign attacks.

## Decision

### General persistence

`target_trial_isolation.attack_instance_id` references the canonical
`attacks.attack_instance_id` table rather than the attacker-pool extension table.

Acquisition persistence now requires only a known attack instance. Attacker-pool execution
continues to work because every attacker-pool assignment already has a canonical attack row.

### Standard campaign lifecycle

`CampaignLifecycleExecutor` accepts an optional `TargetTrialLeaseProvider`.

Before campaign execution it derives the minimum isolation level from target mode and session
mode using the existing shared policy:

- AGENT -> `DISPOSABLE_SANDBOX`;
- PIPELINE -> `APPLICATION_INSTANCE`;
- MODEL with target-managed history -> `SESSION_NAMESPACE`;
- stateless MODEL+REPLAY -> no additional target lease.

If isolation is required, missing or weaker providers block execution before the first target
or Red-model call.

For each statistical trial:

1. record the canonical attack;
2. acquire a fresh target lease;
3. validate target identity, isolation strength and control-plane independence;
4. persist acquisition evidence before target execution;
5. execute only through `IsolationProvenanceTarget`;
6. release the lease in a `finally` boundary;
7. persist teardown evidence;
8. require `cleanup_complete=true`;
9. add teardown evidence to the resulting execution.

At campaign completion, persisted isolation records must exactly cover all campaign attacks,
use unique lease IDs, bind the expected Blue target, meet the required isolation level and
contain complete teardown evidence.

The stable target-isolation provider fingerprint and configured isolation level are included
in the campaign configuration hash.

### Fixture boundary

Environment fixtures and target-state isolation are separate mutable-state boundaries.
Combining a fixture workspace with a disposable external AGENT target requires an explicit
compound fixture/target isolation contract. Until that contract exists, campaigns that
simultaneously require target leases and fixtures fail closed rather than assuming that a
fixture sandbox also resets the Blue application.

## Consequences

The single-profile HAL smoke and attacker-pool experiments now share the same isolation
semantics and audit model.

A planning/declared OpenCode target can never be accidentally executed by the standard
campaign lifecycle; only a validated leased target is used.

No Docker, GPU or inference is needed to test this lifecycle: deterministic in-memory lease
providers exercise the same orchestration and persistence boundaries.
