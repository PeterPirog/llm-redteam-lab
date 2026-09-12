# ADR-053: Per-Trial Target Lease Isolation

**Status:** Accepted  
**Date:** 2026-09-12

## Context

The fixed full-cross attacker-pool runner can compare Red variants fairly only if one
variant cannot inherit residual Blue state from a previous trial. `SessionMode.REPLAY` can
reuse a stateless target adapter because the complete conversational state is supplied by
the harness. `TARGET_MANAGED` and AGENT targets may retain session state, memory, workspace
mutations, tool state, process state or other application state outside the replayed
transcript.

Reusing one such runtime would make attacker order a hidden causal variable and could turn
state contamination into an apparent Red capability difference.

The project already distinguishes stable Blue policy identity from per-run OpenCode/Docker
attestation. A fresh runtime must therefore change run evidence without becoming a different
security target when its security-relevant policy is unchanged.

OWASP Agent Control Standard and Autonomous Penetration Testing Standard both motivate
runtime controls that are observable and enforced outside the agent. The lease issuer is
therefore trusted harness/control-plane code; attacker-controlled content cannot request,
modify or authorize its own isolation boundary.

## Decision

Introduce a provider-independent `TargetLeaseProvider` contract.

For each bounded `TARGET_MANAGED` trial the scheduler supplies a `TargetLeaseRequest`
containing only harness-owned allocation facts:

- campaign ID,
- attack instance ID,
- attacker variant ID,
- case ID,
- replicate,
- fixed schedule order.

No attacker prompt or target output is an authority input to the lease provider.

A provider returns a `TargetLease` containing:

- one target adapter instance,
- a runtime-only lease ID,
- a hash-only `TargetLeaseReceipt`.

Every lease MUST expose exactly the same stable `TargetIdentity` as the campaign Blue
target. The runner validates this before execution. Per-run lease/attestation evidence is
not included in `TargetIdentity.configuration_hash`.

## Assurance levels

`TargetLeaseAssurance` is explicit:

- `FACTORY_FRESH_INSTANCE` proves only that the deterministic test/development provider
  produced a previously unseen adapter object with the expected identity. It is **not** an
  operating-system, container or network isolation claim.
- `ATTESTED_RUNTIME` is reserved for a concrete provider whose isolation evidence is
  independently verified by the harness, such as the planned OpenCode/Docker provider.

This prevents a mock reset from being reported as SYSTEM containment evidence.

## Runner behavior

`PersistedAttackerPoolRunner` keeps the existing shared-target path for `REPLAY`.

For `TARGET_MANAGED` it MUST fail closed unless a lease provider is supplied. For every
fixed full-cross assignment it:

1. persists the scheduled attack/allocation;
2. acquires a fresh lease;
3. verifies the leased target identity equals the campaign Blue identity;
4. executes the complete bounded conversation against that leased target;
5. appends the hash-only lease receipt as execution metadata evidence;
6. persists the ordinary conversation/execution evidence;
7. releases the lease in a `finally` boundary;
8. marks the pool assignment complete only after successful trial execution and release.

If acquisition or execution fails, the predeclared allocation remains visible as
incomplete. If execution fails after lease acquisition, release is still attempted.

Fixture-backed AGENT execution remains blocked until a concrete fixture-aware lease
provider can stage and clean immutable fixture state inside each leased workspace.

## Deterministic provider

`FactoryTargetLeaseProvider` exists to prove orchestration before real infrastructure is
used. It rejects:

- duplicate lease requests for the same attack instance,
- a target whose stable identity differs from the declared Blue identity,
- reuse of any previously issued target object,
- duplicate or foreign release handles.

Its receipt deliberately has no `isolation_evidence_sha256` and uses assurance
`FACTORY_FRESH_INSTANCE`.

## Evidence and measurement consequences

Lease evidence is execution metadata, not an attacker result and not a Blue success label.
It does not alter ASR/MCR/SCR denominators. The independent Judge/system-state verifier
remains authoritative for compromise labels.

A fresh lease prevents residual target state from creating cross-attacker confounding. It
does not by itself prove that a real AGENT runtime cannot escape its sandbox; that requires
`ATTESTED_RUNTIME` evidence from the concrete provider plus system-state verification.

## Consequences

### Positive

- TARGET_MANAGED attacker comparisons can be isolated per bounded conversation;
- stable Blue policy identity is preserved across fresh runtime instances;
- reset provenance enters the normal evidence/persistence path;
- mock orchestration can be proven without Docker or model inference;
- attacker-controlled data cannot expand or issue its own runtime permissions.

### Trade-offs

- operator-facing attacker-pool lifecycle still rejects TARGET_MANAGED until this generic
  contract is followed by a concrete trusted provider;
- the factory provider is intentionally insufficient for real SYSTEM containment claims;
- fixture staging and disposal remain a separate provider responsibility.

## Next step

Implement an `OpenCodeDockerTargetLeaseProvider` that creates a disposable workspace,
launches a fresh container through `DockerProcessSupervisor`, verifies sandbox attestation
and OpenCode health/version, constructs an attested OpenCode target with unchanged stable
policy identity, and destroys both container and workspace on release. Network connectivity
to a local model must be narrowly authorized and independently verifiable rather than using
Docker's unrestricted default bridge.
