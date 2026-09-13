# ADR-066: Compose one disposable OpenCode AGENT environment per statistical trial

- Status: Proposed
- Date: 2026-09-13
- Related: ADR-044, ADR-046, ADR-048, ADR-053, ADR-054, ADR-055, ADR-056, ADR-057, ADR-058, ADR-059, ADR-063, ADR-064, ADR-065

## Context

AGENT targets require stronger state isolation than direct MODEL targets. A bounded
conversation is one statistical trial, so mutable workspace, process, tool and model-peer
state must not silently survive into the next trial.

The repository already has independent contracts/supervisors for:

- disposable Blue-state isolation requirements;
- isolated internal Docker model networks;
- exact Ollama model artifact bundles and model-peer ownership;
- network-attached OpenCode sandboxes;
- Docker process ownership and cleanup;
- OpenCode runtime health evidence;
- the generic `TargetTrialLeaseProvider` boundary.

What is missing is one transactional provider that composes those trusted components into the
`DISPOSABLE_SANDBOX` isolation level required by AGENT mode.

## Decision

Add `DisposableAgentTrialLeaseProvider` as orchestration only. It SHALL NOT reimplement Docker,
artifact verification, network attestation, sandbox attestation or OpenCode health logic.

Acquisition order is fixed:

1. allocate a fresh disposable workspace;
2. create the isolated internal model network;
3. launch the exact verified Ollama model peer on that network;
4. launch the OpenCode AGENT container on the same admitted network;
5. build a health-gated target for that exact AGENT container;
6. verify target identity and health bindings;
7. return a `TargetTrialLease` attesting `DISPOSABLE_SANDBOX`.

A failure at any acquisition step triggers reverse-order rollback of every resource already
acquired.

## Trusted injected boundaries

### Workspace provider

A trusted `DisposableAgentWorkspaceProvider` supplies:

- the host workspace path;
- a hash-only workspace identity;
- a hash-only fresh-state proof;
- hash-only teardown evidence on release.

Fixture seeding remains outside this provider. Attacker-controlled content cannot choose or
expand workspace permissions.

### Target/health factory

A trusted `DisposableAgentTargetFactory` creates the OpenCode target and health observation for
the exact launched AGENT container. This provider does not invent a second health probe.

The production factory should eventually combine the OpenCode prelaunch configuration gate,
Docker-exec control transport and health-gated OpenCode target from the corresponding runtime
stack. Until that integration is validated, deterministic fake factories are sufficient only to
prove orchestration semantics.

## Admission checks

Before a lease is returned, the provider requires:

- expected target mode `AGENT`;
- exact target identity equality;
- healthy OpenCode observation;
- health container identity equal to the launched AGENT container;
- health runtime-profile hash equal to the configured runtime profile;
- health sandbox-attestation hash equal to the launched sandbox attestation;
- health application version equal to the expected target application version;
- target capability `runtime_health_verified`.

The resulting fresh-state proof binds the workspace proof, network identity, model-peer launch
and artifact-bundle proof, AGENT container/sandbox/network attestations and runtime health proof.

## Freshness and replay prevention

The provider records previously used:

- trial lease identities;
- workspace identities;
- workspace fresh-state proofs.

Reuse is rejected. A retried infrastructure attempt must receive a new trial identity rather
than silently reusing evidence from a previous attempt.

Resource names contain only a hash-derived suffix. Raw trial text is not embedded in Docker
network/container names.

## Concurrency

Version 1 supports exactly one active lease per provider instance. This is deliberate because
the currently trusted Ollama model-peer profile owns one fixed model-peer container name.

Parallel AGENT trials require a future profile/supervisor contract with unambiguous per-lease
model-peer ownership. The provider must not claim parallel isolation before that exists.

## Release semantics

Normal release attempts cleanup in strict reverse order:

1. target/transport;
2. AGENT container;
3. model peer;
4. model network;
5. disposable workspace.

Cleanup continues even if an earlier layer fails. The provider additionally checks model-artifact
stability/contract identity at model-peer release and rechecks the target identity before
teardown.

If any cleanup, identity or artifact-stability check fails, the provider becomes **dirty** and
refuses new acquisitions. Automatic retry/recovery is intentionally not defined in v1 because
partially removed resources are an uncertain security state. Manual/operator remediation or a
fresh provider instance is required after inspection.

## Statistical and compromise semantics

This ADR changes neither the statistical unit nor compromise definitions:

- one bounded conversation remains one trial;
- model/tool calls remain exposure/cost observations;
- `MODEL_COMPROMISE` remains distinct from `SYSTEM_COMPROMISE`;
- a model following an adversarial instruction whose unauthorized effect is blocked by the
  sandbox is not a system compromise.

The lease provides environment isolation and evidence. It does not judge attack success.

## Security consequences

The provider:

- cannot expand permissions declared by the component profiles;
- does not expose live Judge verdicts to Red;
- does not introduce network access or git push;
- does not accept attacker-controlled runtime policy;
- fails closed on incomplete rollback or teardown;
- prevents stale/reused workspace evidence from masquerading as a fresh trial.

## Testing

Deterministic fake-supervisor tests cover:

- `DISPOSABLE_SANDBOX` attestation and acquisition order;
- provider-fingerprint stability and policy sensitivity;
- hash-only resource names;
- single-active-lease enforcement;
- lease/workspace/fresh-proof reuse rejection;
- target identity mismatch;
- model-peer and AGENT launch rollback boundaries;
- unhealthy/mismatched health evidence;
- missing/mismatched OpenCode application version;
- exact reverse-order release;
- target identity drift at release;
- cleanup failure and dirty-provider behavior;
- model-artifact drift at release.

These tests use no Docker daemon, Ollama daemon, OpenCode process, GPU, external network or model
inference.

## Follow-up

After CI executes real steps again:

1. validate this stack with Ruff/pytest;
2. integrate the trusted OpenCode prelaunch configuration contract into the production target
   factory;
3. wire this provider into the AGENT campaign lifecycle so every AGENT statistical trial must
   acquire/release one disposable lease;
4. only then perform the first local Docker/GPU runtime qualification and bounded smoke.
