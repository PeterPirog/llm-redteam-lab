# ADR-064 — Disposable OpenCode target lease from composed runtime proofs

- Status: Proposed
- Date: 2026-09-16

## Context

AGENT measurements require `DISPOSABLE_SANDBOX` isolation. The repository now has
independently tested primitives for:

- immutable-template disposable Blue workspaces;
- exact isolated model-only Docker networking;
- exact OpenCode → model-peer launch binding;
- running AGENT command/environment attestation without persisted secret values;
- OpenCode health/version admission;
- Docker-exec loopback HTTP control transport; and
- generic per-trial isolation persistence/validation.

The remaining gap is a thin control-plane component that composes those primitives into a
fresh target instance for each statistical trial without reimplementing their checks.

## Decision

Add `DockerOpenCodeTrialLeaseProvider` as a `DISPOSABLE_SANDBOX`
`TargetTrialLeaseProvider`.

For each acquisition it:

1. requires the predeclared stable Blue identity;
2. materializes a fresh immutable-template workspace through
   `DisposableWorkspaceSupervisor`;
3. launches and admits a fresh OpenCode AGENT through
   `DockerNetworkedOpenCodeSupervisor`;
4. constructs the target only through the ownership-checked Docker-exec transport;
5. applies the already-produced health observation;
6. requires the resulting target identity to equal the predeclared identity;
7. emits a hash-only fresh-state proof binding workspace, runtime, model peer and target
   configuration; and
8. returns the existing generic `TargetTrialLease` contract.

The provider does not duplicate Docker inspection, environment verification or health
protocol logic. Those remain lower-level trusted components.

## Stable identity versus per-trial evidence

Stable target identity includes:

- OpenCode target configuration;
- Docker-exec transport policy;
- runtime profile;
- sandbox policy;
- exact networked model-peer binding; and
- networked OpenCode launch policy.

Per-trial evidence includes:

- materialized workspace lease;
- AGENT container identity;
- model-network runtime identity;
- sandbox/network/environment/health observations; and
- the composed runtime lease proof.

Per-trial container/workspace identities therefore do not create a different logical Blue
target on every replicate.

## Planning target

`DeclaredIsolatedOpenCodeTarget` exposes the stable target identity to campaign planning but
refuses direct execution with `isolation:disposable_trial_lease_required`. Real execution is
available only through an acquired disposable lease.

## Teardown

The preferred path is `release_async`, used by the campaign runner's existing
`release_target_trial_lease()` helper. Teardown order is:

1. close the target HTTP transport;
2. release the exact owned AGENT runtime;
3. only after runtime release, remove the exact owned workspace.

If runtime teardown fails, the workspace remains intact and the release reports
`cleanup_complete=false`. A later release retry may complete containment cleanup.

The synchronous `release()` method remains for protocol compatibility; containment cleanup
still proceeds, but async transport close is available only through `release_async`.

## Acquisition failure

If acquisition fails after workspace/runtime creation, the provider removes the exact runtime
first and the workspace second. If containment cleanup cannot be completed, acquisition raises
an explicit cleanup failure instead of returning a lease.

## MCP boundary

Version 2 still rejects `mcp_fixture_bridge`. A separately controlled fixture mount/runtime
contract is required before MCP fixture sidecars can be admitted into disposable Docker trials.
This provider does not weaken the one-workspace-mount isolation boundary.

## No inference during acquisition

Lease acquisition performs no Red/Blue/Judge prompt. Health and environment checks are
control-plane admission only. CI uses deterministic fake supervisors and does not require a
Docker daemon, GPU, Ollama daemon or cloud model.

## Architectural consequence

After this ADR the remaining step before a real HAL instrumentation smoke is operational
composition/configuration: instantiate the already-tested network/model-peer/runtime/provider
stack with exact HAL artifacts and run the bounded smoke profile. No second campaign engine or
parallel isolation implementation is required.
