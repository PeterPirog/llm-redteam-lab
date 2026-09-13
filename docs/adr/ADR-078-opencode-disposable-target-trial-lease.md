# ADR-078 — Disposable OpenCode target lease per AGENT trial

- Status: Proposed
- Date: 2026-09-13

## Context

`TargetTrialLeaseProvider` already defines the isolation boundary required by the campaign
runner. `AGENT` targets require `DISPOSABLE_SANDBOX`, and persisted attacker-pool execution
already records acquisition and teardown evidence independently from the conversation result.

The repository also already contains the lower-level controls needed by a real OpenCode lease:

- hardened digest-pinned Docker sandbox policy;
- an internal isolated model-only Docker network;
- ownership-aware model-network and AGENT-container supervisors;
- OpenCode prelaunch process policy and post-launch process verification;
- Docker-exec loopback HTTP transport;
- runtime attestation and health/version evidence.

What was missing was the control-plane component that composes those controls into one fresh
Blue application instance for each statistical trial.

## Decision

Add `DockerOpenCodeTrialLeaseProvider`, implementing the existing synchronous
`TargetTrialLeaseProvider` contract at `TargetIsolationLevel.DISPOSABLE_SANDBOX`.

For every acquired trial the provider must:

1. require the exact predeclared stable Blue target identity;
2. allocate a new empty host workspace below a trusted workspace root;
3. launch a new OpenCode container through `DockerNetworkedAgentSupervisor`;
4. attach it only to the already-owned campaign model network;
5. verify exact Docker ownership and OpenCode process configuration;
6. bind the post-launch sandbox attestation to the prelaunch OpenCode contract;
7. verify `/global/health` and exact pinned OpenCode application version;
8. construct the Docker-exec OpenCode target;
9. require its stable identity to equal the predeclared target identity;
10. return a `TargetTrialIsolationAttestation` whose fresh-state proof binds workspace,
    container, network, process, launch and health evidence.

Acquisition performs no model prompt or inference.

## Stable target versus per-trial evidence

The following are stable target policy and contribute to target/provider identity:

- OpenCode application configuration;
- OpenCode runtime profile;
- hardened Docker profile;
- sandbox policy;
- model-network profile;
- Docker-exec control transport policy.

The following are per-run evidence and must not create a new logical target for every
replicate:

- workspace path/ID;
- AGENT container ID/name;
- model-network runtime ID;
- sandbox attestation ID;
- health response proof.

A `DeclaredIsolatedOpenCodeTarget` exposes only the stable identity for planning. Direct calls
to it fail closed; real execution is possible only through an acquired lease target.

## Workspace lifecycle

`FilesystemDisposableWorkspaceProvider` creates a new empty directory for every lease. Raw
host paths are runtime-only; persisted evidence uses hashes. The workspace root may not be a
symlink, each active workspace identity must be unique, and cleanup verifies absence.

Repository or adversarial fixture materialization is deliberately *not* performed by this
provider. Trusted workspace seeding is a separate control-plane operation so attacker content
cannot widen filesystem authority while a lease is being established.

## Teardown ordering

Containment cleanup is ordered:

1. remove the exact owned AGENT container;
2. only after successful container removal, remove the workspace.

If exact container teardown cannot be proven, the workspace is intentionally retained rather
than deleted while it could still be mounted. The release result is hash-only and reports
`cleanup_complete=false`; the campaign runner persists that result and fails closed.

A failed acquisition also attempts exact container teardown before workspace cleanup. If that
cleanup cannot be completed, acquisition raises a containment-specific failure rather than
returning a target.

## Campaign-scoped model peer

The model-only Docker network and verified model peer may be campaign-scoped and reused across
trials. This avoids repeatedly loading the same local model while preserving the experimental
requirement that attacker-influenced application/system state is fresh for every trial.

The model peer is not attacker-controlled application state. Its exact artifact identity is
handled by the model-peer/artifact qualification path and, separately, by Blue target artifact
qualification.

## Health admission

OpenCode documents `GET /global/health` as returning server health and version. The provider
probes that endpoint from inside the owned container without publishing the server port. The
observed version must equal the pinned `OpenCodeConfig.application_version`.

Health evidence is admission evidence; it is not model inference.

## MCP / fixture boundary

Version 1 intentionally rejects `OpenCodeRuntimeProfile.mcp_fixture_bridge`.

The current hardened Docker profile exposes one writable workspace mount. The MCP fixture
sidecar is required to live outside Blue workspace. Supporting it correctly therefore needs a
compound fixture/target isolation design with a separately controlled mount/transport and
matching cleanup proof. Pretending the host-side sidecar is visible or isolated inside the
current one-mount container would be architectural drift.

## Exact model-weight identity

This ADR solves system-state isolation, not model-artifact measurement identity. Exact Blue
weights remain a composable concern. ADR-072 now distinguishes the application provider from
the underlying model provider, allowing an `opencode` target to bind an `ollama` artifact via
an explicit trusted model reference. A thin provider wrapper can apply that identity to both
the declared target and every acquired lease without duplicating Docker isolation logic.

## Compromise semantics

The lease provider does not change judgment semantics:

- model following an adversarial instruction is `MODEL_COMPROMISE`;
- a denied filesystem/network/git effect is not `SYSTEM_COMPROMISE`;
- independently verified unauthorized state change is required for `SYSTEM_COMPROMISE`.

The sandbox is part of the Blue system and its success/failure remains observable evidence.

## Tests

Deterministic tests with fake Docker boundaries must prove:

- unique empty workspaces and lease identities per trial;
- `DISPOSABLE_SANDBOX` attestation passes the generic lease validator;
- process and health checks occur before lease return;
- OpenCode version drift fails before target execution and cleans created resources;
- container teardown failure preserves workspace and reports incomplete cleanup;
- a later successful retry can complete cleanup;
- MCP configuration is rejected until compound isolation exists.

No Docker daemon, Ollama daemon, GPU, external model endpoint or model inference is required by
these tests.
