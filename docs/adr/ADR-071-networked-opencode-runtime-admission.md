# ADR-071: OpenCode runtime admission composes AGENT, environment and health proofs

Status: Proposed

Date: 2026-09-15

## Context

The project already has independent proofs for the networked Docker AGENT sandbox, exact
OpenCode launch policy, redacted running environment and `/global/health` response. The
final disposable target provider must not independently reimplement those checks, nor may
it combine valid observations from different containers or model-peer topologies.

## Decision

Introduce `DockerNetworkedOpenCodeSupervisor` as a narrow coordinator over the existing
supervisors and attestors.

Before launch it requires exact agreement among:

- Docker AGENT profile and networked OpenCode launch-policy hash;
- Docker AGENT model-network profile and requested isolated model network;
- model-network lease and requested network profile;
- launch-policy runtime and requested OpenCode runtime profile; and
- `OpenCodeModelPeerBinding` and requested network endpoint.

After the AGENT is launched, admission requires:

- the AGENT network attestation names the exact expected model-peer container;
- the running environment observation binds the same AGENT container, profile, launch
  policy and model-network profile;
- the attested launch plan binds the same sandbox attestation and model-peer policy;
- the health observation binds the same AGENT container, runtime profile and sandbox
  attestation; and
- all cross-checks succeed before a `DockerNetworkedOpenCodeLease` is issued.

Any failure after AGENT launch releases only the exact owned AGENT lease. The returned
runtime lease has a stable `proof_sha256` over all component evidence.

## Consequences

The final `DISPOSABLE_SANDBOX` provider can compose one admitted OpenCode runtime instead
of duplicating Docker/environment/health validation logic. A health response or environment
snapshot from another container cannot be substituted even if each proof is individually
valid.

This layer performs no model inference and does not construct the final target adapter.

## Follow-up

Build the final predeclared/runtime OpenCode target identity using the staged-artifact
composite proof from ADR-068 and Docker-exec transport. Then compose workspace, network,
model peer, OpenCode runtime and async teardown into the `DISPOSABLE_SANDBOX` lease
provider.
