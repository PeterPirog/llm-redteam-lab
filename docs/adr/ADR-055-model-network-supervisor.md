# ADR-055: Ownership-aware isolated model-network supervisor

Status: Proposed

## Context

ADR-054 defines a deterministic verifier for the intended AGENT-to-model Docker network,
but a verifier alone does not prove that the laboratory created, still owns or safely
removed the inspected resource. Docker names are mutable references. A failed create can
also mean that a requested name already belongs to an unrelated resource.

The laboratory already applies an ownership-aware lifecycle to Docker containers. The
same rule is required for the model network: never infer ownership from a name and never
clean up a resource unless its exact Docker ID still matches the lease issued by the
trusted harness.

Docker gateway mode `isolated` for internal bridge networks is available in Docker Engine
28+. Runtime admission must therefore bind a qualified Docker server version before the
network is created.

## Decision

Introduce `DockerModelNetworkSupervisor` as a trusted orchestration boundary.

### Engine admission

Before network creation the supervisor executes, without a shell:

`docker version --format {{.Server.Version}}`

The server version is parsed into major/minor/patch evidence. Creation fails before any
network mutation if the observed server major version is below the minimum declared by
the network profile.

The observation and command fingerprint are retained in `DockerModelNetworkLease`.

### Network creation and ownership

The supervisor:

1. obtains the deterministic create command from `DockerIsolatedModelNetworkProfile`;
2. executes the create command;
3. requires exactly one valid Docker network ID from stdout;
4. independently performs `docker network inspect <name>`;
5. requires the inspected raw ID to equal the ID returned by create;
6. normalizes the inspection and verifies the empty isolated-network base policy;
7. only then issues a `DockerModelNetworkLease` containing the hashed network ID,
   profile fingerprint, create-command fingerprint and Engine observation.

A failed `docker network create` never triggers cleanup by name.

If post-create verification fails, cleanup is attempted only after a fresh inspection
shows that the current raw network ID is still the exact ID created by this supervisor.

### Peer attestation

After the AGENT and model containers have been attached, `attest_peers()`:

1. verifies current network ownership;
2. independently inspects the AGENT container;
3. independently inspects the declared model peer container;
4. re-verifies the network ownership after the peer inspections;
5. delegates the final exact-two-peer/single-network proof to ADR-054's independent
   verifier.

The caller must supply the expected hash of the AGENT container ID and model-peer
container ID. Container names therefore do not substitute for ownership identity.

### Teardown

`release()` first re-verifies the network ID from the lease. Only an owned network is
removed. The supervisor then inspects the name again:

- inspection failure means the named network is absent, which is the expected state;
- the same ID still present is a teardown failure;
- a different ID means the name was reused and is reported as a race instead of being
  removed.

## Security rationale

The control plane must remain independent of the attacker-controlled model/agent. The
agent cannot grant itself a network, choose a broader network, replace the model peer or
cause cleanup of another Docker resource merely by influencing a name.

This design also preserves the core distinction:

- `MODEL_COMPROMISE` describes adversarial model behavior;
- `SYSTEM_COMPROMISE` requires an independently verified unauthorized effect.

A compromised model does not become a system compromise merely because the model says
that a tool/network action succeeded. Network and system-state evidence remain separate.

## Fail-closed conditions

The supervisor refuses admission or operation when any of the following occurs:

- Docker server version cannot be queried or parsed;
- Docker server major version is below the profile minimum;
- network create fails or does not return exactly one valid ID;
- post-create network ID differs from the create ID;
- the fresh network is not empty or violates ADR-054's base network properties;
- a lease's profile fingerprint does not match the requested profile;
- the network ID changes before peer inspection, during peer inspection, or before
  teardown;
- container or network inspection is malformed;
- teardown cannot be verified.

## Measurement and identity

Docker server version and per-run network ID are execution evidence. They do not by
themselves redefine the logical Blue model/application identity.

The stable network profile fingerprint is security-relevant target/runtime provenance.
Per-run lease and attestation fingerprints must be stored with execution evidence so a
result can be reproduced and audited without treating ephemeral resource IDs as a new
security target.

## Scope limits

This ADR still does not launch the AGENT or model peer onto the network. The existing
OpenCode Docker sandbox profile remains `--network none` until a separately reviewed
network-attached launch profile composes container confinement with ADR-054/055.

It also does not:

- expose host-native Ollama;
- permit general Internet access;
- publish model or OpenCode ports;
- perform real model inference;
- claim Docker Desktop/GPU qualification.

## Consequences

### Positive

- closes Docker network name-reuse and cleanup races;
- turns Docker Engine 28+ from documentation knowledge into runtime admission evidence;
- gives peer attestation a trusted network ownership token;
- reuses the same trusted-control-plane pattern already proven for container lifecycle;
- remains fully testable with deterministic fake command output and no Docker daemon.

### Costs

- adds a second trusted lifecycle primitive alongside container supervision;
- requires later orchestration to compose network, model-peer and AGENT leases in the
  correct creation/teardown order;
- real Windows/Docker Desktop qualification remains pending.

## Follow-up

1. define a network-attached AGENT sandbox profile that preserves all existing Docker
   confinement controls while binding ADR-054's network profile;
2. define/attest the model-peer launch profile and model health probe;
3. compose both resource leases into a `TargetTrialLeaseProvider`;
4. qualify the Docker Desktop/GPU path locally on Windows;
5. only then run a bounded OpenCode + local-model smoke campaign.
