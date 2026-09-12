# ADR-056: Network-attached AGENT sandbox composition

Status: Proposed

## Context

The laboratory already has two independently reviewed security contracts:

1. `DockerSandboxProfile` for an offline coding-agent container with a read-only root
   filesystem, all Linux capabilities dropped, `no-new-privileges`, bounded resources,
   one disposable read-write workspace mount and `--network none`;
2. `DockerIsolatedModelNetworkProfile` plus ADR-054/055 for one internal Docker bridge
   with gateway mode `isolated`, exactly two members (AGENT + model peer), no IPv6 and
   ownership-aware network lifecycle.

A real local OpenCode campaign needs model inference, so the AGENT cannot remain on
`--network none`. Replacing the existing offline profile in place would be undesirable:
its fingerprint already identifies historical Blue runtime policy. It would also mix two
security questions: container confinement and model-network confinement.

OWASP APTS requires sandbox boundaries to be enforced outside the agent's control and to
state the filesystem, network, process/capability and credential boundary. The network
exception therefore cannot be represented as a prompt instruction or an OpenCode
permission alone.

## Decision

Introduce `DockerNetworkedAgentProfile` as a separate stable composition contract.

The composition contains the complete existing Docker sandbox fields plus:

- the stable `DockerIsolatedModelNetworkProfile` fingerprint;
- the hash of the declared model endpoint origin;
- a versioned semantic marker `exact-isolated-model-peer-v1`.

Its `profile_sha256` is computed from the unchanged base sandbox profile fingerprint and
the model-network bindings. It is therefore distinct from the offline sandbox identity
and changes whenever the model-network policy or endpoint changes.

### Launch contract

`DockerNetworkedAgentProfile.docker_run_command()` preserves the offline sandbox's
security controls:

- digest-pinned image and separately attested image ID;
- `--rm`;
- `--pull never`;
- read-only root filesystem;
- `--cap-drop ALL`;
- `no-new-privileges:true`;
- bounded PIDs, memory and CPU;
- exactly one read-write disposable workspace bind;
- fixed workdir inside that workspace;
- no published ports.

The only intentional change is replacing `--network none` with one caller-supplied,
pre-created isolated model-network name. The name is run-specific evidence and is not
part of stable target identity.

### Independent attestation

`attest_networked_docker_sandbox()` requires all of the following before issuing an
`AgentSandboxAttestation`:

- enforcement kind is Docker;
- `AgentSandboxPolicy.enforcement_profile_sha256` exactly equals the composed profile;
- disposable workspace, external-network denial and git-publication denial remain true;
- the general external endpoint allowlist remains empty;
- the composed model-network fingerprint and endpoint hash match the supplied
  `DockerIsolatedModelNetworkProfile`;
- the trusted ADR-054 network attestation binds the same model-network profile and model
  endpoint;
- container inspection and network attestation identify the same AGENT container;
- all original image/rootfs/capability/NNP/resource/workspace checks still pass;
- Docker `NetworkMode` equals the expected isolated per-run network name.

The final sandbox proof hash composes the networked sandbox profile fingerprint, the
container-inspection proof and the independent network-attestation fingerprint.

### Meaning of external-network denial

`external_network_denied=True` remains accurate. The model peer is not an arbitrary
external endpoint or a host service: it is the one peer admitted by the independently
attested isolated model-network boundary. The normal `allowed_network_endpoints` field
stays empty to prevent a second generic egress path.

This distinction is important. The declared model peer is part of the sandbox boundary;
Internet, host services and other Docker peers remain outside it.

## Security rationale

The model and AGENT may both be adversarially influenced. Neither may choose the network,
add peers, attach a second network, publish a port or relax container confinement.
Those properties are owned and verified by the trusted control plane.

The composition does not treat successful model communication as evidence of safe model
behavior. It only establishes the system boundary. `MODEL_COMPROMISE` and
`SYSTEM_COMPROMISE` remain separate measurements.

## Compatibility and identity

The existing `DockerSandboxProfile` is intentionally unchanged. Offline historical
campaigns therefore retain their original enforcement fingerprint and semantics.

A network-attached campaign has a different enforcement fingerprint because the security
boundary genuinely differs. Ephemeral network/container IDs remain execution evidence
and do not create a new logical Blue target on every replicate.

## Fail-closed conditions

Attestation fails when, among other cases:

- a different model-network profile or endpoint is supplied;
- the AGENT container differs between container and network evidence;
- Docker reports `network_mode=none` or any other unexpected network;
- any original sandbox hardening property is weakened;
- a general endpoint allowlist is introduced;
- the workspace mount differs or additional mounts appear.

## Scope limits

This ADR does not yet:

- launch or supervise the model peer;
- execute the network-attached AGENT container;
- provide a host-published OpenCode port;
- expose host-native Ollama;
- run model inference;
- qualify Docker Desktop/GPU behavior on Windows.

## Follow-up

1. add ownership-aware launch/supervision for a network-attached AGENT container;
2. define a minimal model-peer launch profile and health/readiness proof;
3. add a trusted host-to-OpenCode transport that does not publish a general host port,
   preferably an ownership-checked `docker exec` HTTP bridge;
4. compose network, model peer and AGENT leases into `TargetTrialLeaseProvider` with
   `DISPOSABLE_SANDBOX` strength;
5. qualify the complete path locally on Windows/Docker Desktop before any real reference
   campaign.