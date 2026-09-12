# ADR-060: Provider-independent isolated model-peer runtime

Status: Proposed

## Context

The isolated AGENT path now has an owned Docker network, a hardened network-attached
AGENT container and an ownership-checked OpenCode control transport. The remaining
runtime dependency is the local model service itself.

Connecting the AGENT to a host-native model service would reintroduce host reachability
into a network that is intentionally configured with Docker Engine 28 isolated gateway
semantics. Publishing model ports or adding a general bridge would similarly weaken the
containment claim.

The laboratory must also preserve provider independence. Ollama is an initial adapter,
not a business-logic assumption. Model runtime image, launch command and readiness probe
therefore need to be configuration and measurement provenance.

## Decision

Introduce `DockerModelPeerProfile` and `DockerModelPeerSupervisor`.

### Stable profile

The profile fingerprints:

- provider ID and model ID;
- digest-pinned container image and separately expected local image ID;
- provider-specific argument-vector launch command;
- provider-specific non-inference readiness command and required top-level JSON values;
- CPU, memory and PID limits;
- explicit GPU-access boolean.

No provider name is special-cased by the supervisor.

### Launch boundary

The model peer is launched:

- detached with `--rm` and `--pull never`;
- with a digest-pinned image;
- on exactly the pre-existing isolated model network;
- under the DNS/container name already declared by
  `DockerIsolatedModelNetworkProfile.model_endpoint_host`;
- with read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges:true`;
- bounded PIDs, memory and CPU;
- with no host port publication;
- with no host mounts;
- with no extra Docker networks.

GPU access is absent by default. When explicitly enabled it is part of the stable profile
and the launch uses Docker's `--gpus all`; independent container inspection must then show
a GPU device request. This is hardware access for the model-service peer, not permission
for the adversarial AGENT container.

The first generic profile intentionally forbids host model-cache mounts. A later
provider-specific adapter may add an independently fingerprinted read-only model-artifact
contract. This avoids pretending that a mutable host path is a verified model identity.

### Ownership and attestation

Before launch the supervisor independently verifies that the current Docker network ID
still hashes to the supplied `DockerModelNetworkLease`.

After launch it captures the full container ID and independently verifies:

- exact raw container-ID equality;
- exact image ID;
- running + auto-remove state;
- non-privileged, read-only root filesystem;
- exact isolated network mode and exactly one network membership;
- no added capabilities and `cap-drop ALL`;
- `no-new-privileges`;
- resource limits no weaker than the profile;
- no published ports;
- no host mounts;
- GPU device request exactly when declared.

Network ownership is rechecked after container inspection.

### Readiness is not inference

The trusted control plane executes the configured readiness argument vector using
`docker exec`. No shell is invoked. Ownership is checked immediately before and after the
probe.

The command must return a JSON object. Configured top-level values must match exactly.
The response is hashed and stored in `DockerModelPeerReadinessObservation`.

Readiness proves only that the declared service/model endpoint is operational enough to
start a trial. It is not a security verdict, does not score the model and cannot establish
`MODEL_COMPROMISE` or `SYSTEM_COMPROMISE`.

### Cleanup

A failed `docker run` never causes deletion by name. Post-launch failures remove the peer
only after a fresh inspect proves that the name still maps to the exact launched raw ID.
Normal release follows the same ownership discipline and refuses to delete a replacement
resource after name reuse.

## Security rationale

The AGENT and model may both process adversarial content. Neither controls Docker network
membership, image admission, resource limits or process cleanup. The model service has no
host ports, no host filesystem mounts and no network except the exact isolated peer
network.

This keeps containment evidence independent from model responses and preserves the core
laboratory distinction between behavioral model compromise and unauthorized system
effects.

## Compatibility and identity

Existing host-native and offline target modes are unchanged. A model-peer profile is a
new stable runtime policy. Per-run container IDs and readiness response hashes are
execution evidence and do not create a new logical Blue target for every replicate.

## Scope limits

This ADR deliberately does not yet define a mutable host model-cache mount or an Ollama-
specific image/command. Such an adapter must bind the actual model artifact/version
without silently broadening filesystem or host-network access.

CI uses a fake Docker runner and performs no model inference.

## Follow-up

1. define the initial provider adapter/configuration (likely Ollama) with a reproducible
   model artifact strategy suitable for Windows Docker Desktop/GPU;
2. compose network, model-peer and networked-AGENT leases with OpenCode health/transport
   into a `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider`;
3. persist acquire/release proofs independently;
4. qualify the complete path locally before Reference Evaluation v1.