# ADR-054: Isolated model-network attestation

Status: Proposed

## Context

The coding/AGENT target needs a model connection, but the existing Docker sandbox is
deliberately launched with `--network none`. That profile is useful evidence of external
network denial, but a real OpenCode target cannot reach a model through it.

Replacing `--network none` with Docker's ordinary bridge is not an acceptable shortcut.
The default bridge gateway mode provides outbound connectivity through the Docker host.
Likewise, `--internal` alone is not a sufficient high-assurance boundary: ordinary
internal bridge networks normally still have an address on the Docker host, so peers can
reach host services through the bridge address.

Docker Engine 28 added bridge gateway mode `isolated` for internal networks. In this
mode the internal bridge has no address on the Docker host. Peers on the bridge can still
communicate with each other, while the bridge itself does not provide the ordinary host
gateway path.

The laboratory must therefore prove the concrete network topology independently of the
agent. OpenCode output, model output, prompt content and attacker-controlled files are
not trusted evidence of containment.

## Decision

Introduce `DockerIsolatedModelNetworkProfile` and an independent inspection verifier.
The first high-assurance model-network profile is intentionally narrow:

1. the Docker driver is `bridge`;
2. the network is `internal=true`;
3. `com.docker.network.bridge.gateway_mode_ipv4=isolated`;
4. IPv6 is disabled for this first profile;
5. the network is local and not an ingress network;
6. the network contains exactly two peers: the Blue AGENT container and one declared
   local-model container;
7. both peers are running;
8. both peers have an IPv4 address on this network and no IPv6 address;
9. the declared model endpoint hostname is bound to the model peer's container/network
   name;
10. Docker container inspection must independently show that each peer is connected to
    exactly this network and to no second Docker network;
11. the network carries a trusted profile-fingerprint label created by the harness;
12. all persisted evidence is hash-only with respect to container IDs and network names.

The resulting `DockerIsolatedModelNetworkAttestation` is issued by the trusted harness,
not by Red, Blue, OpenCode or the model.

The network profile fingerprints the model endpoint host and port, exact-member policy,
single-network membership requirement and gateway/isolation semantics. A material
change to any of those conditions therefore changes the security configuration identity.

## Why exact two-peer and single-network membership

An internal network is not sufficient if a model relay or agent is also attached to a
second Internet-capable network. Such a dual-homed peer could become an unintended
bridge around the laboratory's containment claim.

The first profile therefore rejects:

- an unexpected third peer;
- an AGENT container attached to another Docker network;
- a model peer attached to another Docker network;
- a model endpoint name that does not identify the attested model peer.

This is deliberately stricter than a general-purpose Docker deployment. It gives the
laboratory a small, auditable initial security boundary.

## Interaction with MODEL_COMPROMISE and SYSTEM_COMPROMISE

The network attestation is containment evidence only. It does not prove that the model
resisted an adversarial instruction.

A model may still be `MODEL_COMPROMISE` while the sandbox/network/authorization layers
prevent the forbidden system effect. That result is not `SYSTEM_COMPROMISE`.
Conversely, the absence of valid network/sandbox evidence must never be interpreted as
successful containment.

## Measurement semantics

This decision does not change ASR, MCR, SCR, the bounded-conversation trial unit or the
multi-attacker discovery estimands. It only strengthens the execution-environment proof
for AGENT targets.

Network-profile and attestation fingerprints belong in the target/runtime provenance.
Per-run container and network identities are evidence and must not destabilize the
logical Blue target identity.

## Engine-version boundary

Gateway mode `isolated` is available in Docker Engine 28 and later. The network verifier
proves the observed network configuration itself, but this ADR does **not** yet claim a
complete Docker runtime admission gate.

The supervisor milestone following this ADR must independently query and bind the Docker
server version, require a qualified Engine version, create the network, verify the exact
returned network ID, manage both container leases, attest membership, and remove only
resources whose ownership is still proven.

Until that lifecycle exists, this module is a deterministic attestation primitive rather
than evidence that a real OpenCode+model campaign has run safely.

## Model placement

The initial high-assurance topology uses a containerized local model or a dedicated
model service container on the same isolated network. It does **not** treat a native
host Ollama service as equivalent evidence.

Host-native Ollama may be supported later only through a separately designed and
attested transport that cannot silently restore general host or Internet reachability.
A dual-homed relay is not allowed by this profile.

## Fail-closed conditions

Attestation fails if any of the following is observed:

- non-bridge or non-local network;
- `internal=false`;
- ingress network;
- IPv6 enabled;
- IPv4 gateway mode other than `isolated`;
- missing or mismatched profile fingerprint;
- missing, extra or substituted peer;
- missing IPv4 or unexpected IPv6 member address;
- model peer name mismatch;
- stopped peer;
- either peer attached to any second Docker network.

Malformed or incomplete Docker inspection data also fails closed.

## Consequences

### Positive

- preserves a network-level distinction between a usable local model connection and
  general outbound connectivity;
- makes the containment claim independently inspectable and reproducible;
- prevents a dual-homed peer from silently expanding the attacker's permissions;
- keeps the model endpoint inside the same disposable security domain as the AGENT;
- supports the project's requirement that attacker-controlled content cannot widen
  authorization.

### Costs / limitations

- requires Docker Engine 28+ for the intended `isolated` gateway semantics;
- requires a containerized model/model service for the first high-assurance path;
- GPU passthrough and model-container qualification remain separate implementation
  work, especially under Docker Desktop on Windows;
- this ADR alone does not start Docker, prove engine version, probe model health or
  prove an end-to-end OpenCode inference path.

## Follow-up

1. add ownership-aware isolated-network lifecycle to `DockerProcessSupervisor` or a
   dedicated trusted network supervisor;
2. add Docker Engine server-version admission and evidence;
3. start/attest the model peer and AGENT peer without publishing ports;
4. add a trusted model-health probe and bind it to the network attestation;
5. compose the resulting sandbox/network lease with `TargetTrialLeaseProvider`;
6. run a small local OpenCode+model smoke campaign only after all of the above pass.

## External references

- Docker Engine 28 release notes, networking section: isolated gateway mode for internal
  bridge networks.
- Docker bridge-network and port-publishing documentation: default bridge/NAT behavior,
  internal networks, and gateway modes.
- OWASP Agent Control Standard (2026): agent systems should be inspectable, traceable,
  instrumentable and subject to runtime control.
- NIST AI 800-3 (2026): evaluation targets and assumptions should be explicit; runtime
  security evidence remains separate from statistical estimands.
