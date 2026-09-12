# ADR-064 — Bind a verified Ollama artifact bundle to the isolated model peer

**Status:** Proposed

## Context

ADR-060 introduced a provider-independent Docker model-service peer. ADR-061 added
content identity for model artifacts, and ADR-063 stages one manifest-bound Ollama model
into a minimal independently verified filesystem bundle.

Those contracts are insufficient by themselves. A real Ollama peer must consume the exact
qualified artifact without mounting the ordinary mutable host Ollama cache. Mounting the
full cache would expose unrelated models and would allow same-path content changes to hide
behind an unchanged model name.

The user environment is Windows with Docker Desktop/WSL2. Docker may represent a Windows
bind-mount source differently inside its Linux VM, so comparing the host path string to the
`docker inspect` source string is not a portable security primitive.

## Decision

Introduce an Ollama-specific edge adapter while keeping the core model-peer runtime
provider-independent.

`OllamaModelPeerProfile` composes:

- the unchanged `DockerModelPeerProfile` fingerprint;
- the exact `ModelPeerArtifactBinding`;
- the minimal `OllamaArtifactBundleContract`;
- the independent bundle-verification proof;
- stable container-visible model-store path and environment-variable name.

The per-run staged host path is intentionally excluded from stable Blue identity.

### Launch contract

The launch command preserves ADR-060 hardening and adds exactly one model-store bind:

- bind the staged minimal bundle;
- mount it read-only;
- expose it at a fixed container-visible path (`/models` by default);
- set `OLLAMA_MODELS` to that path;
- publish no ports;
- attach only to the isolated model network;
- preserve read-only rootfs, `cap-drop ALL`, no-new-privileges and configured resource
  limits;
- preserve explicit GPU admission rather than enabling GPU implicitly.

The adapter contains no model-name special cases. Model names remain configuration data.

### Inspection semantics

Independent Docker inspection must prove:

- exact expected image ID and running state;
- non-privileged, read-only root filesystem;
- `cap-drop ALL` and no-new-privileges;
- exact CPU/memory/PID policy;
- no published ports;
- GPU device request iff GPU was declared;
- exactly one network, the declared isolated network;
- exactly one bind mount;
- the model mount has the exact container destination and `RW=false`;
- `OLLAMA_MODELS` points at that destination.

For Docker Desktop portability, the attestation stores separately:

1. SHA-256 of the requested host bundle path; and
2. SHA-256 of the mount source observed by Docker inspection.

It does not assert that the two path strings are identical because Windows→WSL2/Docker-VM
namespace translation is legitimate. The exact launch command and both hashes remain
available for forensic comparison.

## Measurement semantics

The composed profile is part of stable Blue configuration identity. Disposable container
IDs, network names and host staging paths are per-run evidence, not new Blue targets.

A model name alone is never sufficient evidence that two runs used the same model. The
artifact identity and verified bundle proof are required.

Readiness remains infrastructure evidence, not model inference and not a security verdict.

## Security consequences

This prevents hostile agent/model content from modifying the mounted model store from
inside the peer and prevents accidental exposure of unrelated models from the ordinary
Ollama cache. Host/control-plane mutation is outside the attacker authority model; the
trusted harness should nevertheless re-verify the bundle at lease admission and teardown
when the lifecycle integration is added.

## Follow-up

Add an ownership-aware Ollama peer supervisor that:

1. re-verifies the staged bundle immediately before launch;
2. verifies exact network ownership;
3. launches the composed profile;
4. requires exact container ownership and ADR-064 inspection attestation;
5. performs non-inference readiness;
6. re-verifies bundle bytes before release;
7. tears down only the exact owned peer.

Only after that deterministic path is proven should a local Windows/Docker Desktop GPU
qualification run execute real model inference.
