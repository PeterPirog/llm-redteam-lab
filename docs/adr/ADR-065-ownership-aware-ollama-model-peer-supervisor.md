# ADR-065 — Ownership-aware lifecycle for a verified Ollama model peer

**Status:** Proposed

## Context

ADR-060 defines the provider-independent Docker model-peer confinement boundary. ADR-061
binds measurements to an exact model artifact. ADR-063 creates a minimal independently
verified Ollama model store, and ADR-064 binds that store read-only to the model peer.

The remaining gap is lifecycle enforcement. A pure launch profile does not prove that the
artifact remained qualified immediately before execution, that the network/container name
still belongs to the expected object, or that cleanup targets only the owned peer.

## Decision

Add a trusted `OllamaModelPeerSupervisor` outside Blue/model code.

### Admission order

For each peer lease the supervisor MUST:

1. require the network lease to bind the declared isolated-network profile;
2. require the supplied bundle contract to bind the stable Ollama peer profile;
3. re-verify every staged manifest/blob immediately before any Docker command;
4. require the resulting proof to equal the qualified bundle proof;
5. independently inspect the network and require its current ID to match the lease;
6. launch the peer with the ADR-064 command;
7. capture the exact full container ID returned by Docker;
8. independently inspect the named container and require exact raw-ID equality;
9. apply the ADR-064 hardened inspection verifier;
10. re-check network ownership;
11. re-verify the bundle after launch to detect launch-time TOCTOU mutation;
12. perform a configured, shell-free, non-inference readiness command with container
    ownership checks immediately before and after the command.

Any post-launch failure triggers cleanup only when a fresh inspect still proves that the
named container has the exact launched ID. Name reuse never grants deletion authority.

### Readiness is not inference

Readiness answers only whether the declared local model service is operational enough for
an evaluation trial. It MUST NOT send an adversarial prompt, classify model behavior, or
act as a Judge. The command and required JSON fields remain provider configuration.

### Release and artifact drift

Release has two independent obligations:

1. preserve forensic evidence about whether the exact admitted bundle remained stable; and
2. remove the exact owned model process.

Artifact-integrity failure MUST NOT block cleanup. If the caller supplies a different
bundle contract at release, the supervisor records `artifact_contract_matched=false`,
skips verification under that wrong contract, and still proceeds to exact-container
cleanup. If the correct contract is supplied but bytes changed or verification fails,
`artifact_stable=false` is recorded and cleanup still proceeds.

The lease therefore stores both the bundle-contract fingerprint and the prelaunch bundle
proof. Release evidence separately reports contract match, artifact stability and cleanup.

### Teardown ownership

Before destructive cleanup the supervisor independently inspects the container and requires
its current ID hash to equal the lease. It then stops the peer, uses force-remove only as a
fallback, and verifies absence. A different ID under the same name is reported as name
reuse and is never silently treated as successful cleanup.

## Measurement consequences

The stable Blue/model identity remains the ADR-064 profile: exact peer policy + exact model
artifact + exact verified bundle contract. Disposable container IDs, network names and host
staging paths remain per-run evidence.

Readiness success is infrastructure evidence only. It does not change ASR, MCR, SCR or
portfolio-discovery estimands and cannot convert a model compromise into a system
compromise.

## Security consequences

The lifecycle closes the major TOCTOU gaps between artifact qualification, Docker launch
and readiness while preserving the principle that attacker-controlled or corrupted state
cannot expand authority. Destructive actions remain ownership-gated and cleanup remains
higher priority than forensic verification failure.

## Validation

Deterministic fake-runner tests cover:

- two artifact verifications around launch;
- prelaunch artifact drift before any Docker command;
- postlaunch drift with exact-owned cleanup;
- container-name reuse that is never deleted;
- successful release with stable artifact evidence;
- wrong release contract that is reported but cannot block cleanup.

No Docker daemon, GPU, model inference or external network access is required by these
tests.

## Follow-up

Compose network, verified model-peer and networked OpenCode-agent leases into a concrete
`TargetTrialLeaseProvider` at `DISPOSABLE_SANDBOX` strength. Acquisition should be network
→ model peer → AGENT → OpenCode health; release should be the reverse. Only after that
control loop is proven should Windows/Docker Desktop GPU qualification execute real local
inference.
