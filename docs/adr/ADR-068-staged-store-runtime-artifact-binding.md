# ADR-068: Runtime Ollama artifact proof must bind back to the exact staged store

Status: Proposed

Date: 2026-09-15

## Context

The current high-assurance Ollama path has three independently useful proofs:

1. a content-addressed staged store built from one exact manifest;
2. a running staged peer whose only model mount is that store, read-only; and
3. a trusted runtime `/api/tags` observation proving one exact local model artifact.

Those proofs are insufficient if they can be combined from different runs or different
stores. A qualification result must prove one continuous identity chain from staged bytes
to the container that serves the AGENT.

## Decision

Introduce `DockerOllamaStagedArtifactVerifier` and
`DockerOllamaStagedArtifactBinding`.

Before any runtime inventory probe, the verifier requires exact agreement among:

- staged-store identity hash;
- staged-store model ID;
- peer profile staged-store hash;
- staged-peer lease staged-store hash;
- staged-store attestation hash and peer-profile hash;
- staged attestation container ID and generic peer-lease container ID;
- artifact contract model ID and canonical manifest digest; and
- artifact-probe peer-profile hash.

Only after those static bindings agree does the existing trusted
`DockerOllamaArtifactVerifier` execute `rt-ollama-probe tags` against the still-owned
container. The resulting observed artifact digest must equal the staged-store manifest
digest.

The composite proof stores only stable hashes and identities. It includes the staged-store
identity hash, staged-peer lease proof hash, staging-attestation proof hash, peer-profile
hash, container-ID hash, artifact-identity hash and artifact-verification proof hash.

## Consequences

Evidence from one staged store cannot be combined with a peer or artifact observation from
another runtime while still producing a valid composite proof. Bare and `sha256:` manifest
digest declarations remain equivalent because comparison uses the canonical contract
digest.

This closes model-peer identity from staged bytes through runtime observation. It still
performs no model inference.

## Follow-up

The next high-assurance slice can now compose this closed model-peer proof with the already
merged OpenCode launch/environment proof, health observation and Docker-exec transport.
That composition is the remaining prerequisite before exposing a real
`DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider` and running the first bounded HAL smoke.
