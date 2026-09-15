# ADR-067: Staged Ollama peer lifecycle proves mount delivery before readiness

Status: Proposed

Date: 2026-09-15

## Context

ADR-066 proves the runtime mount contract for one exact staged Ollama model store. That
proof must be part of container admission, not an optional diagnostic performed after a
peer has already been accepted as ready.

## Decision

`DockerOllamaStagedPeerSupervisor` specializes the generic model-peer lifecycle without
weakening generic ownership and teardown rules. Admission order is fixed:

1. prove the model-network lease is still owned;
2. launch the staged peer with the exact read-only store;
3. inspect the exact returned container ID;
4. attest the staged-store mount and confinement;
5. prove the model network is still owned;
6. execute the trusted non-inference readiness probe while rechecking container ownership;
7. only then issue `DockerOllamaStagedPeerLease`.

Any failure after launch triggers cleanup only after exact container ownership is
re-established. The resulting lease embeds the generic peer lease, staged-store runtime
attestation and stable staged-store identity hash.

## Consequences

A peer cannot become measurement-ready merely because Ollama responds. The exact model
store delivery is a prerequisite to readiness. A rejected mount never reaches the trusted
readiness probe, reducing the chance that evidence from the wrong runtime is accepted.

## Follow-up

The next slice will run `rt-ollama-probe tags` against this exact staged-peer lease and bind
the observed artifact manifest to both the peer profile and staged-store identity before
AGENT traffic is permitted.
