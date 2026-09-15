# ADR-066: Ollama measurement peers mount exactly one verified staged store read-only

Status: Proposed

Date: 2026-09-15

## Context

ADR-065 created a content-addressed laboratory-owned Ollama store containing exactly one
predeclared model artifact. The next integrity boundary is runtime delivery: qualification
is not meaningful if the model peer can see the operator's mutable Ollama cache, another
model store, a writable model mount, or host-published service ports.

The generic Docker model-peer profile deliberately permits no host mounts. Ollama therefore
needs one narrow exception that preserves all existing confinement properties.

## Decision

Introduce `DockerOllamaStagedPeerProfile`, bound to the stable
`OllamaStagedModelStoreIdentity.identity_sha256` and model ID. Its launch contract adds
exactly:

- one `OLLAMA_MODELS=<absolute container path>` environment entry; and
- one bind mount from the prepared staged store to that path with `readonly` semantics.

The post-launch attestor accepts the peer only when Docker inspection proves:

- the digest-pinned image and all generic model-peer confinement invariants still hold;
- exactly one mount exists;
- the mount source hashes to the prepared stage path;
- the destination equals the declared `OLLAMA_MODELS` path;
- the mount is read-only;
- there is exactly one `OLLAMA_MODELS` environment entry and it has the expected value;
- no host ports are published;
- the container belongs only to the expected isolated model network; and
- GPU device requests are absent unless explicitly enabled, in which case exactly one
  all-GPU request is required.

The attestation stores host-path hashes and stage identity hashes, never raw host paths.

## Security consequences

The running peer cannot silently gain visibility of the operator's complete mutable model
cache or an additional host mount. A writable model store, duplicate/redirected
`OLLAMA_MODELS`, published port, extra network, or unexpected GPU device request fails
closed.

The host stage path remains ephemeral operational state; measurement identity is the stable
stage identity plus runtime attestation.

## Follow-up

1. compose staged-store launch/attestation into the model-peer lifecycle supervisor;
2. run the trusted `rt-ollama-probe tags` only after staged-peer attestation;
3. bind the returned exact artifact identity back to the staged-store identity;
4. compose model-peer proof with OpenCode environment/health/transport evidence;
5. expose the complete runtime as a `DISPOSABLE_SANDBOX` target-trial lease.
