# ADR-063 — Stage a minimal verified Ollama model store instead of mounting the host cache

Status: Accepted

Date: 2026-09-12

## Context

ADR-061 gives a local Ollama model a stable manifest-bound artifact identity. The generic
Docker model-peer runtime intentionally does not mount the host model cache because a broad,
mutable `~/.ollama/models` view creates two problems:

1. the same host path may change after qualification; and
2. a peer exposed to the full cache can see unrelated models that are not part of the Blue
   target identity.

Current Ollama stores manifests below `OLLAMA_MODELS/manifests` and content-addressed files
below `OLLAMA_MODELS/blobs`. A manifest contains a config descriptor and layer descriptors,
each with a SHA-256 digest and size. Ollama's local model summary reports the manifest
digest and `Manifest.Size()` sums the sizes of config/layer references.

## Decision

Introduce an Ollama-specific artifact-bundle contract and staging operation.

A bundle contains exactly:

- one manifest at its canonical four-component relative manifest path; and
- the unique blob files referenced by that manifest's config and layers.

Admission requires:

- the artifact was already identified as a local Ollama model;
- SHA-256 of the raw manifest bytes equals the predeclared artifact digest;
- manifest schema version is 2;
- every config/layer entry has a valid `sha256:` digest, non-negative size and media type;
- sum of all manifest reference sizes equals the artifact size reported by the qualified
  Ollama inventory;
- duplicate blob digests may be deduplicated in storage only when their declared sizes
  agree;
- every source blob exists inside the trusted models root and matches both declared size
  and SHA-256.

Staging copies bytes into a new control-plane-owned directory. Hard links are deliberately
not used: mutating the ordinary Ollama cache must not mutate an already staged security
target. After copying, the destination is re-hashed in full and must produce the same
verification observation before an atomic rename admits the bundle.

The bundle path itself is per-environment state and is not stable Blue identity. The stable
bundle fingerprint is derived from the artifact identity, manifest identity/path and exact
blob inventory.

## Runtime consequence

A later Ollama model-peer profile may mount only this staged bundle read-only and set
`OLLAMA_MODELS` to the container mount point. It must not regain access to the ordinary host
cache. Network and model-selection enforcement remain separate concerns.

## Performance trade-off

Copying a multi-gigabyte model for every trial would be wasteful. This ADR establishes the
correct security primitive, not the final cache policy. A future trusted cache may reuse a
previously verified staged bundle keyed by `bundle_sha256`; individual disposable trials
can then mount that immutable-qualified bundle read-only without re-copying model bytes.

## External basis

Current Ollama source exposes `OLLAMA_MODELS`, uses separate `manifests` and `blobs`
directories, accepts only SHA-256 blob digests for blob paths, and reports manifest-derived
model identity in the local inventory. This design follows those current storage semantics
without depending on an undocumented mutable host directory as security identity.
