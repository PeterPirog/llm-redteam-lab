# ADR-065: Measurement peers receive an exact content-addressed Ollama model store

Status: Proposed

Date: 2026-09-15

## Context

Mounting the operator's normal Ollama cache into a Red/Blue measurement peer would make the runtime depend on mutable, unrelated local content. Exact artifact qualification and the trusted probe are insufficient if the peer can see additional manifests or blobs that were not part of the predeclared model.

The legacy PR #93 introduced content-addressed staging, but its path canonicalization could hide a staging-root symlink and its existing-stage identity file could be treated too authoritatively. The clean implementation must derive admissible content from the artifact contract and manifest, not from mutable stage metadata.

## Decision

Introduce `OllamaModelStagingSupervisor` that copies exactly one manifest and the unique config/layer blobs referenced by it into an evaluator-owned stage keyed by the manifest SHA-256.

Admission requires:

- `OllamaArtifactContract.require_local=true`;
- exact source manifest SHA-256 equal to the contract digest;
- canonical relative manifest path;
- regular non-symlink source manifest and blobs;
- exact SHA-256 and declared size for every referenced blob;
- no duplicate digest with conflicting sizes;
- a laboratory ownership marker on the staging root.

New stages are built in a private temporary directory, fully verified, assigned a stable `OllamaStagedModelStoreIdentity`, then atomically renamed into their content-addressed location.

Existing stages are never trusted merely because `stage-identity.json` exists. Before reuse the supervisor independently re-verifies the manifest, every blob, all hashes/sizes, symlink absence and the exact expected filesystem member set. It then recomputes the expected identity and requires equality with the stored identity.

## Security consequences

- The model peer no longer needs access to the operator's complete mutable Ollama cache.
- Extra staged files are rejected even if an attacker also rewrites `stage-identity.json` to match a new tree hash.
- Direct staging-root, manifest and blob symlinks are rejected before canonicalization/use.
- Traversal and non-canonical manifest paths are rejected.
- A non-empty staging directory without the laboratory ownership marker is never deleted or adopted.

This mechanism is an integrity boundary, not an authorization boundary against an attacker with arbitrary write access to the evaluator account during a run. Runtime ownership and Docker mount attestation remain required.

## Measurement semantics

The manifest digest, manifest relative-path hash, exact staged tree hash, unique blob count and total referenced blob bytes form stable stage identity. The host path itself is ephemeral and is not measurement identity.

## Follow-up

1. mount exactly one prepared store read-only into a digest-pinned Ollama peer;
2. attest that the running container has exactly that single mount and `OLLAMA_MODELS` destination;
3. run the trusted probe against the owned peer and bind the observed artifact back to the stage identity;
4. compose the peer proof with the OpenCode AGENT proof and final `DISPOSABLE_SANDBOX` lease.
