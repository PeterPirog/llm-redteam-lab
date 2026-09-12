# ADR-061 — Model artifact identity is separate from model name and runtime configuration

Status: Accepted

Date: 2026-09-12

## Context

A mutable provider tag such as `model:latest` is not sufficient identity for a security
measurement. Two campaigns may use the same human-readable model name while resolving to
different weights, quantization, templates or manifests. That silently invalidates
cross-run comparison and regression claims.

The existing Docker model-peer profile binds provider/model names and runtime/container
policy, but intentionally does not claim that a model name proves artifact equality.

For Ollama, the local model inventory endpoint (`GET /api/tags`) reports a SHA-256 digest
for each local model. Ollama server code derives that summary digest from the stored
manifest. The manifest is therefore a useful provider-reported content identity. Runtime
application policy remains a separate target-configuration concern.

## Decision

Introduce a provider-neutral `ModelArtifactIdentity` containing:

- provider ID;
- model ID;
- canonical `sha256:<digest>` artifact identity;
- artifact size;
- local/remote provenance;
- optional descriptive format/family/parameter/quantization metadata.

The artifact has its own stable `identity_sha256`. It is not folded implicitly into a
model name.

Introduce `ModelPeerArtifactBinding` to compose one exact artifact identity with one
model-peer policy fingerprint. Provider and model IDs must match exactly.

Add an Ollama-specific adapter, `OllamaArtifactContract`, which:

1. predeclares the expected model ID and manifest digest;
2. parses a local `/api/tags` inventory response;
3. requires exactly one matching record;
4. rejects remote/proxy records when local execution is required;
5. canonicalizes both bare 64-hex and `sha256:` forms;
6. fails closed on digest mismatch or malformed inventory;
7. stores only hash-safe observation evidence.

## Measurement semantics

Artifact identity, runtime/application configuration and sandbox policy are independent
measurement dimensions.

Changing the artifact digest while keeping the same model name creates a different model
artifact. Changing OpenCode/system/runtime policy while keeping the same artifact creates
a different Blue target configuration. A disposable container ID is per-run evidence and
must not become stable target identity.

## Security consequences

A model name alone can no longer support a reproducibility or regression claim. Local
qualification must prove the predeclared artifact digest before the model peer is admitted
into a comparable campaign.

This ADR does not yet authorize a mutable host model-cache mount. A later artifact-staging
or read-only provider adapter must ensure the model peer can access only a verified artifact
without allowing attacker-controlled content to expand permissions or silently substitute a
model.

## External basis

Ollama's documented local-model inventory returns a SHA-256 `digest`, and current server
code populates the summary digest from `manifest.Manifest.Digest()`. NIST AI 800-3 also
reinforces explicit estimands and assumptions: evaluation claims should identify which
sources of variability are held fixed and which are generalized over.
