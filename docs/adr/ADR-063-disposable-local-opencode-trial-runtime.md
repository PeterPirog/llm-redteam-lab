# ADR-063: Disposable local OpenCode trials use verified staged model artifacts

Status: Proposed

Date: 2026-09-14

## Context

AGENT evaluation requires a stronger boundary than transcript/session reset. Every trial
must receive a fresh Blue workspace and a fresh OpenCode process, while the local model
service must remain unreachable from the host/network except through the isolated AGENT
network.

The generic model-peer policy deliberately rejects all host mounts. An Ollama container,
however, needs access to model files. Mounting the operator's complete mutable Ollama
cache would make artifact identity and containment dependent on unrelated host state.

A second lifecycle issue exists at the campaign boundary: `TargetTrialLeaseProvider`
currently has synchronous teardown while OpenCode's Docker-exec target exposes an async
`aclose()`. Full disposable-provider integration must not report cleanup complete until
both the async target transport and synchronous Docker/filesystem resources are closed.

## Decision

### 1. Blue workspace is separate from attack fixture

Use `DisposableWorkspaceSupervisor` for Blue application state. It materializes an
immutable project template under a laboratory-owned root and proves initial/final tree
hashes. It is intentionally separate from `LocalFixtureRuntime`, which remains the
lifecycle for adversarial fixture inputs.

### 2. Stage exactly one Ollama artifact

Use `OllamaModelStagingSupervisor` to build a content-addressed evaluator-owned model
store from:

- one predeclared model manifest;
- the config blob referenced by that manifest;
- only the layer blobs referenced by that manifest.

The manifest digest must equal the `OllamaArtifactContract`. Every blob is verified by
SHA-256 and declared size before and after copy. Unknown source-cache content is never
copied. Existing stages are reverified before reuse.

The staged store is immutable campaign infrastructure rather than per-trial mutable state.
It may be reused across trials because the model container receives it read-only.

### 3. Permit one provider-specific read-only mount

`DockerOllamaStagedPeerProfile` specializes the generic no-mount peer policy. The only
additional host mount is the exact staged model-store directory to `OLLAMA_MODELS`, with
Docker inspection requiring `RW=false`. Additional mounts, host ports, networks or weaker
sandbox settings fail closed.

The generic `DockerModelPeerProfile` remains unchanged and mount-free.

### 4. Use a laboratory-owned non-inference probe

The staged peer image includes the dependency-free `rt-ollama-probe` binary. It exposes
only two local operations:

- `version`: GET `/api/version`, normalized to readiness JSON;
- `tags`: GET `/api/tags`, returned as JSON for artifact verification.

The probe has a fixed `127.0.0.1:11434` origin, accepts no arbitrary URL and performs no
generation/inference call. It is built into an image whose builder and Ollama base images
are supplied as digest-pinned references.

### 5. Bind observed artifact to Blue identity

`model_digest` in `TargetIdentity` carries the predeclared/verified Ollama manifest digest.
It remains separate from `configuration_hash`; runtime policy and model artifact are
independent measurement dimensions.

A runtime target is admitted only when:

1. staged artifact identity matches the peer profile;
2. peer container ownership and read-only staging attestation succeed;
3. `/api/tags` matches the predeclared manifest digest;
4. the isolated network binds that exact peer container to the AGENT;
5. OpenCode environment/command attestation succeeds;
6. OpenCode health/version matches the predeclared target;
7. Docker-exec transport, sandbox policy and model selection produce exactly the
   predeclared `TargetIdentity`.

### 6. Required acquisition order

A future `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider` must acquire in this order:

1. prepare fresh Blue workspace;
2. create isolated Docker model network;
3. launch staged Ollama model peer;
4. verify exact model artifact through the owned peer;
5. launch networked OpenCode AGENT;
6. attest OpenCode command/environment;
7. verify OpenCode health/version;
8. construct Docker-exec target;
9. compare runtime and predeclared target identity;
10. return trial isolation attestation.

Any failure unwinds only resources whose exact ownership has already been proven.

### 7. Required teardown order

Successful release must occur in this order:

1. asynchronously close target/Docker-exec HTTP client;
2. stop and verify removal of AGENT container;
3. stop and verify removal of model-peer container;
4. remove and verify isolated Docker network;
5. hash and remove disposable Blue workspace.

The staged model artifact is not deleted per trial because it is immutable read-only
campaign infrastructure. Teardown evidence must aggregate each owned resource proof.

## Security consequences

The model service cannot write to the operator's model cache or staged artifact. The AGENT
cannot access host networking or the model files directly. Model names/tags are not
accepted as content identity. Mutable Blue workspace is recreated per trial, while immutable
model content may be safely shared read-only across replicates.

The full provider MUST remain unavailable until the async target-close lifecycle is wired
into campaign teardown. Reporting `cleanup_complete=true` while an owned async target is
still open is forbidden.

## Compatibility

Existing offline model-peer, fixture runtime and in-memory lease providers are unchanged.
This is an additive high-assurance path for local OpenCode + Ollama AGENT campaigns.

## Follow-up

1. add the async target-close step to the common trial-release lifecycle without changing
   isolation evidence semantics;
2. implement `DockerOpenCodeTargetTrialLeaseProvider` from the acquisition/teardown order
   above;
3. add deterministic failure-injection tests for every acquisition step and reverse cleanup;
4. qualify the probe image, Docker Desktop GPU path and Windows host-path normalization
   locally;
5. after the user supplies local model inventory, create the first local-only Red/Blue/Judge
   role assignment and bounded Reference Evaluation profile.
