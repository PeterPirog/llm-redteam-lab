# ADR-017: Direct ComfyUI Target Uses Durable History as Evidence

## Status

Accepted

## Context

`image_generation` is a first-class Blue target class. The project already has provider-independent image artifacts, multimodal judging and image-specific safety/utility metrics, but it requires a real local target adapter before image evaluation can move beyond deterministic mocks.

The user's normal environment includes a local ComfyUI installation. ComfyUI exposes an API-format workflow graph and local server endpoints that allow a client to queue execution, inspect execution history and fetch generated files. Current official examples use `/prompt`, `/history/{prompt_id}` and `/view`; websocket events are an optional completion/progress mechanism. Newer Comfy API v2 documentation also adopts a poll-first model in which durable job state is authoritative and streams are only an enhancement.

The lab must not confuse transient progress events with durable output evidence, silently ignore unsupported multimodal/session semantics, or persist raw generated image bytes in ordinary experiment records.

## Decision

### Target identity

Direct ComfyUI is represented as:

- `target_class = image_generation`
- `target_mode = PIPELINE`
- `provider = comfyui`
- `application = ComfyUI`

It is a pipeline rather than a raw model because a ComfyUI workflow includes checkpoint/model selection, conditioning, samplers, schedulers, latent/image processing and output nodes.

The target configuration hash binds at least:

- ComfyUI endpoint,
- declared model identity,
- API-format workflow hash,
- prompt input binding,
- seed bindings/default seed,
- selected output nodes,
- application version when known.

The same underlying checkpoint used through a different workflow or application therefore becomes a different Blue target configuration.

### Workflow mutation

The operator supplies a ComfyUI workflow exported in API format. Runtime prompt and seed values are bound only to explicitly configured node inputs.

The stored workflow is never mutated in place. Every execution deep-copies the workflow before applying runtime values. Missing nodes or input names are configuration errors detected before backend I/O.

### Reproducibility

If the workflow exposes one or more configured seed bindings, an authorized seed is mandatory. The seed comes from request metadata or the target's configured default. Missing/invalid seeds fail before execution.

The seed is recorded in normalized metadata and in the image artifact identity.

### Durable evidence

Execution flow is:

```text
render API-format workflow
        |
        v
POST /prompt
        |
        v
prompt_id
        |
        v
GET /history/{prompt_id} until complete
        |
        v
recorded output references
        |
        v
GET /view
        |
        v
hash-verified ImageArtifact + EvidenceRecord
```

The prompt ID is hashed before entering normalized evidence. Raw server prompt IDs are not persisted in ordinary evidence.

A websocket completion event may be added later as a latency optimization, but it cannot replace durable history verification.

### Image artifacts

Only images referenced by the durable history record are ingested. Raw image bytes are passed to the configured `ImageArtifactStore` and do not enter ordinary SQL/evidence records.

Normalized image evidence retains:

- artifact reference,
- SHA-256 content hash,
- MIME type,
- width and height,
- seed,
- workflow hash,
- output type.

The adapter accepts PNG, JPEG and WebP outputs and determines image dimensions without introducing a heavyweight image-processing dependency.

### Session and multimodal input semantics

Direct local ComfyUI does not provide conversational memory. Therefore:

- `TARGET_MANAGED` is rejected,
- replay requests containing prior conversation messages are rejected,
- image/multimodal input artifact references are rejected until an explicit upload/workflow binding implementation exists.

This prevents a false experiment where the harness believes context or an input image reached Blue when the target actually ignored it.

Multi-turn T2I memory testing belongs to a stateful application/pipeline adapter such as OpenWebUI + ComfyUI, not to direct ComfyUI.

### Fail-closed measurement

The following never count as Blue defense success:

- queue HTTP/protocol errors,
- history timeout,
- failed execution status,
- missing durable outputs,
- missing images,
- invalid/unsupported image bytes,
- artifact persistence/integrity errors.

They are measurement errors and ultimately produce `ERROR` through the campaign engine.

## Consequences

### Positive

- first real local image-generation target,
- no cloud inference required,
- reproducible seed/workflow identity,
- evidence semantics aligned with OpenCode's durable-state principle,
- raw image content remains opt-in,
- future Comfy API v2 transport can reuse the same target/evidence contract.

### Negative

- direct ComfyUI does not yet test chat-memory jailbreaks,
- image-to-image input is intentionally unsupported in this first adapter,
- legacy local endpoint polling can be less efficient than websocket-assisted completion,
- model identity is operator-declared rather than inferred from every possible custom workflow node.

## Follow-up

1. Add an optional Comfy API v2 transport profile while retaining target identity semantics.
2. Add explicit `/upload/image` plus workflow input bindings for authorized image-to-image tests.
3. Add an OpenWebUI image pipeline target for prompt rewriting, filters and true conversational T2I memory tests.
4. Run the first local smoke campaign only after all deterministic CI gates are green.
