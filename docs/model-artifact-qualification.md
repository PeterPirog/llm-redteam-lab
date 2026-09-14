# HAL model artifact qualification

## Purpose

The project uses two different but complementary meanings that must not be conflated:

1. **HAL-local execution** — the harness invokes a model through the runtime operating on the HAL machine (loopback by default, or an explicitly trusted HAL host in a future split deployment).
2. **Local artifact** — Ollama resolves the selected model to weights stored locally rather than to a remote proxy (`remote_model` and `remote_host` are absent).

The default zero-cloud / zero-paid-inference profile requires both conditions. This preserves the operator-facing meaning of **local = invoked locally on HAL** while still preventing an Ollama cloud proxy from being mistaken for a free local artifact.

## Stage policy

`INSTRUMENTATION_SMOKE` is intended to validate the end-to-end harness with minimal local compute. Local-model admission is sufficient for that stage.

`POLICY_QUALIFICATION` requires stronger reproducibility. Every admitted model must be predeclared with an exact Ollama manifest SHA-256 and verified against a saved local Ollama `/api/tags` snapshot before model inference begins.

The intended evidence chain is:

```text
OpenWebUI /api/models snapshot
        |
        v
LocalOnlyAdmissionReport
  - admitted model IDs
  - local/remote-proxy decision
  - route fingerprints
        |
        v
OllamaArtifactContractSet
  - exact predeclared digest for every admitted model
        |
        +------ saved local Ollama /api/tags snapshot
        |                 |
        v                 v
ReferenceArtifactQualificationReport
  - admission proof hash
  - contract-set hash
  - tags-snapshot hash
  - exact artifact identity/observation hashes
        |
        v
campaign execution provenance
```

## Fail-closed rules

Artifact qualification fails before inference when any of the following is true:

- the contract set does not exactly cover the model IDs admitted for the run;
- a contract model ID is duplicated;
- `/api/tags` does not resolve exactly one declared model;
- the observed manifest digest differs from the predeclared digest;
- the observed model is a remote Ollama proxy;
- the digest in `/api/tags` disagrees with the digest in the OpenWebUI inventory used for local admission; or
- the artifact size in `/api/tags` disagrees with the admitted inventory record.

The cross-check between the two saved inventories is deliberate. A qualification run must not silently combine an admission snapshot from one model state with an artifact snapshot from another.

## Contract document

Qualification uses a YAML or JSON document with one exact contract per admitted model. Real HAL digests are intentionally not committed until a fresh local snapshot is captured. A schematic document is:

```yaml
version: 1
contracts:
  - model_id: <red-planner-model>
    expected_manifest_digest: sha256:<exact-64-hex-digest>
    require_local: true
  - model_id: <red-mutator-model>
    expected_manifest_digest: sha256:<exact-64-hex-digest>
    require_local: true
  - model_id: <blue-model>
    expected_manifest_digest: sha256:<exact-64-hex-digest>
    require_local: true
```

Do not copy placeholder digests into a qualification run. The contract must be produced from a fresh HAL observation and then treated as a frozen experimental input.

## When HAL becomes necessary

No HAL access, Ollama daemon, GPU, model inference or cloud API is required to develop and unit-test the qualification logic. Synthetic snapshots are sufficient for CI.

HAL becomes necessary only when we are ready to perform the first real execution:

1. save a fresh OpenWebUI `/api/models` response;
2. save a fresh local Ollama `/api/tags` response from the same model state;
3. generate/freeze exact artifact contracts for the models selected for the run; and
4. execute the bounded instrumentation smoke, followed later by qualification.

Until that point the project can continue to be developed entirely through GitHub/GPT without consuming model-inference tokens or paid cloud calls.
