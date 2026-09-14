# Qualification-grade Ollama artifact pinning

Local HAL admission and exact artifact qualification answer different questions.

- **local admission** proves that the selected model record is not an Ollama remote proxy and
  that the inference route remains inside the admitted local HAL boundary;
- **artifact qualification** proves that a mutable model ID such as `qwen3.8:latest` resolved
  to the exact predeclared Ollama manifest digest used by the experiment.

Instrumentation smoke requires only the first guarantee. `POLICY_QUALIFICATION` requires
both.

## Evidence inputs

Qualification consumes two independent inputs before any Red or Blue client is constructed:

1. an operator-frozen YAML artifact-contract file;
2. a saved local HAL Ollama `/api/tags` JSON snapshot.

The OpenWebUI/Ollama inventory already required by `reference-run` remains the third source.
The qualifier requires all three views to agree for every model actually admitted to the
run.

For each admitted model it verifies:

- exactly one predeclared artifact contract exists;
- the `/api/tags` snapshot resolves exactly one model with that ID;
- the observed manifest digest equals the predeclared digest;
- the observed model is local rather than a remote/proxy entry;
- the `/api/tags` digest equals the digest seen during local model admission;
- the observed artifact size equals the admitted inventory artifact size.

A mismatch blocks the run before inference.

## Contract file

Start from `config/artifact-contracts.hal-quality.example.yaml` for the default stronger HAL
profile. Its digest values are placeholders and must never be treated as qualification
evidence.

The reviewed file has this shape:

```yaml
version: 1
models:
  - model_id: nemotron-3.5-lightning:latest
    manifest_digest: sha256:<64 lowercase hex characters>
  - model_id: gpt-oss:latest
    manifest_digest: sha256:<64 lowercase hex characters>
  - model_id: qwen3.8:latest
    manifest_digest: sha256:<64 lowercase hex characters>
```

Freeze the file before the qualification run. Do not rewrite pins automatically to whatever
happens to be installed at execution time; that would turn an expectation into an
observation and defeat the purpose of the contract.

Only models actually admitted to the run must have contracts. Disabled semantic Judge,
multimodal Judge and forensic roles do not need pins until they are enabled.

## Capturing `/api/tags` on HAL

When execution moves to HAL, capture the control-plane snapshot immediately before the
qualification run. For example in PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/tags |
  ConvertTo-Json -Depth 20 |
  Set-Content -Encoding utf8 .\hal-ollama-tags.json
```

This is a metadata call to the locally running Ollama service; it does not invoke a model.
The resulting JSON is verification evidence, not a secret.

## Qualification command

A qualification run uses the normal local inventory plus both artifact inputs:

```powershell
llm-redteam reference-run `
  --models config/models.hal-local.example.yaml `
  --model-inventory .\hal-model-inventory.json `
  --target-model qwen3.8:latest `
  --target-base-url http://127.0.0.1:11434 `
  --stage POLICY_QUALIFICATION `
  --artifact-contracts .\hal-artifact-contracts.yaml `
  --ollama-tags .\hal-ollama-tags.json
```

If either artifact input is missing, qualification is rejected before model-client
construction. Providing only one of the two files is rejected for every stage because a
partial artifact claim is ambiguous.

## Persisted proof

Successful verification produces the execution-provenance kind:

`ollama_artifact_qualification_v1`

For each used model the payload stores hash-safe identity information:

- model ID and role labels;
- exact `sha256:` manifest digest;
- artifact size;
- admitted inventory-record hash;
- `ModelArtifactIdentity` hash;
- artifact-observation proof hash;
- artifact-contract hash.

The full `/api/tags` snapshot is represented by its canonical SHA-256 hash. Raw credentials,
prompts and secrets are not part of this provenance.

The execution-provenance layer then binds this descriptor into both baseline and treatment
campaign configuration hashes. A changed artifact therefore produces a different campaign
measurement identity even when the human-readable model alias is unchanged.

## Why smoke is different

Instrumentation smoke answers whether the experiment plumbing works: lifecycle, storage,
Red/Blue transport, deterministic scoring, paired ordering and evidence capture. Requiring
manual artifact pinning there would add operational friction without materially improving
that engineering check.

Policy qualification supports comparative security claims, so alias-level identity is not
sufficient. Exact artifacts are mandatory there.

## Remaining stronger guarantee

Artifact pinning proves the exact local model weights/manifest. It does not prove that the
process ran on a particular physical machine merely because the operator calls it HAL.
Host/container/network/model-peer attestation remains a separate execution-provenance layer,
especially for future AGENT and isolated OpenCode campaigns.