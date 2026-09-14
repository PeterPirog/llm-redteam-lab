# Execution provenance

Security measurements need two distinct kinds of reproducibility information:

1. **measurement protocol** — what the experiment estimates and how it is scored;
2. **execution provenance** — which independently admitted runtime conditions were used.

`llm-redteam-lab` stores these separately. This avoids turning runtime-specific facts into
metric semantics while still making changes in the execution environment visible in the
campaign identity.

## Contract

`ExecutionProvenanceDescriptor` is a campaign-independent, hash-bound descriptor with:

- a schema version;
- a stable `kind` identifier;
- a JSON payload containing only hash-safe execution metadata;
- a canonical SHA-256 content hash.

A campaign may have at most one descriptor of a given `kind`. Persistence is idempotent for
an exact repeat and fail-closed for an attempted mutation. The descriptor hash is recomputed
immediately before persistence so mutating a nested payload after model validation cannot
silently write inconsistent provenance.

The database key is `(campaign_id, provenance_kind)`. Loading a descriptor reconstructs its
canonical hash and rejects database tampering.

## Binding to reference experiments

Reference evaluation validates all supplied execution-provenance descriptors before Red or
Blue inference. Descriptor kinds must be unique and are sorted canonically.

For each paired baseline/treatment campaign:

1. the map `provenance_kind -> content_hash` is included in the campaign configuration hash;
2. the descriptors are persisted immediately after campaign creation;
3. the measurement snapshot binds the resulting campaign configuration hash;
4. only then may trial execution begin.

Changing execution provenance therefore changes the measurement identity even if attack
policy, target alias, corpus and scoring protocol remain unchanged.

The same descriptors are attached to both arms of one paired reference experiment. This
prevents execution-environment drift from becoming an uncontrolled difference between the
baseline and treatment arms.

## Local HAL admission provenance

`reference-run` currently emits the descriptor kind:

`local_model_admission_v1`

Its payload comes from `LocalOnlyAdmissionReport` and contains:

- the normalized model-inventory hash;
- role labels and model IDs;
- per-model inventory-record hashes;
- inference-endpoint hashes;
- the selected Blue model ID.

It deliberately does **not** persist raw endpoints, prompts, credentials, secret values,
OpenWebUI user IDs or access grants.

For this project, **local means model inference executed by models hosted locally on HAL**.
The normal single-machine profile runs the harness on HAL and talks to Ollama through
loopback. If the harness is later split across trusted machines, a HAL LAN hostname must be
explicitly admitted; public hosts are never inferred as local merely from a model name.

The admission descriptor proves the model record was not an Ollama remote proxy and that the
configured route remained inside the trusted local boundary. It does not by itself prove
machine identity.

## What admission provenance does not prove

A mutable model tag such as `qwen3.8:latest` is not a stable artifact identity. Local-only
admission records the observed inventory record, but qualification-grade comparisons require
an independently predeclared artifact contract.

The next stronger layer uses `OllamaArtifactContract` and `ModelArtifactIdentity` to bind a
selected model ID to an exact Ollama manifest digest. Instrumentation smoke remains lighter:
it validates the execution plumbing without requiring artifact pinning. Policy qualification
must fail closed when the required exact artifact cannot be proven.

Likewise, the string `HAL` is not machine attestation. Future runtime/sandbox provenance may
add independently verified host, container, network, model-peer and application observations
as additional descriptor kinds. The generic execution-provenance table is intentionally
extensible for those facts.

## Security invariants

Execution provenance must remain safe to persist and compare. New descriptor kinds should:

- store hashes or non-secret identifiers rather than secret values;
- never store credentials or authentication tokens;
- avoid raw attack/target prompts unless another evidence policy explicitly authorizes them;
- be collected before the inference they are intended to qualify;
- fail closed when required evidence is missing, ambiguous or internally inconsistent;
- use a versioned `kind` when semantics change incompatibly;
- include only facts that the implementation can actually observe or verify.

A label or operator assertion must not be upgraded into an attestation without a technical
verification mechanism.