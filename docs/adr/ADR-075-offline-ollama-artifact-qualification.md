# ADR-075: Qualify local Ollama artifacts offline before any model inference

- Status: Proposed
- Date: 2026-09-13
- Related: ADR-068, ADR-072, ADR-073

## Context

The first local runtime step should establish what exact model artifacts are available before
any Red, Blue, Judge or forensic role performs inference. Model names and UI labels are
insufficient because:

- mutable tags can resolve to different weights;
- an OpenWebUI/Ollama inventory entry may appear local at the connection layer while carrying
  `remote_host` or `remote_model` metadata;
- a correct model name is not evidence of the expected manifest digest;
- qualification must be reproducible without requiring another provider call.

The repository already has `OllamaArtifactContract`, which verifies one predeclared model
against an Ollama `/api/tags` response and produces the provider-neutral
`ModelArtifactIdentity` / `ModelArtifactObservation` used by later admission layers.

PR #77 also defines a local smoke artifact declaration document with this shape:

```yaml
version: 1
provider: ollama
source: <operator inventory identity>
require_local: true
artifacts:
  model:tag:
    digest: sha256:<manifest digest>
    roles: [role-label]
```

## Decision

Add an offline multi-artifact qualification layer that consumes:

1. a predeclared artifact contract document;
2. a previously saved JSON `/api/tags` payload.

The verifier SHALL make no network request and SHALL perform no model inference.

Every declared model must:

- resolve to exactly one inventory record;
- have no effective remote proxy classification when `require_local=true`;
- expose an exact SHA-256 manifest digest;
- match the predeclared digest;
- provide a valid non-negative artifact size.

Failure of any declared artifact SHALL fail the entire qualification operation. Additional
undeclared models in the saved inventory are permitted and ignored.

## Output

A successful `OfflineOllamaQualificationReport` records only normalized evidence and hashes:

- source label;
- local-only requirement;
- exact hash of the saved inventory payload;
- normalized contract-set hash;
- one verified artifact observation per declared model;
- semantic artifact-set hash;
- overall report hash.

Raw model weights are never copied into the report.

The report exposes a provider/model keyed mapping of verified `ModelArtifactIdentity` objects so
later provider-neutral boundaries can reuse the same evidence for:

- Blue target artifact admission;
- Red planner/mutator role qualification;
- semantic/multimodal Judge role qualification;
- forensic role qualification;
- verified model-peer staging.

## Exact observation hash versus semantic hashes

The workflow deliberately separates two kinds of hashes.

`inventory_sha256` identifies the exact observed JSON-like payload. Array order is therefore
part of the observation identity. Two provider responses containing the same records in a
different order are different observations and may have different inventory hashes.

`contracts_sha256` and `artifact_set_sha256` identify normalized semantics. They canonicalize:

- artifact mapping order;
- role-label order;
- digest representation through `OllamaArtifactContract`.

Pure YAML presentation changes therefore do not create a new semantic contract identity.

The overall report hash binds both the exact observation hash and normalized semantic hashes.

## Locality

This first offline qualification format is intentionally local-only. The contract document must
use:

```yaml
provider: ollama
require_local: true
```

A matching digest does not override locality. A record containing `remote_host` or
`remote_model` is rejected by the existing `OllamaArtifactContract` even when its digest equals
the declaration.

A future remote/cloud artifact protocol may be introduced separately; it must not weaken the
meaning of a local qualification report.

## Role labels

`roles` are operator-facing intent labels, not executable permissions and not business-logic
model routing. They do not cause any role to invoke a model. Concrete runtime role admission
still uses configured model roles and provider-neutral artifact identities.

This distinction allows the declaration document to list recommended Blue alternatives or
attacker variants without automatically enabling them.

## Security consequences

Offline qualification:

- does not contact Ollama;
- does not contact OpenWebUI;
- does not invoke any local or cloud model;
- does not grant network/filesystem/tool permissions;
- does not start Docker containers;
- does not modify Red/Blue/Judge policy;
- does not claim runtime byte-level attestation by itself.

It proves only that the saved inventory observation is consistent with the predeclared local
artifact contracts. Runtime loading/isolation evidence remains a later model-peer attestation
step.

## Testing

Deterministic tests SHALL cover:

- successful verification of multiple declared local artifacts;
- ignoring additional undeclared inventory entries;
- semantic hash stability under YAML mapping/role reordering;
- exact inventory hash sensitivity to observed record ordering;
- remote proxy rejection despite matching digest;
- digest drift rejection;
- missing and duplicate declared-model rejection;
- `require_local=false` rejection for this protocol;
- file-only YAML/JSON loading followed by qualification.

No model inference, Ollama daemon, Docker daemon, GPU, external network or cloud API is needed.

## Follow-up

The next operator-facing step is a thin CLI command that loads these two files and emits a JSON
report. Capturing `/api/tags` from a live local Ollama instance remains an explicit operator or
runtime-qualification action; it is separate from this offline verifier and should occur before
any prompt is sent to a model.
