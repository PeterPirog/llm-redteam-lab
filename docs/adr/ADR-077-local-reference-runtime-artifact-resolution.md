# ADR-077: Re-resolve local Reference admission into exact runtime artifact inputs

- Status: Proposed
- Date: 2026-09-13
- Related: ADR-072, ADR-073, ADR-075, ADR-076

## Context

The local-first control plane can now produce two persisted artifacts before inference:

1. an offline Ollama qualification report proving exact local artifacts against a saved
   `/api/tags` observation;
2. a local Reference admission bundle binding the configured Red roles and selected Blue to
   those exact artifacts.

Later runtime admission layers require provider-neutral `ModelArtifactIdentity` objects, not
only hashes copied from JSON. Re-reading the qualification report without checking the prepared
bundle would permit configuration/report drift between preparation and execution.

## Decision

Add an offline runtime-input resolver that consumes:

- the current `ModelsConfig`;
- the current validated `OfflineOllamaQualificationReport`;
- the persisted validated `LocalReferenceAdmissionBundle`.

Before exposing any artifact, the resolver SHALL:

1. require the bundle's qualification-report hash to equal the current report hash;
2. require the bundle's inventory hash to equal the current report inventory hash;
3. require the bundle's artifact-set hash to equal the current report artifact-set hash;
4. recompute the entire Local Reference admission bundle from the current ModelsConfig/report;
5. require byte-semantic equality with the persisted bundle;
6. re-check each participant's artifact identity hash, digest and local classification.

Only then may it expose exact provider-neutral artifacts for:

- `red_planner`;
- `red_mutator`;
- campaign-selected Blue.

## Persisted bundle loading

The JSON bundle stores `bundle_sha256` beside the normalized bundle fields. Loading recomputes
that hash and rejects stale content.

As with the qualification report, this self-hash is content identity rather than
authentication. The loader therefore accepts an optional independently pinned
`expected_bundle_sha256` so a rewritten bundle with recomputed self-hash can be rejected when a
trusted external hash is available.

## Downstream interface

`LocalReferenceRuntimeArtifacts` exposes:

- exact planner artifact;
- exact mutator artifact;
- exact Blue artifact;
- a provider/model keyed Red artifact map;
- a provider/model keyed complete artifact map.

These are existing `ModelArtifactIdentity` objects. This ADR does not define a second artifact
identity type.

The Red map is intentionally keyed by provider/model because the measurement-side artifact
qualification layer resolves configured roles against those keys. If planner and mutator ever
share one underlying artifact, the same artifact may satisfy both configured role lookups; role
identity remains separately bound by `ModelsConfig` and the admission bundle.

## Security consequences

Runtime-input resolution:

- performs no network request;
- performs no Ollama/OpenWebUI call;
- performs no model inference;
- starts no Docker container;
- grants no tool/filesystem/network capability;
- does not prove that a runtime has loaded the admitted bytes.

It closes a control-plane TOCTOU boundary only. The later model-peer supervisor must still
attest the exact staged bundle and runtime ownership before inference.

## Testing

Deterministic tests cover:

- persisted bundle hash validation;
- independently pinned bundle hash;
- exact provider-neutral artifact resolution;
- current ModelsConfig drift;
- qualification-report/artifact drift;
- inventory identity mismatch.

No model inference, Ollama daemon, Docker daemon, GPU, external network or cloud API is required.

## Follow-up

After real CI execution is restored, the exact artifacts exposed here should be wired into:

1. artifact-qualified Red policy preparation/admission;
2. artifact-qualified Blue target admission;
3. verified model-peer bundle staging and runtime attestation.

That integration should consume this resolver rather than re-parsing role labels or mutable model
names.
