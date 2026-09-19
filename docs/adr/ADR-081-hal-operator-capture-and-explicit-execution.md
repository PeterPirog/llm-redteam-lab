# ADR-081: HAL operator flow separates capture, validation and explicit execution

- Status: Accepted
- Date: 2026-09-19

## Context

The first HAL instrumentation smoke now has a complete internal orchestration path, but an
operator still needs to translate local machine state into trusted runtime inputs.

Two classes of state must not be conflated:

1. **captured immutable runtime pins** — exact staged Blue artifact identity, digest-pinned
   Docker image references and their observed local image IDs;
2. **live execution evidence** — current image identity, current staged bytes, current Docker
   ownership, exact Red runtime artifact recheck and per-trial OpenCode attestations.

A single command that silently captures mutable state and immediately executes inference would
reduce auditability and make operator mistakes harder to detect.

## Decision

Expose a three-step operator flow.

### 1. Runtime capture

`hal-smoke-capture-runtime`:

- requires an exact local Blue artifact contract;
- requires the operator to supply the real Ollama manifest-relative path explicitly;
- stages and verifies only the referenced manifest/blobs into the laboratory-owned staging
  root;
- requires digest-pinned OpenCode and Ollama-peer image references;
- resolves their current local Docker image IDs;
- writes a `HalSmokeRuntimePins` document when requested;
- performs no model inference.

The manifest path is never guessed from a model tag.

### 2. Dry validation

`hal-smoke-run` without `--execute`:

- loads the saved local model inventory;
- validates local-only model selection;
- verifies exact artifact qualification from saved local `/api/tags`;
- loads runtime pins;
- composes the exact offline HAL smoke contract;
- selects the fixed built-in safe smoke case and budget profile;
- reports the bound hashes and local paths;
- does not inspect Docker, stage model bytes, require OpenCode secrets, contact Ollama or
  invoke any model.

This is the default behavior.

### 3. Explicit execution

Only `hal-smoke-run --execute` crosses the live runtime boundary.

Before the campaign starts it:

- rechecks the local Docker image IDs against persisted runtime pins;
- reverifies/reuses the exact staged Blue store and requires its identity to equal the pins;
- requires the configured OpenCode secret environment variable to be present, but never
  serializes or hashes its value;
- constructs the real Docker network, model-peer, environment, health and per-trial workspace
  supervisors;
- uses direct local HAL Red model endpoints;
- uses the fixed safe HAL smoke case, independent workspace state verifier and fixed
  system-state Judge;
- executes the already-defined `HalSmokeCampaignRunner`.

The live command returns only hash-safe campaign/runtime evidence.

## Locality

Operator-facing `local` continues to mean model inference through runtimes operating locally
on HAL.

The zero-cloud path additionally requires exact local Ollama artifacts. Remote Ollama proxy
metadata remains disallowed.

## Consequences

The transition from GPT/GitHub development to HAL is now explicit and reproducible:

1. collect fresh inventory/tags;
2. freeze exact artifact contracts;
3. capture runtime pins;
4. dry-validate;
5. explicitly execute one bounded smoke.

CI tests capture and dry-validation behavior with synthetic files and fake Docker command
runners. CI still performs no Docker daemon access, GPU work or model inference.
