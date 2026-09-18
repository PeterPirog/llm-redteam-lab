# ADR-078: Live Red artifact recheck is a non-inference pre-campaign gate

- Status: Accepted
- Date: 2026-09-18

## Context

Offline HAL preflight binds the exact planner and mutator artifacts into a stable
`red_measurement_binding_sha256`. That is necessary but not sufficient for a live run:
a mutable Ollama runtime could change after the saved qualification snapshot and before the
first Red inference.

For the project, "local" means model execution occurs on the HAL runtime boundary. The first
smoke uses direct local Ollama. Therefore the runtime must be rechecked immediately before
Red inference without spending model tokens or invoking a generation endpoint.

## Decision

Add a dedicated live Red artifact recheck.

The recheck:

1. resolves the configured Red planner and mutator roles;
2. requires Ollama, local role classification, explicit endpoint and no fallback chain;
3. validates that inference endpoints are loopback by default or explicitly trusted HAL
   hosts;
4. fetches only Ollama `/api/tags`;
5. caches a shared tags endpoint so planner and mutator on the same runtime require one GET;
6. verifies each model against its prequalified exact manifest digest;
7. rejects Ollama remote/cloud proxy metadata;
8. recomputes the full provider-reported artifact identity, including size and stable model
   metadata;
9. requires the fresh artifact identity hash to equal the qualified artifact identity;
10. recomputes the same stable Red measurement binding from the fresh observations;
11. requires the observed binding to equal the predeclared binding.

The output is hash-safe `RedRuntimeArtifactRecheck` evidence. Raw tags payloads are not
persisted.

The verified report can be converted to immutable campaign execution provenance with kind
`red_runtime_artifact_recheck_v1`.

## Transport

`HttpxLocalOllamaTagsProbe` is the production acquisition adapter. It performs only an HTTP
GET to `/api/tags` derived from the already validated inference endpoint.

The verifier accepts an injected probe protocol so CI uses deterministic fake or
`httpx.MockTransport` implementations and never contacts a real model runtime.

## Failure semantics

Any of the following blocks the campaign before Red inference:

- predeclared Red measurement binding mismatch;
- nonlocal/untrusted endpoint;
- provider or role-policy mismatch;
- fallback model configuration;
- missing or duplicate model entry;
- remote Ollama proxy metadata;
- manifest digest drift;
- artifact size/metadata identity drift;
- transport, HTTP or JSON protocol failure.

## Consequences

A live HAL smoke can prove that the exact planner/mutator artifacts used at campaign start
still match the offline qualified attacker identity without consuming inference tokens.

Stable Red identity remains part of the attack-policy fingerprint. This live recheck remains
runtime execution provenance; the two concepts are deliberately separate.
