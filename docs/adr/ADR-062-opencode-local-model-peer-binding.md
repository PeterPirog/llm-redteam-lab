# ADR-062: OpenCode provider configuration must bind the exact isolated local model peer

Status: Proposed

Date: 2026-09-13

## Context

The isolated AGENT path already proves that exactly one AGENT container and one local
model-service container share an internal Docker network. That network proof is necessary
but not sufficient: OpenCode must also be configured to send inference to that exact peer.
Relying on a default `localhost` endpoint is incorrect inside the AGENT container and can
silently invalidate the intended topology.

OpenCode provider configuration is version-sensitive. The established configuration uses
a `provider` section with an OpenAI-compatible npm adapter, while the newer v2 line uses a
`providers` section with an explicit provider package. Inferring the dialect from an
unverified version string would make the measurement contract ambiguous.

## Decision

Introduce `OpenCodeModelPeerBinding` as stable policy with:

- explicit `provider_id` and `model_id`;
- exact model-peer HTTP origin from `DockerIsolatedModelNetworkProfile`;
- an explicit `OpenCodeProviderConfigDialect`;
- a stable `binding_sha256`;
- rendering for the selected OpenCode provider schema;
- fail-closed merge semantics that never overwrite an existing provider section;
- target validation requiring the same provider/model selection and a declared
  `application_version`.

The initial supported dialects are:

1. `provider_v1`: `provider.<id>.npm = @ai-sdk/openai-compatible` with
   `options.baseURL`;
2. `providers_v2`: `providers.<id>.package =
   @opencode/ai/providers/openai-compatible` with `settings.baseURL`.

Both point to `<isolated-model-origin>/v1` and explicitly enumerate the bound model.

## Measurement semantics

The provider dialect is part of the stable binding fingerprint. Changing the dialect,
provider ID, model ID or model endpoint therefore changes measurement configuration even
when the model weights are unchanged.

This binding is separate from `ModelArtifactIdentity`: the latter proves which model
artifact is present, while this ADR proves which model service OpenCode is configured to
address. Both are required for a reproducible isolated AGENT campaign.

## Security consequences

The AGENT cannot silently fall back to a host-local `localhost` service while claiming the
isolated model peer as its Blue model. Existing provider policy is not overwritten during
configuration merge. The endpoint is constrained to a credential-free plain HTTP origin;
transport confidentiality is unnecessary on the internal two-peer Docker network and no
external endpoint is introduced.

No inference is performed by this layer.

## Follow-up

1. bind the rendered provider fragment into the exact OpenCode launch configuration;
2. attest that the running AGENT received that configuration without persisting secret
   values;
3. compose network, verified model artifact/model peer, OpenCode AGENT, health gate and
   Docker-exec control transport into a `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider`;
4. run the first bounded local-only Reference Evaluation after the user supplies the local
   model inventory and the runtime artifacts are qualified.
