# ADR-062: OpenCode provider configuration binds the exact isolated HAL model peer

Status: Proposed

Date: 2026-09-15

## Context

The isolated AGENT path can prove that exactly one AGENT container and one model-service
container share a dedicated internal Docker network. That network proof is necessary but
not sufficient: OpenCode must also be configured to send inference to the exact peer named
by that network policy. A correctly isolated container with a default or drifted provider
configuration is not a valid measurement environment.

OpenCode currently has two explicitly different provider configuration dialects that are
relevant to the project. The established schema uses a singular `provider` section with an
AI SDK `npm` adapter and `options.baseURL`; OpenCode V2 uses `providers` with `package` and
`settings.baseURL`. Both support OpenAI-compatible local endpoints. The harness must not
guess this dialect from an application-version string.

## Decision

Introduce `OpenCodeModelPeerBinding` with stable identity over:

- the exact `DockerIsolatedModelNetworkProfile.profile_sha256`;
- provider ID;
- model ID;
- exact credential-free HTTP model-peer origin including its port; and
- an explicit `OpenCodeProviderConfigDialect`.

The supported dialects are:

1. `provider_v1`: `provider.<id>.npm = @ai-sdk/openai-compatible` with
   `options.baseURL`;
2. `providers_v2`: `providers.<id>.package =
   @opencode/ai/providers/openai-compatible` with `settings.baseURL`.

Both render `<isolated-model-origin>/v1` and enumerate the bound model. Existing provider
sections are never overwritten during configuration composition.

`OpenCodeNetworkedLaunchPolicy` then composes the binding with the existing deny-by-default
`OpenCodeRuntimeProfile`. It emits only non-secret environment values plus names of secret
environment variables. Its `NetworkedOpenCodeLaunchPlan` extends stable target-policy
identity with both the model-binding hash and networked-launch-policy hash.

Finally, `DockerNetworkedOpenCodeAgentProfile` includes the networked launch policy in the
Docker enforcement fingerprint and refuses command drift or a model binding created for a
different model-network profile.

## Measurement semantics

The following are measurement-significant and change fingerprints:

- network profile;
- peer endpoint;
- provider ID;
- model ID;
- provider dialect;
- OpenCode runtime profile;
- rendered provider configuration; and
- launch command/public environment contract.

A model-peer binding is intentionally separate from `ModelArtifactIdentity`. Artifact
identity answers **which weights/configuration are present**. This ADR answers **which
service OpenCode is configured to address through which isolated topology**. A later
runtime composition must require both.

## Security consequences

- OpenCode cannot silently use a default host-local endpoint while the measurement claims
  a different isolated peer.
- A binding cannot be reused with another Docker model-network profile merely because the
  hostname happens to look similar.
- Secret values are not included in stable profiles, hashes or launch-plan serialization;
  only environment-variable names are carried.
- Provider configuration cannot replace a pre-existing provider section implicitly.
- Changing the model peer changes stable target-policy identity, not merely Docker command
  bytes.

This layer performs no model inference and does not contact Docker or Ollama.

## Follow-up

1. independently inspect the running AGENT environment and prove that the bound public
   configuration and secret-name contract were actually delivered;
2. compose exact `ModelArtifactIdentity`/`ModelPeerArtifactBinding` with the networked
   OpenCode peer;
3. bind health-gate and Docker-exec transport evidence;
4. expose the resulting runtime as a `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider`;
5. only then perform the first bounded HAL instrumentation smoke.
