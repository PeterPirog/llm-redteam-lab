# ADR-063: Running OpenCode AGENT environment is independently attested and redacted

Status: Proposed

Date: 2026-09-15

## Context

ADR-062 binds the intended OpenCode launch configuration to one exact isolated HAL model
peer and makes that binding part of stable target identity. Intent alone is not sufficient
for a measurement-grade AGENT runtime. The running Docker container may differ because of
operator error, environment injection, command drift, container-name reuse, or a race
between launch and measurement.

Docker `inspect` can expose the effective command and environment, but `Config.Env` also
contains secret values. Persisting or hashing the complete inspection payload would turn
runtime attestation into a secret-retention mechanism and could expose or create durable
hashes of low-entropy credentials.

## Decision

Introduce `DockerNetworkedOpenCodeEnvironmentAttestor` as an independent post-launch
observation step.

Before inspecting Docker it verifies that:

- the AGENT profile names the same model-network profile as the lease's network
  attestation;
- the lease and network attestation agree on the AGENT container identity;
- the lease and network attestation agree on the Docker network identity; and
- the profile's model endpoint matches the endpoint attested for that network.

It then performs an exact, shell-free:

```text
docker inspect --type container <owned-container-name>
```

and fails closed unless:

- the inspected full container ID hashes to the ID held by the lease;
- `Config.Cmd` exactly equals the approved OpenCode launch command;
- every declared public environment variable exists with exactly the approved value; and
- every required secret environment-variable name exists with a non-empty value.

Duplicate Docker environment-variable names are rejected because accepting first/last-win
semantics would make the observation ambiguous.

## Secret handling

Secret values are deliberately excluded from durable evidence:

- a secret value is used only to decide whether its declared environment-variable name is
  present and non-empty;
- it is not stored in the observation object;
- it is not included in any canonical hash;
- it is not copied into the redacted observation; and
- unrelated container environment values are ignored and do not affect the proof hash.

The raw `docker inspect` response exists only transiently at the command boundary. The
project must not log or persist it as measurement provenance.

## Evidence identity

`DockerNetworkedOpenCodeEnvironmentObservation` binds:

- owned container ID hash;
- `DockerNetworkedOpenCodeAgentProfile.profile_sha256`;
- networked OpenCode launch-policy hash;
- isolated model-network profile hash;
- observed command hash;
- observed approved-public-environment hash;
- required secret-name-set hash; and
- a redacted observation hash containing secret names only.

The resulting `proof_sha256` can therefore be persisted without retaining credential
material.

## Consequences

The harness no longer relies solely on the command it attempted to execute. It can prove
that the still-owned running AGENT has the expected application command and configuration
before health checks or target traffic are accepted.

This is still a deterministic infrastructure layer. Unit tests use a fake Docker command
runner and perform no Docker, Ollama, GPU or model inference.

## Follow-up

1. compose this environment observation with the sandbox/network lease and OpenCode health
   observation into one runtime-ready proof;
2. bind exact `ModelArtifactIdentity` to the same model peer/runtime;
3. bind Docker-exec transport to that proof;
4. expose the composition as a `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider`; and
5. only then run the first bounded HAL instrumentation smoke.
