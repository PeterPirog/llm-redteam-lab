# ADR-059: Transport-bound OpenCode target identity and container-managed authentication

Status: Proposed

## Context

ADR-058 introduced an ownership-checked `docker exec` HTTP transport so the laboratory
control plane can reach OpenCode on container loopback without publishing a host port or
adding a second Docker network. Directly injecting that transport into the existing
`OpenCodeTarget` is insufficient for two reasons.

First, normal `OpenCodeTarget` Basic authentication resolves the configured password from
the host process environment. In the isolated AGENT design the secret should exist only
inside the disposable container. Requiring the host to duplicate the secret would widen
the credential boundary and defeat the purpose of ADR-058.

Second, changing control transport or authentication username changes the security target
configuration. Those stable settings must affect Blue identity, while disposable
container names/IDs must not.

## Decision

Add `DockerExecOpenCodeTarget`, a specialized `OpenCodeTarget` for the isolated Docker
runtime.

### Authentication ownership

The target validates that `OpenCodeConfig.password_env` exactly matches
`OpenCodeRuntimeProfile.server_password_env`, but it does not read the password on the
host. Its HTTP auth hook returns no host-side credentials. `DockerExecHttpTransport`
reconstructs Basic authentication inside the owned container using the password from the
predeclared environment variable.

The transport profile now explicitly fingerprints the Basic-auth username. The username
is not secret, so it may be passed as a process argument; the password value may not.

### Stable target identity

`DockerExecOpenCodeTarget.identity.configuration_hash` composes:

- the ordinary OpenCode target configuration hash; and
- `DockerExecHttpProfile.profile_sha256`.

The transport profile includes the runtime profile hash, username, Python executable and
transport mechanism version. Changing any of these therefore changes the logical Blue
target configuration.

Per-run container name and container-ID hash are intentionally excluded from stable Blue
identity. They are emitted in provider metadata as execution evidence instead.

The existing `AttestedOpenCodeTarget` may wrap `DockerExecOpenCodeTarget`. Its existing
stable runtime/sandbox policy fingerprint is then composed with the transport-bound base
target identity without changing historical host-reachable OpenCode targets.

### Protocol behavior

Session creation, message submission and persisted-message retrieval still use the normal
`OpenCodeTarget` implementation. Only the HTTP transport and authentication ownership are
different. Durable tool/message evidence therefore keeps the existing normalization and
judgment semantics.

## Security properties

- the OpenCode password need not exist in the host environment;
- password values never appear in host-side Docker argv;
- auth username and transport policy are measurement provenance;
- disposable container identity remains evidence, not logical target identity;
- transport cannot change the declared loopback origin;
- ownership checks occur around every HTTP exchange;
- existing runtime/sandbox attestation remains independently required;
- transport success is not a Judge verdict and does not imply `SYSTEM_COMPROMISE`.

## Compatibility

The ordinary `OpenCodeTarget` and its historical configuration hash remain unchanged.
Only the new Docker-exec specialization gets the additional transport policy binding.

## Validation

CI uses a fake Docker runner to execute a complete synthetic OpenCode flow:

1. create session;
2. submit message;
3. retrieve persisted message;
4. verify durable trace semantics;
5. verify no host password environment is required;
6. verify stable identity across disposable container replicates;
7. verify username changes target identity;
8. fail closed on password-environment binding mismatch.

No real model inference or Docker daemon is required.

## Follow-up

The next execution milestone is a separately attested model-peer lifecycle/readiness
contract. After that, network lease, model peer, networked AGENT, OpenCode health and this
transport can be composed into a `DISPOSABLE_SANDBOX` `TargetTrialLeaseProvider` for local
qualification.