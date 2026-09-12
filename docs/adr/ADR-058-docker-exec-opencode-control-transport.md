# ADR-058: Ownership-checked Docker exec transport for loopback OpenCode

Status: Proposed

## Context

The hardened AGENT container intentionally publishes no host ports and is attached only
to the isolated model network. OpenCode itself is bound to loopback inside that
container. The laboratory control plane still needs to create sessions, submit messages
and fetch durable message evidence.

Publishing OpenCode with Docker `-p` would introduce a second network path and weaken the
claim that the AGENT has only the declared model peer. Adding another bridge network
would violate the exact-single-network attestation from ADR-054/056.

OpenCode's current server contract exposes normal HTTP endpoints including
`/global/health`, session creation, `/session/:id/message` and persisted message reads.
The transport mechanism can therefore change without changing the application protocol.

## Decision

Add `DockerExecHttpTransport`, an `httpx.AsyncBaseTransport` that executes a constant
Python stdlib HTTP client inside the already-owned AGENT container via `docker exec`.

For every request the transport:

1. validates that the requested origin is exactly the predeclared loopback host/port from
   `OpenCodeRuntimeProfile`;
2. independently inspects the Docker container and requires the current full container ID
   to match the per-run ownership hash;
3. serializes only HTTP method, path/query, non-sensitive headers and body as data
   arguments to a constant in-container client script;
4. performs the HTTP request against loopback from inside the container namespace;
5. returns a bounded JSON/base64 response envelope;
6. independently re-checks container ownership before accepting the response.

No shell is invoked and request data is never executable command text.

## Authentication

`Authorization`, `Cookie` and `Proxy-Authorization` headers are never forwarded through
Docker process arguments. When OpenCode Basic authentication is configured, the constant
in-container client obtains the password from the predeclared container environment
variable named by `OpenCodeRuntimeProfile.server_password_env`.

The password value therefore does not appear in the host-side `docker exec` argv.

## Identity

`DockerExecHttpProfile` has a stable fingerprint that binds the OpenCode runtime profile,
Python executable and transport mechanism version. Per-run container name/ID are excluded
from that stable profile and remain execution evidence.

A later integration wrapper must bind this stable transport profile into the complete
OpenCode target-policy fingerprint before reference measurements are run.

## Security properties

- no host port publication;
- no second Docker network;
- loopback origin is fixed by trusted runtime configuration;
- exact container ownership is checked before and after every HTTP exchange;
- Docker name reuse fails closed;
- Basic-auth secrets are not passed in argv;
- hostile prompt text is base64 data consumed by a constant script, not shell syntax;
- transport success is not a security verdict and cannot establish `SYSTEM_COMPROMISE`.

## Scope limits

This ADR does not yet wire the transport into `OpenCodeTarget`/`AttestedOpenCodeTarget`,
launch the model peer, or run inference. CI uses a fake Docker runner only.

## Follow-up

1. bind the stable transport fingerprint into the attested OpenCode target identity;
2. use the transport for session/message/durable-evidence calls;
3. add a separately attested model-peer lifecycle and readiness check;
4. combine all resource proofs in a disposable `TargetTrialLeaseProvider`;
5. qualify the complete Windows/Docker Desktop path locally before real campaigns.