# ADR-048: OpenCode Container Health Admission Gate

- Status: Accepted
- Date: 2026-09-12

## Context

ADR-046 and ADR-047 establish an independently verified Docker isolation boundary and an
ownership-aware lifecycle supervisor. Those controls prove how a container is isolated and
which container the harness owns. They do not prove that the expected OpenCode server
actually started inside that container or that the observed server version matches the Blue
target configuration.

OpenCode currently documents `GET /global/health` as the canonical server-health endpoint.
The endpoint returns a health boolean and application version. For an offline Docker sandbox,
Docker `network=none` creates only a loopback interface, so the supervisor can probe the
OpenCode server from inside the already-owned container without enabling external network
access.

Runtime health is per-run evidence. It must not fragment the stable Blue target identity,
but stale health from one container must never authorize a replacement container.

## Decision

Introduce a separate `OpenCodeHealthObservation` and require a health-gated wrapper before a
supervised OpenCode target is admitted for campaign execution.

The Docker supervisor performs the probe with these rules:

1. Re-verify lease ownership with `docker inspect` before probing.
2. Execute a constant Python standard-library probe inside the container against
   `http://<loopback>:<port>/global/health`.
3. Do not invoke a shell and do not place a password value in the command arguments. If the
   runtime uses HTTP Basic authentication, the probe reads the configured password variable
   from the container environment.
4. Require one valid JSON object with `healthy: true` and a non-empty `version`.
5. Re-verify lease ownership after the response, so a name-reuse race cannot produce trusted
   health evidence for a different container.
6. Persist only hashes of the endpoint/response plus the application version, runtime-profile
   hash, sandbox-attestation hash and container-ID hash.

`HealthGatedOpenCodeTarget` then verifies that the health observation binds the same runtime
profile and per-run sandbox attestation as the attested target and that the observed OpenCode
version equals `TargetIdentity.application_version`.

The health proof is exposed in provider metadata but is deliberately excluded from the stable
configuration hash. Two isolated replicates of the same Blue policy remain the same security
target; a different configured OpenCode version remains a different target through the
existing target identity.

## Security semantics

A passing health probe is not evidence that the model is safe. It is admission evidence that
the intended application instance is alive inside the intended containment boundary.

Infrastructure failure, malformed health output, version mismatch, ownership change, or stale
sandbox evidence fails closed and must not be counted as a Blue defense success.

This preserves the project distinction:

- `MODEL_COMPROMISE` is established by model behavior/evidence;
- `SYSTEM_COMPROMISE` requires an independently verified unauthorized system effect;
- a healthy sandboxed server is only the measurement substrate for those claims.

## Consequences

Positive consequences:

- campaign evidence cannot silently refer to a dead or replacement OpenCode process;
- the tested application version is checked against live runtime evidence;
- health checks do not require opening the offline sandbox to external networking;
- per-run health evidence does not corrupt statistical target identity across replicates.

Remaining work:

- provide the real OpenCode container image/profile and pass the deterministic runtime
  environment into the supervised container;
- add a model-connectivity topology that permits only the authorized local model path while
  preserving independently verifiable external-network denial;
- run the first bounded local OpenCode + MCP + local-model smoke on the user's machine.

## References

- OpenCode server API: https://opencode.ai/docs/server/
- Docker none network driver: https://docs.docker.com/engine/network/drivers/none/
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
