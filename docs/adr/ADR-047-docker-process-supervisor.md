# ADR-047: Trusted Docker Process Supervisor

- Status: Accepted
- Date: 2026-09-12

## Context

ADR-046 established a stable offline Docker sandbox profile and an independent verifier for
normalized `docker inspect` evidence. That verifier alone did not control the process
lifecycle. A coding-agent campaign still needs a trusted component that launches the
container, proves that the observed container is the one it launched, rejects a sandbox
before Blue execution if the inspection contract fails, and tears the sandbox down without
risking deletion of an unrelated container.

This component is security infrastructure. It must not accept instructions from Red or from
the Blue model, and its success must not be inferred from model output.

## Decision

Add `DockerProcessSupervisor` as a separate trusted harness boundary.

The supervisor:

1. builds a detached `docker run` command from the predeclared `DockerSandboxProfile`;
2. executes Docker through an injectable command-runner boundary;
3. requires successful launch to return exactly one full lowercase 64-character container
   ID;
4. immediately performs `docker inspect` and requires the inspected ID to equal the launch
   ID before any sandbox attestation is accepted;
5. normalizes and verifies the inspection record using ADR-046 and only then returns a
   `DockerSandboxLease` containing hash-only ownership/evidence identifiers;
6. if attestation fails after ownership is established, force-removes only a container whose
   current ID still matches the ID returned by the successful launch;
7. on normal release, re-inspects the name and verifies the lease's container-ID hash before
   issuing `docker stop` or fallback `docker rm --force`;
8. verifies that the owned container no longer exists after teardown and treats name reuse
   during teardown as an error rather than deleting the replacement container.

A failed `docker run` never triggers cleanup by container name. This is deliberate: a launch
failure can be caused by a pre-existing name collision, and blindly removing that name would
turn the harness itself into a destructive confused deputy.

The production runner uses Python `subprocess.run` with `shell=False`; the unit tests inject a
fake runner and therefore require neither a Docker daemon nor model inference.

## Security semantics

The supervisor is an independent evidence issuer, not a Blue control that can be trusted
because Blue says it succeeded. A lease is returned only after the observed system state
matches the stable sandbox policy.

A valid lease can support a later claim that a prohibited model request was contained, but
it does not by itself prove that every possible unauthorized effect was blocked. System
compromise continues to require effect-specific state verifiers.

## Scope limitation

The current profile remains intentionally offline (`network=none`). The supervisor therefore
does not yet construct a runnable OpenCode+Ollama target. Network/model connectivity is a
separate security design problem because enabling Docker's ordinary bridge would introduce
general egress.

The next networking slice should use a predeclared isolated topology with independently
verifiable network state. Docker's `--internal` networks are a candidate because containers
on such a network can communicate with each other without a normal external default route,
but Docker Desktop host/gateway reachability must be explicitly modeled and verified before
that topology can satisfy a strict model-endpoint-only allowlist.

## Consequences

Positive consequences:

- container lifecycle is now owned by a trusted harness rather than ad-hoc shell commands;
- attestation cannot be issued for a different container that merely reused the same name;
- failed launch does not risk deleting a pre-existing container;
- failed attestation triggers ownership-checked cleanup;
- teardown is itself verified and fails closed;
- the real subprocess boundary is testable without executing Docker in CI.

Trade-offs:

- malformed successful `docker run` output cannot safely establish ownership and therefore
  is treated as a hard failure rather than guessed around;
- real OpenCode health checks and model connectivity remain outside this ADR;
- a future networked supervisor will need network-inspection evidence in addition to the
  container inspection defined by ADR-046.

## References

- Docker `run`: https://docs.docker.com/reference/cli/docker/container/run/
- Docker `inspect`: https://docs.docker.com/reference/cli/docker/inspect/
- Docker internal networks: https://docs.docker.com/reference/cli/docker/network/create/
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
