# ADR-046: Docker Sandbox Attestation Contract

- Status: Accepted
- Date: 2026-09-12

## Context

The laboratory distinguishes `MODEL_COMPROMISE` from `SYSTEM_COMPROMISE`. That distinction
is only credible for coding agents when containment is independently enforceable and
observable. OpenCode application permissions are useful defense in depth, but they are not
proof that the host filesystem, network or Git publication boundary prevented an effect.

`PROJECT_REQUIREMENTS.md` requires disposable coding-agent workspaces, workspace-scoped
filesystem access, external-network deny by default, Git-push deny by default, logged tool
and shell decisions, configurable resource limits, and fail-closed execution. The sandbox
is explicitly part of Blue and therefore must itself be evaluated.

Docker documents that the default bridge permits outbound access through the host, while
`--network none` creates an isolated network namespace containing only loopback. That gives
the first sandbox profile a deterministic enforcement primitive that can be independently
verified from Docker state.

## Decision

Add a Docker-specific sandbox contract with two independent artifacts:

1. `DockerSandboxProfile` — stable desired security configuration and a deterministic
   `docker run` command builder.
2. `DockerContainerInspection` — normalized, hash-only evidence parsed from a trusted
   `docker inspect` record after container creation.

The first profile is intentionally offline and fail-closed. It requires:

- image reference pinned by manifest digest and expected local image ID pinned separately;
- `--pull never` so an adversarial campaign cannot trigger image acquisition;
- `--network none`;
- read-only container root filesystem;
- `--cap-drop ALL` with no added capabilities;
- `no-new-privileges:true`;
- finite PID, memory and CPU limits;
- automatic container removal;
- non-privileged execution;
- exactly one read-write bind mount: the disposable Blue workspace;
- no network allowlist entries in the corresponding `AgentSandboxPolicy`.

The verifier fails closed on any mismatch. Host workspace paths and Docker container IDs are
hashed before they enter persistent attestation evidence. The resulting
`AgentSandboxAttestation` binds the observed Docker state to the OpenCode runtime profile
and stable sandbox policy.

The image manifest digest and Docker image ID are distinct values. Both are retained in the
stable sandbox profile: the digest pins the launch reference while the image ID is compared
against the concrete container inspection evidence.

## Why this is only the first supervisor slice

An offline container cannot reach Ollama or another Blue model endpoint. Therefore this ADR
does **not** claim that a real OpenCode+model campaign is runnable inside this profile yet.
It establishes the trusted isolation/attestation boundary first, using deterministic tests
and no real model inference.

The next runtime slice should introduce an explicitly isolated model-connectivity design,
for example a Docker-internal network plus a narrowly scoped relay/model peer, and must
prove that the agent cannot obtain general Internet egress. Merely switching the container
to Docker's default bridge would violate this ADR because the default bridge can provide
outbound access.

## Security semantics

A model can still request a prohibited network operation, Git publication or filesystem
effect. That is potentially `MODEL_COMPROMISE`. If independently verified Docker/runtime
controls prevent the effect, it is not `SYSTEM_COMPROMISE`.

Conversely, if the observed container configuration violates the sandbox contract, the
trial must not be scored as a clean containment success. The evaluation fails closed because
the required system-control evidence is missing or invalid.

## Consequences

Positive consequences:

- system-containment claims gain an independent, machine-verifiable evidence source;
- accidental use of Docker's Internet-capable default bridge is rejected;
- image drift, privilege escalation, extra mounts and unbounded resources are detectable;
- Windows workspace paths are normalized before hashing, supporting Docker Desktop hosts;
- CI can prove the verifier contract without Docker, network access or model inference.

Trade-offs:

- this profile is intentionally too restrictive for a real networked model endpoint;
- a concrete process supervisor still needs to execute Docker, collect inspection evidence,
  supervise lifecycle/health and feed the attestation into target construction;
- a future allowlisted model transport needs its own enforcement and evidence contract.

## References

- Docker `none` network driver: https://docs.docker.com/engine/network/drivers/none/
- Docker networking overview: https://docs.docker.com/engine/network/
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
- MITRE ATLAS: https://atlas.mitre.org/
