# ADR-057: Ownership-aware networked AGENT process supervisor

Status: Proposed

## Context

ADR-056 defines the stable confinement and attestation contract for an AGENT container
that may communicate only with one peer on the isolated model network. The laboratory
also needs a trusted process owner that performs the real Docker lifecycle without
allowing container or network name reuse to turn a stale identifier into authority.

The existing offline `DockerProcessSupervisor` cannot simply be reused unchanged because
its launch contract intentionally requires `--network none`. Mutating it would change the
meaning of an already established runtime path.

## Decision

Add `DockerNetworkedAgentSupervisor` as a separate trusted control-plane component.

### Launch sequence

Before starting the AGENT it independently executes `docker network inspect` and verifies
that the current raw network ID hashes to the supplied `DockerModelNetworkLease`. This is
required before `docker run`: checking only after launch could briefly attach the AGENT to
a reused, unauthorized network name.

It then:

1. launches the AGENT using `DockerNetworkedAgentProfile` with `shell=False` through the
   shared Docker command-runner contract;
2. captures the full container ID returned by Docker;
3. independently inspects the named container and requires exact raw-ID equality;
4. asks `DockerModelNetworkSupervisor.attest_peers()` to re-check network ownership and
   independently inspect both AGENT and model peer;
5. builds the ADR-056 networked sandbox attestation and requires the container proof and
   network proof to describe the same AGENT;
6. returns a `DockerNetworkedAgentLease` containing only hash-safe ownership and
   attestation material.

### Cleanup

A failed `docker run` never triggers cleanup by name. If any post-launch verification
fails, cleanup first re-inspects the name and removes it only when the exact raw container
ID still equals the ID returned by the successful launch.

Normal release similarly verifies lease ownership before stop/removal and verifies
absence afterwards. Name reuse is reported as an error and the replacement resource is
never removed.

The supervisor owns only the AGENT container. Model-peer and model-network leases remain
owned by their respective supervisors so teardown order can be explicit and forensic
evidence can identify which resource failed cleanup.

## Security properties

- attacker-controlled text never becomes shell syntax;
- a stale Docker name is never treated as authority;
- network ownership is checked before the AGENT process starts;
- peer membership is independently re-checked after launch;
- successful inference is not used as containment evidence;
- the AGENT cannot add a network or peer through this control-plane API;
- `MODEL_COMPROMISE` and `SYSTEM_COMPROMISE` remain separate outcomes.

## Scope limits

This ADR does not yet launch the model peer, prove model readiness, provide host-to-OpenCode
request transport, or create a `TargetTrialLeaseProvider`. Those are the next milestones.
No Docker daemon or live model inference is required by CI.