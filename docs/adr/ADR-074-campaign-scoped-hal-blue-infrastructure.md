# ADR-074: Campaign-scoped HAL Blue infrastructure precedes per-trial AGENT leases

- Status: Accepted
- Date: 2026-09-18

## Context

The first HAL OpenCode smoke has two different state lifetimes.

The exact Blue Ollama model peer and its isolated Docker network can be shared for a bounded
campaign because they are read-only model-serving infrastructure. In contrast, attacker-
influenced OpenCode application state and the writable Blue workspace must be recreated for
every statistical trial.

The repository already verifies each lower-level boundary independently:

- content-addressed exact Ollama staging;
- read-only staged peer confinement and readiness;
- trusted non-inference artifact probing;
- exact staged-store -> runtime artifact binding;
- owned isolated Docker model networking;
- networked OpenCode runtime/environment/health admission;
- disposable Blue workspaces;
- per-trial `DISPOSABLE_SANDBOX` target leases.

A missing campaign coordinator would force operators to manually connect those proofs and
could make teardown ordering or evidence binding ambiguous.

## Decision

Add `HalSmokeBlueInfrastructureSupervisor`.

### Admission order

Before any Docker call, require the offline composition, staged store and Blue artifact
contract to agree exactly on:

- Blue model ID;
- local-only artifact policy;
- exact manifest digest;
- staged-store identity;
- staged-peer profile.

Then, in order:

1. create and own the isolated model network;
2. launch the exact staged Ollama peer;
3. require staged-store mount/confinement and readiness evidence;
4. run the fixed trusted `rt-ollama-probe tags` artifact verifier;
5. require the runtime artifact proof to bind the same network peer, container, profile and
   staged store;
6. issue one campaign-scoped infrastructure lease.

These steps perform no model inference.

### Per-trial handoff

A still-active campaign infrastructure lease can construct
`DockerOpenCodeTrialLeaseProvider`.

The provider receives:

- the exact owned network lease;
- the exact model-peer container identity;
- the stable Blue measurement binding from offline composition;
- the live exact model-peer artifact proof.

The stable measurement binding participates in target snapshot identity. The live artifact
proof is instead folded into each trial's fresh-state evidence; it is a runtime observation,
not a stable logical target property.

### Teardown order

Campaign teardown is retry-safe and strictly ordered:

1. remove the exact model peer;
2. only after peer removal succeeds, remove the isolated network.

If peer teardown fails, the network is preserved. A subsequent release call can retry. A
failed admission follows the same peer-before-network cleanup rule.

Per-trial OpenCode targets/workspaces must already have been released before campaign
infrastructure teardown. Docker ownership checks remain the final enforcement mechanism if an
operator violates that lifecycle.

## Consequences

The live HAL path now has a single trusted boundary from an offline exact configuration to the
campaign-scoped Blue runtime and then to fresh per-trial AGENT targets.

No mutable model tag, container name or host endpoint is sufficient evidence by itself.

The supervisor is fully unit-testable with fake lower-level supervisors; CI still requires no
Docker daemon, GPU, model credential or external inference.
