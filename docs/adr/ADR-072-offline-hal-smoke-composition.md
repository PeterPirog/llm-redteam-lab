# ADR-072: Offline HAL smoke composition precedes live runtime admission

- Status: Accepted
- Date: 2026-09-18

## Context

The repository now has the runtime primitives required for a high-assurance OpenCode AGENT
trial: exact local-model admission, artifact qualification, content-addressed Ollama staging,
owned staged peers, model-only Docker networking, OpenCode environment and health
attestation, Docker-exec control transport, disposable workspaces and per-trial
`DISPOSABLE_SANDBOX` leases.

The remaining operator problem is composition. A first HAL smoke needs one deterministic
statement of *what is intended to run* before trusted runtime evidence exists. That statement
must not be confused with runtime admission.

The project uses the following locality semantics:

1. **execution-local**: model inference is invoked through a runtime operating locally on HAL;
2. **artifact-local**: the selected Ollama artifact is an exact local artifact and not a remote
   Ollama proxy.

"Local" in operator-facing language means the first property. The zero-cloud measurement path
requires both.

## Decision

Add a two-step offline preflight contract.

### Static smoke plan

The first instrumentation smoke is intentionally bounded:

- `models.policy.local_first=true`;
- cloud fallback is disabled;
- exactly `red_planner` and `red_mutator` are enabled;
- the first attacker pool is disabled;
- enabled Red roles are Ollama-backed, declared local, use explicit local endpoints and have
  no fallback chain;
- planner requires text+reasoning; mutator requires text;
- Blue is an explicit campaign model;
- the Blue target is a coding `AGENT`;
- minimum Blue isolation is `DISPOSABLE_SANDBOX`.

This stage can be built on GitHub/CI and needs no HAL runtime.

### Offline runtime composition

After fresh HAL inventory/artifact evidence and immutable runtime pins are available, compose
the exact profiles that the live harness must use:

- local-only admission proof;
- exact artifact-qualification proof for Red and Blue;
- exact staged Blue-store identity whose manifest digest equals the qualified Blue digest;
- digest-pinned OpenCode image;
- digest-pinned Ollama/probe peer image;
- isolated model-network profile;
- exact OpenCode-to-model-peer binding;
- OpenCode launch policy;
- hardened networked OpenCode Docker profile;
- Docker sandbox policy;
- exact OpenCode target configuration;
- staged Ollama peer profile.

The composition is deterministic and hashable, but it **never** claims the live runtime is
admitted. `live_runtime_admitted` remains false by construction.

## Required live HAL evidence

Before any AGENT trial executes, the operator path still requires:

- a fresh OpenWebUI/Ollama inventory;
- a fresh local `/api/tags` snapshot;
- an exact Red runtime artifact recheck;
- Docker Engine version evidence;
- the exact owned isolated-network lease;
- staged-store filesystem reverification;
- staged-peer mount/confinement and readiness evidence;
- runtime Blue artifact probe binding;
- disposable-workspace materialization proof;
- running OpenCode environment attestation;
- OpenCode health/version attestation;
- per-trial teardown proof.

These are runtime observations, not configuration fields, and cannot be precomputed in CI.

## Consequences

The first real HAL smoke can now be prepared almost entirely through GPT/GitHub without
spending model tokens or requiring the HAL host. When HAL becomes necessary, the remaining
work is evidence acquisition and live execution, not architecture design.

The current smoke model profile remains a configuration choice rather than an architecture
dependency. It may be changed after fresh HAL inventory is supplied without changing this
contract.
