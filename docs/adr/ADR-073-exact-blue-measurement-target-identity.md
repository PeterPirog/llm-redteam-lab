# ADR-073: Exact Blue measurement configuration participates in target identity

- Status: Accepted
- Date: 2026-09-18

## Context

OpenCode AGENT target identity already includes the stable OpenCode runtime policy, Docker
sandbox policy, isolated model-network policy and provider/model binding. Exact model artifact
identity is tracked independently because a mutable model tag is not sufficient measurement
identity.

For the HAL smoke path, offline composition now also binds the exact staged Blue artifact and
digest-pinned runtime images. If that stable measurement configuration changed while
`TargetIdentity.configuration_hash` remained unchanged, the attacker-pool target snapshot
could incorrectly treat materially different Blue systems as the same target.

Per-run observations such as container IDs, network IDs, health responses and fresh inventory
snapshot hashes must still remain outside the logical target identity.

## Decision

Introduce a reusable `MeasurementBoundTarget` adapter and stable
`bind_target_measurement_identity()` function.

A predeclared lowercase SHA-256 measurement binding is folded into the target configuration
hash and adds the `measurement_identity_bound` capability. Execution responses record only
that stable binding hash; no secret value is added.

For the HAL smoke composition, derive `target_measurement_binding_sha256` from stable Blue
measurement inputs:

- Blue model ID;
- exact Blue artifact digest;
- exact staged-store identity;
- isolated model-network profile;
- staged model-peer profile;
- OpenCode runtime profile;
- OpenCode networked launch policy;
- hardened OpenCode AGENT profile;
- sandbox policy;
- exact OpenCode target configuration.

The binding explicitly excludes fresh admission/inventory proof hashes and all per-run runtime
observations.

`DockerOpenCodeTrialLeaseProvider` accepts this binding optionally. When present, both the
planning-only declared target and every acquired live target are wrapped with the same
measurement identity before equality checks and target-isolation evidence are emitted.

## Consequences

Changing the exact Blue artifact, digest-pinned runtime image or other stable security-relevant
Blue policy changes the target snapshot identity even if the mutable model tag stays the same.

Refreshing an equivalent HAL inventory snapshot does not change target identity.

Existing non-HAL users remain compatible because the measurement binding is optional.
