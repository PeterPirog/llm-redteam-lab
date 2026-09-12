# ADR-062 — Separate OpenCode pre-launch process policy from post-launch attestation

Status: Accepted

Date: 2026-09-12

## Context

`OpenCodeLaunchPlan` binds process configuration to an already-issued sandbox attestation.
That is correct for evidence, but a real container needs its command and environment before
it can be launched and attested.

The networked Docker supervisor previously accepted only a command. Therefore a future real
launch could start OpenCode without the exact `OPENCODE_CONFIG_CONTENT`, auto-share/update
controls or declared secret environment names that were later represented by the attested
launch plan. That creates a measurement gap between declared policy and executed process.

## Decision

Introduce `OpenCodePrelaunchContract`, derived only from `OpenCodeRuntimeProfile`. It binds:

- working directory;
- exact argument-vector command;
- non-secret public environment;
- names (not values) of required secret environment variables;
- runtime/workspace fingerprints;
- optional MCP fixture bridge fingerprint.

Introduce `DockerOpenCodeNetworkedAgentProfile`, a new profile that composes the already
reviewed `DockerNetworkedAgentProfile` with one exact pre-launch contract. The historical
base profile is unchanged.

The specialized profile overrides Docker command construction so that:

- all public environment values are passed explicitly before the image reference;
- secret values never appear in the stable contract or argv;
- Docker receives only `--env <NAME>` for declared secret names and resolves the value from
  the supervisor environment;
- environment order is deterministic;
- the runtime command must exactly match the predeclared command.

After sandbox attestation, `bind_attested_opencode_launch` compares the historical
`OpenCodeLaunchPlan` against the pre-launch contract and sandbox policy. Any mismatch in
command, cwd, public environment, secret names, runtime/workspace identity, MCP bridge or
sandbox policy fails closed.

## Identity consequences

The existing `DockerNetworkedAgentProfile` and historical target identities remain
unchanged. The stronger OpenCode-specific profile has a distinct enforcement fingerprint
that includes the pre-launch contract hash. Disposable container IDs and secret values do
not enter stable target identity.

## Security consequences

A campaign can no longer claim that an OpenCode runtime used a particular deny-by-default
configuration merely because that configuration was reconstructed after the container
started. The configuration must be part of the pre-launch enforcement profile and must
match post-launch attested evidence.

This ADR does not itself create a full `TargetTrialLeaseProvider`; it removes the circular
launch/attestation dependency required before that provider can be implemented correctly.
