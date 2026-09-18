# ADR-077: Standard campaigns persist immutable execution provenance before inference

- Status: Accepted
- Date: 2026-09-18

## Context

The reference evaluation runner already supports immutable execution-provenance descriptors.
The ordinary `CampaignLifecycleExecutor` did not.

That asymmetry matters for the first HAL smoke. Stable Red/Blue measurement identities say
what exact system and attacker were intended to be measured. Live runtime evidence answers a
different question: which independently admitted runtime conditions were actually present
for this concrete campaign.

Examples include:

- local-only model admission;
- exact Red runtime artifact recheck;
- exact Blue runtime artifact proof;
- runtime/container version attestations;
- other hash-safe admission facts.

These observations must affect campaign identity and must be persisted before model/target
inference begins.

## Decision

`CampaignLifecycleExecutor` accepts an immutable tuple of
`ExecutionProvenanceDescriptor` values.

Before any execution:

1. descriptor kinds are required to be unique;
2. descriptors are canonicalized by kind;
3. their kind -> content-hash mapping is included in the campaign configuration hash;
4. after the campaign row exists, every descriptor is persisted immutably;
5. persistence occurs inside the campaign failure boundary and before measurement execution.

If provenance persistence fails, the campaign is marked failed and no target/Red inference
continues.

The lifecycle result exposes the canonical tuple of
`(provenance_kind, provenance_hash)` pairs.

Execution provenance remains distinct from stable measurement identity:

- exact Blue artifact/policy identity belongs to `TargetIdentity`;
- exact Red planner/mutator artifact identity belongs to attack-policy identity;
- live runtime observations belong to immutable campaign execution provenance.

## Consequences

Two otherwise identical campaigns with different admitted runtime evidence have different
campaign configuration hashes.

The standard single-profile HAL smoke can now persist live Red artifact rechecks and related
HAL evidence using the same provenance model already used by reference evaluation.

No credentials, raw prompts, secret values, or low-entropy secret hashes are permitted in
provenance payloads.
