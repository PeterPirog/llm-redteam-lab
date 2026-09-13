# ADR-074: Canonicalize the full TargetIdentity for persisted target snapshots

- Status: Proposed
- Date: 2026-09-13

## Context

A persisted target snapshot is the measurement anchor for campaigns, executions,
reproduction, regression and paired experiments. The previous snapshot ID was derived from
only two fields:

```text
TargetIdentity.id + TargetIdentity.configuration_hash
```

That design assumed every target adapter always folded every security-relevant property into
its own `configuration_hash` correctly. The assumption is too weak for an adversarial
measurement system.

`TargetIdentity` already carries normalized security-target properties including target class,
mode, model, provider, runtime, optional exact model digest, application identity/version,
system-prompt hash and capabilities. If any of those fields changes while an adapter leaves its
configuration hash unchanged, the old persistence algorithm could reuse the same snapshot ID
for a materially different target.

This is especially important for mutable model tags: `blue:latest` may resolve to different
weights while retaining the same configured model name and application settings.

## Decision

`ExperimentRepository.target_snapshot_fingerprint()` SHALL hash a canonical explicit payload
containing every field of `TargetIdentity`:

- `id`;
- `target_class`;
- `target_mode`;
- `model`;
- `provider`;
- `runtime`;
- `model_digest`;
- `application`;
- `application_version`;
- `system_prompt_hash`;
- `configuration_hash`;
- capabilities in sorted order.

The canonical JSON encoding SHALL use sorted keys, compact separators and UTF-8. Capabilities
are explicitly sorted so hash stability cannot depend on `frozenset` iteration order.

The complete SHA-256 is exposed as the snapshot fingerprint. The persisted snapshot ID remains
compact and uses the first 24 hexadecimal characters:

```text
target-<first 24 hex characters of canonical SHA-256>
```

## Relationship to adapter configuration hashes

This decision does not make `configuration_hash` redundant. The adapter configuration hash
continues to identify the adapter-specific runtime/application policy. The persistence layer
now treats it as one component of target identity rather than trusting it as a complete
substitute for the normalized target record.

Provider-specific target adapters therefore remain responsible for accurately describing their
configuration, but an omitted model digest, provider/application change or capability change
can no longer be hidden merely because the adapter reused the same configuration hash.

## Relationship to exact model artifacts

ADR-072 additionally composes a verified `ModelArtifactIdentity` into the Blue target
configuration and `model_digest`. ADR-074 is defense in depth: persistence independently binds
the normalized `model_digest` and all other `TargetIdentity` fields into the snapshot key.

The two controls solve different problems:

- artifact qualification proves what exact model artifact was admitted;
- canonical snapshot identity proves what complete normalized security target the campaign was
  persisted against.

## MODEL / PIPELINE / AGENT semantics

This decision applies uniformly across target modes. It directly supports the architectural
rule that the same underlying model used in different applications or configurations is a
different security target.

Examples that now necessarily produce distinct snapshots include:

- same model weights in direct MODEL API vs OpenWebUI PIPELINE;
- same model in two application versions;
- same application with different system-prompt hashes;
- same mutable model tag with a different exact digest;
- MODEL vs AGENT mode;
- a target whose declared tool/capability surface changes.

## Compatibility

This changes snapshot IDs relative to the earlier pre-1.0 persistence algorithm because the
identity input is stronger. The project is still at version `0.1.0` and target-snapshot IDs are
experimental persistence identifiers, not a stable public API. Preserving a weaker identity
algorithm would create architectural debt and undermine later reproducibility claims.

Existing experimental databases should not be mixed blindly with new measurement campaigns.
A future schema/version migration mechanism should record persistence-format evolution before
the project promises stable on-disk compatibility.

## Security consequences

The change does not alter:

- target permissions;
- model invocation;
- Red behavior;
- Judge behavior;
- `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE` semantics;
- campaign budgets;
- statistical trial units;
- fixed-corpus inference semantics.

It strengthens only the identity key used to bind persisted evidence to the target that
produced it.

## Testing

Deterministic tests SHALL prove that:

- identical normalized targets produce identical full fingerprints and snapshot IDs;
- capability ordering does not affect identity;
- changing any individual security-relevant `TargetIdentity` field changes the fingerprint and
  snapshot ID;
- the same mutable model tag and configuration hash with different model digests persist as two
  distinct target snapshots.

No model inference, network access, Docker daemon or provider runtime is needed.
