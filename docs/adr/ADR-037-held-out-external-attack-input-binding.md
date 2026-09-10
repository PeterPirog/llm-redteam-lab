# ADR-037: Bind external attack inputs into held-out evaluation manifests

Status: Accepted
Date: 2026-09-11

## Context

A normalized `AttackCase` does not necessarily contain all bytes that define an attack.
Indirect prompt-injection campaigns can reference repository fixtures, terminal/tool output,
retrieval corpora, MCP context or other externally materialized attacker-controlled inputs.

The fixture-aware AGENT runtime already fingerprints complete fixture bundles and isolates
each trial, but held-out manifest schema v1 fingerprints only normalized `AttackCase`
content. Therefore changing fixture bytes after creating a v1 manifest could silently change
the effective evaluation population while leaving the manifest case hash unchanged.

That is incompatible with the laboratory's fixed-corpus measurement contract. A held-out
ASR or compromise-rate estimate is interpretable only if the evaluated attack inputs are
exactly the frozen inputs represented by the manifest.

## Decision

Introduce held-out evaluation manifest schema v2 with generic external dependency bindings.

1. Schema v1 remains supported and retains its existing hash semantics. It binds normalized
   `AttackCase` content only.
2. Schema v2 adds a canonical tuple of `EvaluationDependencyFingerprint` objects to each
   case fingerprint.
3. A dependency fingerprint contains only:
   - a dependency `kind`,
   - SHA-256 of the declared reference/locator,
   - SHA-256 of the resolved dependency content.
   Raw local paths, URLs, canaries or external bytes are not persisted by this contract.
4. Fixture-based EVALUATION requires a concrete `FixtureRuntime` during preflight. A boolean
   capability flag is insufficient because the evaluator must resolve and hash the exact
   bundle that will execute.
5. The observed fixture dependency is defined as:
   - `kind = fixture_bundle`,
   - `reference_hash = SHA256(fixture_ref)`,
   - `content_hash = FixtureDescriptor.bundle_sha256`.
6. The observed dependency tuple must exactly equal the dependency tuple bound to that case
   in the selected held-out partition. Missing, stale, extra or mismatched dependencies fail
   closed before target or Red-model inference.
7. The lifecycle passes the same concrete fixture runtime to preflight and later rechecks the
   descriptor before execution. Existing per-trial isolation and materialization hash checks
   remain in force.
8. Ordinary v1 MODEL/PIPELINE/AGENT evaluations remain valid. They do not inherit v2 claims.
9. Fixed-corpus inference semantics do not change: one bounded conversation is one trial;
   turns and retries are costs/trajectory observations, not independent Bernoulli trials.
10. The dependency model is intentionally generic so artifact, RAG, tool-output and MCP
    providers can reuse the same measurement contract when their lifecycle runners mature.

## Rationale

This closes a measurement-integrity gap without coupling the evaluation-set schema to one
specific attack surface. It also prevents an evaluator from accidentally reporting results
against a changed repository/tool fixture under an unchanged held-out manifest identity.

The split between reference identity and content identity is deliberate. It detects both a
fixture being redirected to a different declared input and the bytes behind an unchanged
reference changing.

Keeping v1 hash serialization unchanged avoids retroactively invalidating prior measurements.
A v1 manifest remains truthful about its weaker guarantee instead of silently being upgraded.

## Consequences

### Positive

- Fixture-based held-out evaluation can become fail-closed and reproducible.
- External attack bytes become part of the immutable evaluation population.
- Measurement snapshots already persist the manifest identity and campaign configuration;
  schema v2 now makes those identities causally consistent with the actual fixture bundle.
- The same contract can later bind retrieval corpora, MCP/tool providers and artifacts.

### Limitations

- This change provides the integrity contract, not statistical power. A tiny fixture corpus
  must not be presented as generalized security evidence.
- RAG and MCP still need concrete isolated providers/loaders before their dependencies can be
  executed under this contract.
- A schema v2 manifest may be internally held out or sequestered; physical secrecy of a
  public repository is not implied by the hash binding itself.
- Generalized-population inference remains separate and must not be inferred from fixed-corpus
  metrics without an explicit sampling/statistical model.

## Rejected alternatives

### Continue using only the AttackCase hash

Rejected because the effective attack can change without changing normalized case content.

### Put raw fixture paths or fixture bytes in the manifest

Rejected because the manifest should carry stable hash-only measurement identity, not local
machine details or attacker payload material.

### Trust campaign configuration hash alone

Rejected because it records what ran but does not prove that what ran matches the frozen
held-out population before execution.

### Silently change schema v1 hashing

Rejected because it would invalidate historical manifests and obscure the difference between
case-only and case-plus-dependency integrity guarantees.
