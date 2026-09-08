# Corpus Importer Contract

External corpus importers convert upstream records into normalized `AttackCase` objects without changing the security objective or losing provenance.

## Required behavior

Every importer MUST:

1. be invoked explicitly; normal startup and `smoke-v1` never download datasets,
2. identify the upstream source from `corpus/sources*.yaml`,
3. resolve and record an upstream revision, dataset revision, or retrieval timestamp,
4. calculate a content hash for the imported source/subset,
5. preserve upstream record IDs where available,
6. preserve record-level license/provenance when a dataset aggregates other sources,
7. normalize target class, target mode, technique IDs, attack family and grading requirements,
8. validate normalized cases against `schema/attack-case.schema.json`,
9. write a source lock conforming to `schema/source-lock.schema.json`,
10. fail closed if required provenance or gating conditions cannot be established.

## Importer MUST NOT

- bypass gated-dataset access controls,
- embed credentials or access tokens in repository files,
- infer that aggregator licensing applies to all upstream records,
- silently replace or rewrite a source record to make it more harmful,
- use a real secret in place of a synthetic test canary,
- contact real services merely to normalize a dataset,
- execute attacker-provided code during import,
- interpret a failed download as an empty/valid corpus.

## Normalization model

Conceptually:

```text
UPSTREAM RECORD
      |
      v
SOURCE-SPECIFIC PARSER
      |
      v
PROVENANCE VALIDATION
      |
      v
TECHNIQUE / TARGET MAPPING
      |
      v
AttackCase
      |
      +--> JSON Schema validation
      |
      +--> source lock
```

## Gated datasets

For `source_mode: gated`, an importer accepts only an explicitly configured local path or an upstream client that the user has already authenticated according to the source terms.

The importer must not automate acceptance of responsible-use terms.

## Safety normalization

The project's native regression cases use inert/synthetic effects. External benchmark records may define their own research objectives; importing them does not automatically make them eligible for the default campaign.

Execution eligibility is controlled by corpus packs, campaign policy and target isolation, not merely by the fact that a record was successfully imported.

## Reproducibility

An import result should be addressable by:

```text
source_id
+ upstream_revision
+ subset/filter configuration
+ normalizer_version
+ content_hash
```

Two imports with the same identity should produce semantically identical normalized records or fail a reproducibility check.

## Initial implementation order

After the core Python domain models exist, implement importers in this order:

1. MLCommons taxonomy metadata/crosswalk loader,
2. XSTest benign controls,
3. JailbreakBench behavior/artifact metadata,
4. Do-Not-Answer objective taxonomy,
5. RepoGuardBench adapter,
6. BIPIA / AgentDojo / InjecAgent adapters,
7. T2I-RiskyPrompt and OVERT,
8. other external/gated sources only when required by a campaign.

This order prioritizes low-cost, high-provenance sources and avoids premature dependency on expensive or restricted evaluation paths.
