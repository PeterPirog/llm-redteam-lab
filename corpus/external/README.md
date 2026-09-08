# External Corpus Policy

External benchmark datasets and attack artifacts are not copied into this repository by default.

## Why

1. Some datasets are gated or require responsible-use acceptance.
2. Some benchmark repositories combine records under different upstream licenses.
3. Some image-generation datasets contain sensitive visual material.
4. Upstream projects evolve; adapters preserve provenance better than stale copies.
5. The project should remain safe to clone and run in deterministic smoke mode.

## Import policy

An importer may be added only when it records:

- upstream project and URL,
- upstream record identifier,
- retrieval date,
- source version/commit/dataset revision where available,
- applicable license/terms,
- content hash,
- target-class mapping,
- attack-family mapping,
- whether the source is gated,
- whether redistribution is permitted.

If redistribution is unclear, store only metadata and load the record from the user's separately obtained upstream dataset.

## Gated sources

`source_mode: gated` means:

- the framework must not bypass the upstream access process,
- the framework must not embed access credentials,
- the user must obtain the dataset independently under its terms,
- local path/revision may then be configured explicitly.

## Vendoring

Vendoring is exceptional, not the default. A vendored subset requires:

1. explicit source-level license review,
2. attribution/NOTICE where required,
3. provenance down to record level when the source aggregates datasets,
4. no real secrets or uncontrolled exploit effects,
5. a deterministic reason why local vendoring materially improves reproducibility.

## Safe default

Fresh clones of `llm-redteam-lab` should be able to run unit tests and native smoke fixtures without downloading harmful datasets or invoking external LLMs.
