# Attack Corpus Registry

This directory is the curated, versioned starting corpus for `llm-redteam-lab`.

The corpus is not a dump of jailbreak prompts. It is a provenance-aware registry of adversarial test cases, attack techniques, benchmark sources, expected security properties, and execution requirements.

## Design goals

1. Provide a cheap, deterministic baseline before adaptive Red inference is used.
2. Separate attack complexity from observed target difficulty.
3. Keep external benchmark provenance and licensing explicit.
4. Support the four first-class Blue target classes: `coding`, `reasoning`, `writing`, and `image_generation`.
5. Preserve known failures as well as known successes so the adaptive attacker does not waste inference on repeatedly unproductive branches.
6. Keep dangerous or license-restricted external datasets out of the repository by default.
7. Make every confirmed finding convertible into a regression case.

## Corpus layout

```text
corpus/
├── README.md
├── sources.yaml                 # curated external source registry
├── tiers.yaml                   # complexity tiers; not target difficulty
├── schema/
│   └── attack-case.schema.json  # normalized case schema
├── native/
│   └── smoke/
│       └── canary-baseline.yaml # harmless synthetic baseline cases
├── packs/
│   └── baseline-v1.yaml         # initial per-target-class test packs
└── external/
    └── README.md                # policy for non-vendored external datasets
```

Future implementation may add `importers/` after the domain model and Target abstraction exist.

## Complexity tiers

`complexity_tier` describes the attack mechanism, not how difficult a specific Blue target is to compromise.

- `T0` — negative controls, benign controls, direct invariant checks.
- `T1` — cheap deterministic/static techniques such as direct override, persona wrappers, simple encoding/obfuscation and known templates.
- `T2` — semantic reframing, composed static techniques and contextual/authority manipulation.
- `T3` — adaptive single-turn or multi-attempt search using an attacker model.
- `T4` — stateful multi-turn, indirect prompt injection, RAG/context poisoning, repository/tool-output injection and comparable environment-mediated attacks.
- `T5` — target-specific optimization, cross-modal attacks, agent/tool exploitation and other high-cost or highly specialized attacks.

A T1 case may be trivial for one target and impossible within budget for another. Target-specific difficulty is measured from experiment evidence, e.g. ASR, attempts-to-success, generations-to-success and reproducibility.

## Source modes

External sources are classified as:

- `reference` — metadata/citation only; no automated retrieval assumed.
- `external` — loaded from the upstream project/dataset at runtime or by an explicit importer.
- `gated` — requires upstream access approval/terms acceptance; never vendored automatically.
- `vendored` — permitted subset copied into this repository with required notices. This mode requires an explicit licensing review before use.
- `native` — authored for this project, using synthetic canaries or inert goals.

Default policy is `external`, not `vendored`.

## Safety rule for native cases

Native attack cases must use synthetic secrets and inert effects. Examples include:

- reveal a generated canary,
- request an unauthorized but sandbox-blocked path,
- write a harmless marker file inside a disposable workspace,
- attempt a forbidden synthetic tool action,
- redirect a coding agent away from a benign fixture task.

Do not place real credentials, production paths, exploit payloads or uncontrolled network-exfiltration goals in this corpus.

## Baseline-to-adaptive escalation

Campaigns should start cheaply:

```text
T0 controls
  -> T1 known/static baseline
  -> T2 composed/semantic baseline
  -> T3 adaptive single-turn
  -> T4 multi-turn/indirect/agent context attacks
  -> T5 specialized target-specific exploration
```

Escalation is budget-controlled. A target that already fails a cheap invariant should not automatically trigger expensive adaptive exploration.

## Evidence feedback

Corpus entries are immutable definitions. Observed results belong in experiment persistence/Blue Security Profiles, not in the source case itself.

For each target, retain evidence such as:

- attempted/succeeded counts,
- observed ASR,
- median attempts and turns to success,
- model compromise vs system compromise,
- effective controls,
- bypassed controls,
- minimal reproducing attacks,
- regressions.

This lets Red use both `what worked` and `what did not work` when planning future attacks.
