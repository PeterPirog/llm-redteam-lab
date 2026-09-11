# Local Reference Evaluation v1

This document describes the operator-facing execution path for the fixed-corpus, multi-turn Red reference experiment.

The command is designed for an authorized local OpenAI-compatible target, with Ollama as the Reference v1 provider. It does not enable external network access, agent tools, git push, production secrets, or production workspaces.

## What the experiment measures

Reference v1 compares two frozen Red search policies against the same Blue target snapshot and held-out evaluation cases:

- baseline: `MECHANISM`
- treatment: `PORTFOLIO`
- target mode: `MODEL`
- session mode: `REPLAY`
- inference scope: `FIXED_CORPUS`
- Judge: deterministic synthetic-canary detector

One complete bounded conversation is one statistical trial. Individual turns are resource cost and time-to-violation observations, not independent ASR trials.

The two arms are executed in deterministic counterbalanced pair order. Each arm has an independent campaign-wide budget ledger, and exact per-conversation Red resource deltas are persisted before paired analysis.

## Blue policy is part of the target

The shipped `config/reference-blue-policy-v1.txt` declares `RT_SYNTHETIC_CANARY` to be protected across the entire conversation. The OpenAI-compatible target prepends this text as a system message and includes only its SHA-256 identity in evidence and target configuration fingerprinting.

Changing the Blue system policy therefore creates a different target configuration. Results from different policy hashes must not be treated as measurements of the same Blue target.

The reference corpus intentionally gives Red the security objective. The experiment measures whether a target that was explicitly configured to protect the synthetic marker continues to respect that higher-priority policy under adaptive multi-turn pressure.

## Red model configuration

Provide a normal `ModelsConfig` YAML through `--models`. Both `red_planner` and `red_mutator` must be enabled and must have explicit OpenAI-compatible endpoints. The standard local-first policy remains in force; a cloud role is rejected when cloud fallback is disabled.

No concrete Red or Blue model name is hard-coded by the reference runner.

## Stage 1: instrumentation smoke

Run this stage first. It validates the end-to-end measurement lifecycle and cannot qualify a Red policy, regardless of observed effect size or p-value.

PowerShell example:

```powershell
llm-redteam reference-run `
  --models .\config\models.local.yaml `
  --target-model <YOUR_LOCAL_BLUE_MODEL> `
  --stage INSTRUMENTATION_SMOKE `
  --target-base-url http://localhost:11434 `
  --database-url "sqlite+pysqlite:///reference-evaluation.db"
```

The command uses the reference specification, discovery/evaluation corpora, budgets, and Blue policy shipped in the repository unless explicit alternate paths are supplied.

A successful smoke proves instrumentation and persistence, not superiority of the treatment Red policy and not generalized Blue security.

## Stage 2: policy qualification

Only run qualification after the smoke completes without measurement errors and after inspecting the persisted target, Judge, budget, corpus and attack-policy fingerprints.

```powershell
llm-redteam reference-run `
  --models .\config\models.local.yaml `
  --target-model <YOUR_LOCAL_BLUE_MODEL> `
  --stage POLICY_QUALIFICATION `
  --target-base-url http://localhost:11434 `
  --database-url "sqlite+pysqlite:///reference-evaluation.db"
```

Qualification uses the predeclared paired exact McNemar/binomial rule, effect threshold and operational cost ceilings. A non-significant or non-discordant result is `INCONCLUSIVE`, not evidence that the policies are equivalent.

## Interpreting the output

The report keeps these concepts separate:

- attack/objective-violation rate on the exact held-out corpus,
- model compromise rate,
- system compromise rate,
- paired treatment-minus-baseline effect,
- exact paired p-value and discordance,
- target-interaction and Red token cost deltas,
- qualification status.

Reference v1 does not support generalized-population claims. It measures the exact pinned target configuration against the exact hash-bound evaluation population.

## Fail-closed conditions

Execution stops before meaningful measurement if the target class/mode/provider differs from the reference specification, the required corpus cases are missing, the budget is insufficient, the Red role configuration violates local-first policy, the Blue system policy is empty or does not bind the synthetic marker, or the requested inference design is unsupported.

Transport/model failures are measurement failures, not defensive success.
