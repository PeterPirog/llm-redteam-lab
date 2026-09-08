# llm-redteam-lab

Evidence-driven red/blue-team laboratory for authorized adversarial evaluation of LLMs, multimodal models and agentic systems.

The project is intentionally built around a complete experiment lifecycle rather than a collection of jailbreak prompts:

```text
security invariant
  -> attack hypothesis
  -> execution against Blue
  -> evidence
  -> independent judgment
  -> reproduction
  -> minimization / counterfactuals
  -> forensic root cause
  -> Blue security knowledge
  -> regression
```

## First-class Blue target classes

- `coding`
- `reasoning`
- `writing`
- `image_generation`

Target modes are `MODEL`, `PIPELINE` and `AGENT`. The same underlying model in different applications/configurations is treated as a different security target.

## Core security distinction

- `MODEL_COMPROMISE`: the model follows an adversarial instruction or violates a behavioral invariant.
- `SYSTEM_COMPROMISE`: the surrounding system permits an unauthorized effect.

A model compromise contained by sandboxing or deterministic authorization is **not** a system compromise.

## Safe development defaults

- authorized targets only,
- synthetic canaries instead of real secrets,
- local-first model use,
- deterministic mocks before inference,
- strict campaign budgets,
- network denied by default for adversarial agent tests,
- git push denied by default for target agents,
- disposable/sandboxed coding-agent workspaces,
- attacker-controlled content cannot expand permissions.

## Current development phase

The repository is establishing the deterministic foundation before real model campaigns:

- provenance-aware attack corpus,
- strict typed domain model,
- uncertainty-aware metrics,
- local-first model-role configuration,
- fail-closed campaign budgets,
- standards alignment.

See `PROJECT_REQUIREMENTS.md` for authoritative architecture and `PROJECT_OPERATING_CONTEXT.md` for operating assumptions.

## Development

Python 3.12+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[dev]"
ruff check .
pytest
```

CI and unit tests must not require paid APIs or external model inference.
