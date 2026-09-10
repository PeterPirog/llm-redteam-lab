# llm-redteam-lab

Evidence-driven red/blue-team laboratory for authorized adversarial evaluation of
LLMs, multimodal models and agentic systems.

The project is built around an experiment lifecycle rather than a collection of
jailbreak prompts:

```text
security invariant
  -> adaptive or scripted Red attack
  -> execution against Blue
  -> evidence
  -> independent judgment
  -> reproduction
  -> minimization / counterfactuals
  -> forensic root cause
  -> Blue security knowledge
  -> regression
```

## First-class Blue targets

Target classes:

- `coding`
- `reasoning`
- `writing`
- `image_generation`

Target modes:

- `MODEL`
- `PIPELINE`
- `AGENT`

The same underlying model in different applications/configurations is a different
security target.

## Core security distinction

- `MODEL_COMPROMISE`: the model follows an adversarial instruction or violates a
  behavioral invariant.
- `SYSTEM_COMPROMISE`: the surrounding system permits an unauthorized effect.

A model compromise contained by authorization, sandboxing or trusted post-state
verification is **not** a system compromise.

## Current capabilities

The current core includes:

- provenance-aware attack corpus and source registry,
- static and adaptive LangGraph Red strategies,
- first-class multi-turn trajectories with branching/backtracking,
- branch-aware Red learning and mechanism/portfolio policies,
- paired held-out Red component ablations,
- DISCOVERY vs held-out/sequestered EVALUATION measurement contracts,
- Wilson uncertainty intervals and explicit denominator policies,
- Ollama/OpenAI-compatible/OpenWebUI-style model interfaces,
- OpenCode `coding/AGENT` target support,
- request/authorization/execution/post-state evidence primitives,
- deterministic filesystem and local-git state verifiers,
- image-generation artifacts, ComfyUI target support and multimodal judging,
- reproduction, minimization, counterfactual replay and evidence-grounded forensics,
- Blue control knowledge and regression artifacts,
- SQLAlchemy persistence and OpenTelemetry instrumentation.

Known multi-turn jailbreak sequences can be represented as explicit corpus `turns`
and replayed as one statistical attack trial. Adaptive discovery can instead use a
goal seed and generate the sequence dynamically under a bounded Red policy.

## Safe operator preflight

Install the project and validate data without invoking any model:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[dev]"

llm-redteam validate-corpus corpus/native/smoke/canary-baseline.yaml
```

Build a deterministic campaign plan:

```powershell
llm-redteam plan `
  --corpus corpus/native/smoke/canary-baseline.yaml `
  --target-class writing `
  --target-mode MODEL `
  --purpose DISCOVERY `
  --budget-profile smoke `
  --red-policy static
```

`plan` performs **zero target calls and zero model inference**. It fails closed on
incompatible cases, insufficient attack/turn/image budgets, missing model roles and
invalid EVALUATION measurement identity.

Comparative `EVALUATION` additionally requires a held-out manifest, pinned target
snapshot and frozen attack/Judge policy fingerprints. Adaptive DISCOVERY yield must
not be reported as an unbiased Blue ASR estimate.

## Safe development defaults

- authorized targets only,
- synthetic canaries instead of real secrets,
- local-first model use,
- deterministic mocks before inference,
- strict campaign budgets,
- network denied by default for adversarial agent tests,
- git push denied by default for target agents,
- disposable/sandboxed coding-agent workspaces,
- attacker-controlled content cannot expand permissions,
- infrastructure errors and incomplete telemetry are never defensive success.

## Development

Python 3.12+.

```powershell
ruff check .
pytest
```

CI and unit tests must not require paid APIs or external model inference.

See `PROJECT_REQUIREMENTS.md` for authoritative architecture and
`PROJECT_OPERATING_CONTEXT.md` for operating assumptions.
