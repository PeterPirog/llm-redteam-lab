# HAL local-only model profiles

HAL has two zero-cloud profiles with different purposes. Both use the same fail-closed
admission rule: an Ollama/OpenWebUI record is considered local only when both
`remote_model` and `remote_host` are absent. `connection_type: local` is not sufficient,
because OpenWebUI can expose a local connection to an Ollama cloud proxy.

## Instrumentation smoke profile

Use `config/models.hal-smoke.example.yaml` to prove the E2E harness before spending local
compute on stronger models.

| Role | Model | Rationale |
| --- | --- | --- |
| Red planner | `gpt-oss:latest` | Local 20.9B MXFP4 model with tools + thinking; the lightest supplied model with explicit reasoning capability suitable for adaptive planning. |
| Red mutator | `mistral:7b-instruct` | Local 7.2B Q4 model from a different family; inexpensive text mutation. |
| Blue MODEL target | `ornith-1.5:9b` | Local 9B Qwen-family model; materially lighter than the quality Blue while still exercising a real model target. |
| Judge | deterministic canary | No model inference or external cost during the instrumentation smoke. |

Semantic Judge, multimodal Judge, forensic roles and the attacker pool remain disabled.
The objective of this profile is instrumentation correctness, lifecycle evidence and cost
containment, not a publishable security estimate.

## Local quality profile

After instrumentation is proven, use `config/models.hal-local.example.yaml` for a stronger
preliminary local evaluation.

| Role | Model | Rationale |
| --- | --- | --- |
| Red planner | `nemotron-3.5-lightning:latest` | Local Nemotron family, tools + thinking, 1M context; stronger adaptive planner. |
| Red mutator | `gpt-oss:latest` | Local GPT-OSS family, distinct from the planner. |
| Blue MODEL target | `qwen3.8:latest` | Local 27.3B Qwen family with tools/thinking/vision; independent from the default Red families. |
| Semantic Judge | `gemma4:31b` | Local Gemma family, distinct from Red and Blue; enable only when semantic adjudication is required. |
| Multimodal Judge | `muse-glimmer:latest` | Local vision + thinking model from another family; enable only for visual semantic evidence. |
| Forensic | `qwen3.6:latest` | Local long-context Qwen MoE; enable for reproducible forensic analysis, not ordinary smoke. |

The deterministic Judge remains preferred where deterministic evidence is conclusive.
Model Judge escalation should remain explicit so that local compute use is measurable and
Judge/model dependence is visible in provenance.

## Models deliberately not selected by default

Large local models such as `laguna-s-2.1:latest` (117.6B Q8) and `gpt-oss:120b`
(116.8B MXFP4) remain valid candidates for later quality/ablation experiments, but are not
defaults because they increase memory pressure and latency without improving early
instrumentation validation.

Specialized/legacy models such as `wizardcoder:latest`, `mwiewior/bielik:latest`,
`tomasonjo/llama3-text2cypher-demo:latest` and older LLaVA variants remain useful as
controls or specialist fixtures rather than primary Red/Judge models.

## Cloud aliases are forbidden in local-only runs

Any model carrying `remote_model` or `remote_host` is rejected even if OpenWebUI reports
`connection_type: local`. Supplied examples include:

- `minimax-m3:cloud`
- `deepseek-v4-flash:cloud`
- `glm-5.3-flash:cloud`
- `gpt-oss:120b-cloud`
- `kimi-k2.7-code:cloud`
- `gemma4:31b-cloud`
- `deepseek-v4-pro:cloud`
- `kimi-k2.6:cloud`
- `qwen3.5:cloud`
- `qwen3.5:397b-cloud`
- `qwen3-next:80b-cloud`
- `qwen3-coder-next:cloud`
- `qwen3-vl:235b-cloud`

The rule is metadata-based rather than name-based, so renamed cloud proxies are blocked as
well.

## Recommended first run

When the harness is executed directly on HAL and Ollama listens on the normal loopback
port, the first real run should use:

```text
models: config/models.hal-smoke.example.yaml
Blue target model: ornith-1.5:9b
Blue target base URL: http://127.0.0.1:11434
stage: INSTRUMENTATION_SMOKE
```

Before any inference, load a fresh OpenWebUI `/api/models` inventory and run
`validate_local_only_model_selection(...)` over every enabled role and the Blue target.
This produces a hash-safe `LocalOnlyAdmissionReport` and blocks cloud proxies before model
clients are constructed.

Artifact qualification remains a separate stronger guarantee. Inventory admission proves
that a selected model is not a remote proxy; `ModelArtifactIdentity` and
`OllamaArtifactContract` prove the exact local artifact for reproducible qualification
runs.
