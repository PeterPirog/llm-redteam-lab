# HAL local-only model profile

This profile is for preliminary zero-cloud Red/Blue evaluation. It is intentionally
conservative: an Ollama/OpenWebUI record is considered local only when both
`remote_model` and `remote_host` are absent. `connection_type: local` is not sufficient,
because OpenWebUI can expose a local connection to an Ollama cloud proxy.

## Initial role assignment

| Role | Model | Rationale |
| --- | --- | --- |
| Red planner | `nemotron-3.5-lightning:latest` | Local Nemotron family, tools + thinking, 1M context; strong planner without using a cloud model. |
| Red mutator | `gpt-oss:latest` | Local 20.9B GPT-OSS family; different family from planner and moderate artifact size. |
| Blue MODEL target | `qwen3.8:latest` | Local 27.3B Qwen family with tools/thinking/vision; independent from the default Red families. |
| Semantic Judge | `gemma4:31b` | Local Gemma family, distinct from Red and Blue; disabled for initial deterministic smoke. |
| Multimodal Judge | `muse-glimmer:latest` | Local vision + thinking model from another family; disabled until visual semantic adjudication is required. |
| Forensic | `qwen3.6:latest` | Local long-context Qwen MoE; disabled in smoke to avoid unnecessary loading. |

The initial smoke therefore performs model inference only for the Red planner, Red
mutator and Blue target. The reference experiment continues to use the deterministic
canary Judge. Semantic Judge escalation is a separate, explicit later step.

## Models deliberately not selected by default

Large local models such as `laguna-s-2.1:latest` (117.6B Q8) and `gpt-oss:120b`
(116.8B MXFP4) remain valid candidates for later quality-focused experiments, but are not
appropriate default smoke models because they increase memory pressure and latency without
improving instrumentation validation.

Small legacy/specialized models remain useful as controls or specialist fixtures but are
not primary Red/Judge choices: `mistral:7b-instruct`, `wizardcoder:latest`,
`mwiewior/bielik:latest`, `tomasonjo/llama3-text2cypher-demo:latest`, and the older LLaVA
variants.

## Cloud aliases are forbidden in local-only runs

Any model carrying `remote_model` or `remote_host` is rejected even if OpenWebUI reports
`connection_type: local`. This includes the supplied aliases such as:

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

The rule is metadata-based rather than name-based so renamed cloud proxies are also
blocked.

## Recommended first run

When the harness is executed directly on HAL and Ollama listens on the normal loopback
port, use:

```text
models: config/models.hal-local.example.yaml
Blue target model: qwen3.8:latest
Blue target base URL: http://127.0.0.1:11434
stage: INSTRUMENTATION_SMOKE
```

Before inference, load a fresh OpenWebUI `/api/models` inventory and run
`validate_local_only_model_selection(...)` over both the enabled Red roles and the Blue
model. This produces a hash-safe `LocalOnlyAdmissionReport` and blocks cloud proxies.

Artifact digest qualification remains separate. The inventory admission proves that a
selected model is not a remote proxy; `ModelArtifactIdentity`/`OllamaArtifactContract`
continues to prove the exact local model artifact for reproducible qualification runs.
