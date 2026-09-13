from pathlib import Path

import yaml

from llm_redteam.model_roles import load_models_config
from llm_redteam.ollama_artifact import OllamaArtifactContract

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "config" / "models.local-smoke.example.yaml"
ARTIFACTS = ROOT / "config" / "local-smoke-ollama-artifacts.yaml"


def _artifact_document() -> dict[str, object]:
    payload = yaml.safe_load(ARTIFACTS.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_every_local_smoke_role_and_attacker_model_has_a_pinned_artifact() -> None:
    models = load_models_config(MODELS)
    document = _artifact_document()
    artifacts = document["artifacts"]
    assert isinstance(artifacts, dict)

    configured = {role.model for role in models.roles.values()}
    for variant in models.red_attacker_pool.variants:
        configured.add(variant.planner.model)
        configured.add(variant.mutator.model)

    assert configured.issubset(artifacts)

    for model_id in configured:
        entry = artifacts[model_id]
        assert isinstance(entry, dict)
        contract = OllamaArtifactContract(
            model_id=model_id,
            expected_manifest_digest=entry["digest"],
            require_local=True,
        )
        assert contract.model_id == model_id
        assert contract.manifest_digest.startswith("sha256:")
        assert len(contract.manifest_digest) == len("sha256:") + 64


def test_artifact_contract_rejects_remote_alias_even_when_digest_matches() -> None:
    document = _artifact_document()
    artifacts = document["artifacts"]
    assert isinstance(artifacts, dict)
    entry = artifacts["gpt-oss:latest"]
    assert isinstance(entry, dict)
    contract = OllamaArtifactContract(
        model_id="gpt-oss:latest",
        expected_manifest_digest=entry["digest"],
        require_local=True,
    )

    remote_proxy = {
        "models": [
            {
                "name": "gpt-oss:latest",
                "model": "gpt-oss:latest",
                "remote_model": "gpt-oss:20b",
                "remote_host": "https://ollama.com",
                "size": 384,
                "digest": contract.manifest_digest,
                "details": {},
            }
        ]
    }

    try:
        contract.verify_tags_response(remote_proxy)
    except ValueError as exc:
        assert "local model, not remote proxy" in str(exc)
    else:
        raise AssertionError("remote Ollama alias must fail the local artifact contract")


def test_artifact_contract_accepts_exact_local_manifest_record() -> None:
    document = _artifact_document()
    artifacts = document["artifacts"]
    assert isinstance(artifacts, dict)
    entry = artifacts["ornith-1.5:9b"]
    assert isinstance(entry, dict)
    contract = OllamaArtifactContract(
        model_id="ornith-1.5:9b",
        expected_manifest_digest=entry["digest"],
        require_local=True,
    )

    observation = contract.verify_tags_response(
        {
            "models": [
                {
                    "name": "ornith-1.5:9b",
                    "model": "ornith-1.5:9b",
                    "size": 6550813657,
                    "digest": contract.manifest_digest,
                    "details": {
                        "format": "gguf",
                        "family": "qwen35",
                        "parameter_size": "9.0B",
                        "quantization_level": "Q4_K_M",
                    },
                }
            ]
        }
    )

    assert observation.identity.model_id == "ornith-1.5:9b"
    assert observation.identity.local_artifact is True
    assert observation.identity.artifact_digest == contract.manifest_digest
