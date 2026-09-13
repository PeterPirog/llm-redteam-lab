import json

import pytest

from llm_redteam.offline_ollama_qualification import (
    OllamaArtifactContractDocument,
    load_ollama_artifact_contract_document,
    load_ollama_tags_payload,
    qualify_saved_ollama_inventory,
)


def _document() -> OllamaArtifactContractDocument:
    return OllamaArtifactContractDocument.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-operator-inventory",
            "require_local": True,
            "artifacts": {
                "planner:latest": {
                    "digest": "sha256:" + "a" * 64,
                    "roles": ["red_planner"],
                },
                "blue:latest": {
                    "digest": "sha256:" + "b" * 64,
                    "roles": ["recommended_model_blue"],
                },
            },
        }
    )


def _record(
    model: str,
    digest_char: str,
    *,
    remote_host: str | None = None,
    remote_model: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "name": model,
        "model": model,
        "digest": digest_char * 64,
        "size": 4096,
        "details": {
            "format": "gguf",
            "family": "synthetic",
            "parameter_size": "9B",
            "quantization_level": "Q4_K_M",
        },
    }
    if remote_host is not None:
        record["remote_host"] = remote_host
    if remote_model is not None:
        record["remote_model"] = remote_model
    return record


def _payload() -> dict[str, object]:
    return {
        "models": [
            _record("blue:latest", "b"),
            _record("planner:latest", "a"),
            _record("unrelated:latest", "c"),
        ]
    }


def test_offline_report_verifies_declared_models_and_ignores_extra_inventory() -> None:
    report = qualify_saved_ollama_inventory(
        document=_document(),
        tags_payload=_payload(),
    )

    assert tuple(item.model_id for item in report.artifacts) == (
        "blue:latest",
        "planner:latest",
    )
    assert report.require_local is True
    assert len(report.inventory_sha256) == 64
    assert len(report.contracts_sha256) == 64
    assert len(report.artifact_set_sha256) == 64
    assert len(report.report_sha256) == 64
    assert all(item.identity.local_artifact for item in report.artifacts)
    assert set(report.artifact_identities()) == {
        ("ollama", "blue:latest"),
        ("ollama", "planner:latest"),
    }
    assert "unrelated:latest" not in {item.model_id for item in report.artifacts}


def test_report_identity_is_stable_across_inventory_record_order() -> None:
    first = qualify_saved_ollama_inventory(
        document=_document(),
        tags_payload=_payload(),
    )
    reversed_payload = {"models": list(reversed(_payload()["models"]))}
    second = qualify_saved_ollama_inventory(
        document=_document(),
        tags_payload=reversed_payload,
    )

    assert first.artifact_set_sha256 == second.artifact_set_sha256
    assert first.contracts_sha256 == second.contracts_sha256
    assert first.inventory_sha256 != second.inventory_sha256
    assert first.report_sha256 != second.report_sha256


def test_remote_proxy_is_rejected_even_when_digest_matches() -> None:
    payload = _payload()
    models = payload["models"]
    assert isinstance(models, list)
    models[0] = _record(
        "blue:latest",
        "b",
        remote_host="https://ollama.com",
        remote_model="blue:latest",
    )

    with pytest.raises(ValueError, match="local model, not remote proxy"):
        qualify_saved_ollama_inventory(document=_document(), tags_payload=payload)


def test_digest_drift_fails_the_entire_report() -> None:
    payload = _payload()
    models = payload["models"]
    assert isinstance(models, list)
    models[1] = _record("planner:latest", "d")

    with pytest.raises(ValueError, match="manifest digest"):
        qualify_saved_ollama_inventory(document=_document(), tags_payload=payload)


def test_missing_declared_model_fails_the_entire_report() -> None:
    payload = {"models": [_record("planner:latest", "a")]}

    with pytest.raises(ValueError, match="resolve exactly one"):
        qualify_saved_ollama_inventory(document=_document(), tags_payload=payload)


def test_duplicate_declared_model_record_fails_closed() -> None:
    payload = _payload()
    models = payload["models"]
    assert isinstance(models, list)
    models.append(_record("blue:latest", "b"))

    with pytest.raises(ValueError, match="resolve exactly one"):
        qualify_saved_ollama_inventory(document=_document(), tags_payload=payload)


def test_contract_document_requires_local_ollama() -> None:
    raw = _document().model_dump(mode="json")
    raw["require_local"] = False

    with pytest.raises(ValueError, match="require_local=true"):
        OllamaArtifactContractDocument.model_validate(raw)


def test_contract_and_inventory_loaders_are_offline_file_only(tmp_path) -> None:
    contract_path = tmp_path / "contracts.yaml"
    contract_path.write_text(
        """version: 1
provider: ollama
source: synthetic-file
require_local: true
artifacts:
  planner:latest:
    digest: sha256:{digest}
    roles: [red_planner]
""".format(digest="a" * 64),
        encoding="utf-8",
    )
    inventory_path = tmp_path / "tags.json"
    inventory_path.write_text(json.dumps({"models": [_record("planner:latest", "a")]}))

    document = load_ollama_artifact_contract_document(contract_path)
    payload = load_ollama_tags_payload(inventory_path)
    report = qualify_saved_ollama_inventory(document=document, tags_payload=payload)

    assert report.source == "synthetic-file"
    assert report.artifacts[0].model_id == "planner:latest"
    assert report.artifacts[0].roles == ("red_planner",)
