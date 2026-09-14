import json
from pathlib import Path

import pytest

from llm_redteam.model_inventory import (
    OpenWebUIOllamaInventory,
    load_openwebui_ollama_inventory,
    require_local_model_endpoint,
    validate_local_only_model_selection,
)
from llm_redteam.model_roles import ModelsConfig


def _payload() -> dict[str, object]:
    return {
        "data": [
            {
                "id": "planner-local",
                "owned_by": "ollama",
                "ollama": {
                    "digest": "a" * 64,
                    "size": 100,
                    "details": {
                        "family": "nemotron",
                        "parameter_size": "30B",
                        "quantization_level": "Q4_K_M",
                        "context_length": 131072,
                    },
                    "capabilities": ["completion", "tools", "thinking"],
                    "connection_type": "local",
                },
                "access_grants": [{"principal_id": "ignored-user-data"}],
            },
            {
                "id": "mutator-local",
                "owned_by": "ollama",
                "ollama": {
                    "digest": "b" * 64,
                    "size": 200,
                    "details": {
                        "family": "gptoss",
                        "parameter_size": "20B",
                        "quantization_level": "MXFP4",
                    },
                    "capabilities": ["completion", "tools", "thinking"],
                    "connection_type": "local",
                },
            },
            {
                "id": "blue-local",
                "owned_by": "ollama",
                "ollama": {
                    "digest": "c" * 64,
                    "size": 300,
                    "details": {"family": "qwen", "context_length": 262144},
                    "capabilities": ["completion", "tools", "thinking", "vision"],
                    "connection_type": "local",
                },
            },
            {
                "id": "looks-local-but-cloud",
                "owned_by": "ollama",
                "ollama": {
                    "digest": "d" * 64,
                    "size": 301,
                    "details": {"family": "remote"},
                    "capabilities": ["completion", "tools", "thinking"],
                    "connection_type": "local",
                    "remote_model": "remote-model",
                    "remote_host": "https://ollama.com:443",
                },
            },
            {
                "id": "code-arena",
                "owned_by": "arena",
                "arena": True,
            },
        ]
    }


def _models(*, planner_model: str = "planner-local") -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": planner_model,
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
            },
        }
    )


def test_parser_distinguishes_true_local_model_from_local_connection_cloud_proxy() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    assert inventory.require_local("planner-local").is_strictly_local is True
    assert inventory.require_local("planner-local").capabilities == frozenset(
        {"text", "tools", "reasoning"}
    )
    assert "code-arena" not in {record.model_id for record in inventory.records}

    with pytest.raises(ValueError, match="remote Ollama proxy"):
        inventory.require_local("looks-local-but-cloud")


def test_local_only_selection_validates_enabled_red_roles_and_blue_target() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    report = validate_local_only_model_selection(
        models=_models(),
        inventory=inventory,
        blue_model_id="blue-local",
        blue_endpoint="http://127.0.0.1:11434",
    )

    assert report.admitted_model_ids == (
        "blue-local",
        "mutator-local",
        "planner-local",
    )
    assert report.blue_model_id == "blue-local"
    assert {binding.label for binding in report.bindings} == {
        "blue",
        "red_mutator",
        "red_planner",
    }
    assert all(len(binding.endpoint_sha256) == 64 for binding in report.bindings)
    assert len(report.inventory_sha256) == 64
    assert len(report.proof_sha256) == 64


def test_local_class_cannot_hide_remote_proxy() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    with pytest.raises(ValueError, match="remote Ollama proxy"):
        validate_local_only_model_selection(
            models=_models(planner_model="looks-local-but-cloud"),
            inventory=inventory,
            blue_model_id="blue-local",
            blue_endpoint="http://127.0.0.1:11434",
        )


def test_local_only_selection_rejects_remote_role_endpoint() -> None:
    raw = _models().model_dump(mode="python", by_alias=True)
    raw["roles"]["red_planner"]["endpoint"] = "https://api.example.com/v1/chat/completions"
    models = ModelsConfig.model_validate(raw)
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    with pytest.raises(ValueError, match="not loopback or explicitly allowed"):
        validate_local_only_model_selection(models=models, inventory=inventory)


def test_local_only_selection_rejects_remote_blue_endpoint() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    with pytest.raises(ValueError, match="not loopback or explicitly allowed"):
        validate_local_only_model_selection(
            models=_models(),
            inventory=inventory,
            blue_model_id="blue-local",
            blue_endpoint="https://ollama.com",
        )


def test_explicit_trusted_host_can_be_admitted_for_future_lan_runtime() -> None:
    endpoint_hash = require_local_model_endpoint(
        "http://hal-model-host:11434/v1/chat/completions",
        label="red_planner",
        allowed_hosts={"hal-model-host"},
    )

    assert len(endpoint_hash) == 64


def test_local_only_selection_rejects_cloud_fallback_policy() -> None:
    raw = _models().model_dump(mode="python", by_alias=True)
    raw["policy"]["allow_cloud_fallback"] = True
    models = ModelsConfig.model_validate(raw)
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_payload())

    with pytest.raises(ValueError, match="forbids cloud fallback"):
        validate_local_only_model_selection(models=models, inventory=inventory)


def test_loader_accepts_markdown_fenced_openwebui_export(tmp_path: Path) -> None:
    path = tmp_path / "inventory.md"
    path.write_text("```\n" + json.dumps(_payload()) + "\n```\n", encoding="utf-8")

    inventory = load_openwebui_ollama_inventory(path)

    assert inventory.require_local("blue-local").artifact_digest == "sha256:" + "c" * 64


def test_inventory_hash_ignores_openwebui_access_grants() -> None:
    first = _payload()
    second = _payload()
    second_data = second["data"]
    assert isinstance(second_data, list)
    second_item = second_data[0]
    assert isinstance(second_item, dict)
    second_item["access_grants"] = [{"principal_id": "different-user-data"}]

    left = OpenWebUIOllamaInventory.from_openwebui_response(first)
    right = OpenWebUIOllamaInventory.from_openwebui_response(second)

    assert left.inventory_sha256 == right.inventory_sha256
