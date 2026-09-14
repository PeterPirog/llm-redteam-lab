import pytest

from llm_redteam.model_inventory import (
    OpenWebUIOllamaInventory,
    require_local_model_endpoint,
)


def _record(**ollama_updates: object) -> dict[str, object]:
    ollama: dict[str, object] = {
        "digest": "a" * 64,
        "size": 123,
        "details": {"family": "test"},
        "capabilities": ["completion"],
        "connection_type": "local",
    }
    ollama.update(ollama_updates)
    return {
        "id": "local-model",
        "owned_by": "ollama",
        "ollama": ollama,
    }


def test_malformed_remote_metadata_fails_closed() -> None:
    with pytest.raises(ValueError, match="invalid remote_host"):
        OpenWebUIOllamaInventory.from_openwebui_response(
            {"data": [_record(remote_host=True)]}
        )

    with pytest.raises(ValueError, match="invalid remote_model"):
        OpenWebUIOllamaInventory.from_openwebui_response(
            {"data": [_record(remote_model={"unexpected": "shape"})]}
        )


def test_empty_remote_metadata_is_equivalent_to_absent_metadata() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(
        {"data": [_record(remote_host="  ", remote_model="")]}
    )

    assert inventory.require_local("local-model").is_strictly_local is True


def test_local_endpoint_rejects_query_fragment_and_credentials() -> None:
    for endpoint in (
        "http://127.0.0.1:11434/v1/chat/completions?route=cloud",
        "http://127.0.0.1:11434/v1/chat/completions#alternate",
        "http://user:secret@127.0.0.1:11434/v1/chat/completions",
    ):
        with pytest.raises(ValueError):
            require_local_model_endpoint(endpoint, label="red_planner")


def test_loopback_ipv4_ipv6_and_localhost_are_accepted() -> None:
    for endpoint in (
        "http://127.0.0.1:11434/v1/chat/completions",
        "http://127.10.20.30:11434/v1/chat/completions",
        "http://[::1]:11434/v1/chat/completions",
        "http://localhost:11434/v1/chat/completions",
    ):
        assert len(require_local_model_endpoint(endpoint, label="test")) == 64
