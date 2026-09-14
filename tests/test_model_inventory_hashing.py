from llm_redteam.model_inventory import OpenWebUIOllamaInventory


def _payload(capabilities: list[str]) -> dict[str, object]:
    return {
        "data": [
            {
                "id": "local-model",
                "owned_by": "ollama",
                "ollama": {
                    "digest": "a" * 64,
                    "size": 123,
                    "details": {
                        "family": "test",
                        "parameter_size": "7B",
                        "quantization_level": "Q4_K_M",
                        "context_length": 8192,
                    },
                    "capabilities": capabilities,
                    "connection_type": "local",
                },
            }
        ]
    }


def test_capability_order_does_not_change_inventory_or_record_hash() -> None:
    left = OpenWebUIOllamaInventory.from_openwebui_response(
        _payload(["completion", "tools", "thinking"])
    )
    right = OpenWebUIOllamaInventory.from_openwebui_response(
        _payload(["thinking", "completion", "tools"])
    )

    assert left.inventory_sha256 == right.inventory_sha256
    assert left.records[0].record_sha256 == right.records[0].record_sha256
