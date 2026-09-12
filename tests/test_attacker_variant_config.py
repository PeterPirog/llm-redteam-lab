import pytest

from llm_redteam.model_roles import ModelRole, ModelRoleConfig, ModelsConfig


def _role(capabilities: list[str]) -> dict[str, object]:
    return {
        "provider": "ollama",
        "model": "local-model",
        "class": "local",
        "capabilities": capabilities,
        "endpoint": "http://localhost:11434/v1/chat/completions",
        "fallback": ["availability-only"],
    }


def test_role_fingerprint_is_canonical_across_capability_input_order() -> None:
    first = ModelRoleConfig.model_validate(_role(["text", "reasoning"]))
    second = ModelRoleConfig.model_validate(_role(["reasoning", "text"]))

    assert first == second
    assert first.configuration_fingerprint == second.configuration_fingerprint


def test_variant_routing_is_rejected_for_non_red_roles() -> None:
    config = ModelsConfig.model_validate(
        {
            "version": 1,
            "roles": {
                "red_planner": _role(["text", "reasoning"]),
                "red_mutator": _role(["text"]),
                "judge_semantic": _role(["text", "reasoning"]),
            },
            "red_attacker_pool": {
                "enabled": True,
                "variants": [
                    {
                        "id": "a",
                        "planner": _role(["text", "reasoning"]),
                        "mutator": _role(["text"]),
                    },
                    {
                        "id": "b",
                        "planner": {
                            **_role(["text", "reasoning"]),
                            "model": "other-planner",
                        },
                        "mutator": {
                            **_role(["text"]),
                            "model": "other-mutator",
                        },
                    },
                ],
            },
        }
    )

    with pytest.raises(ValueError, match="non-Red role"):
        config.resolve_role_config(
            ModelRole.JUDGE_SEMANTIC,
            attacker_variant_id="a",
        )
