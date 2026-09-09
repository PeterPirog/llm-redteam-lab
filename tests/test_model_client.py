import asyncio
import json
from pathlib import Path

import httpx

from llm_redteam.budget import BudgetLedger
from llm_redteam.domain import CampaignBudget
from llm_redteam.model_client import (
    BudgetedRoleModelClient,
    ModelMessage,
    ModelRequest,
    OpenAICompatibleRoleModelClient,
    ScriptedRoleModelClient,
)
from llm_redteam.model_roles import ModelRole, ModelsConfig, load_models_config

ROOT = Path(__file__).resolve().parents[1]


def test_example_model_roles_load_without_hard_coded_business_logic() -> None:
    config = load_models_config(ROOT / "config" / "models.example.yaml")

    planner = config.role(ModelRole.RED_PLANNER, required_capabilities={"reasoning"})
    mutator = config.role(ModelRole.RED_MUTATOR, required_capabilities={"text"})

    assert planner.model == "SET_LOCAL_REASONING_MODEL"
    assert mutator.model == "SET_LOCAL_FAST_MODEL"
    assert config.policy.local_first is True
    assert config.policy.allow_cloud_fallback is False


def test_scripted_role_client_is_deterministic_and_role_scoped() -> None:
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: ['{"action":"stop"}'],
            ModelRole.RED_MUTATOR: ["mutated"],
        }
    )
    response = asyncio.run(
        client.complete(
            ModelRequest(
                role=ModelRole.RED_PLANNER,
                messages=(ModelMessage(role="user", content="controlled input"),),
            )
        )
    )

    assert response.text == '{"action":"stop"}'
    assert client.calls[ModelRole.RED_PLANNER] == 1
    assert client.calls[ModelRole.RED_MUTATOR] == 0


def test_budgeted_client_accounts_model_calls_by_role() -> None:
    config = load_models_config(ROOT / "config" / "models.example.yaml")
    delegate = ScriptedRoleModelClient(
        {ModelRole.RED_PLANNER: ['{"action":"stop"}']}
    )
    ledger = BudgetLedger(
        CampaignBudget(
            max_attacks=1,
            max_generations=1,
            max_turns_per_attack=1,
            max_model_calls=2,
            max_model_calls_by_role={"red_planner": 1},
            max_total_output_tokens=2000,
            max_output_tokens_by_role={"red_planner": 1200},
            max_image_generations=0,
            wall_clock_seconds=60,
        )
    )
    client = BudgetedRoleModelClient(delegate, models=config, budget=ledger)

    response = asyncio.run(
        client.complete(
            ModelRequest(
                role=ModelRole.RED_PLANNER,
                messages=(ModelMessage(role="user", content="synthetic test"),),
            )
        )
    )

    assert response.error_kind is None
    snapshot = ledger.snapshot()
    assert snapshot.model_calls_by_role == (("red_planner", 1),)
    assert snapshot.output_tokens_by_role == (("red_planner", 0),)


def test_openai_compatible_role_client_uses_configured_role_endpoint() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "planner-local",
                "choices": [{"message": {"content": "structured result"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 7},
            },
        )

    config = ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner-local",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "max_output_tokens": 256,
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                },
            },
            "blue": {"source": "campaign"},
        }
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OpenAICompatibleRoleModelClient(config, client=http)
    response = asyncio.run(
        client.complete(
            ModelRequest(
                role=ModelRole.RED_PLANNER,
                messages=(
                    ModelMessage(role="system", content="return structured output"),
                    ModelMessage(role="user", content="synthetic test"),
                ),
            )
        )
    )
    asyncio.run(http.aclose())

    assert response.text == "structured result"
    assert response.input_tokens == 20
    assert response.output_tokens == 7
    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["model"] == "planner-local"
    assert body["max_tokens"] == 256


def test_cloud_role_is_blocked_by_local_first_policy() -> None:
    config = ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "cloud",
                    "model": "remote-model",
                    "class": "cloud",
                    "capabilities": ["text", "reasoning"],
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "local-model",
                    "class": "local",
                    "capabilities": ["text"],
                },
            },
        }
    )

    try:
        config.role(ModelRole.RED_PLANNER)
    except ValueError as exc:
        assert "blocked by local-first policy" in str(exc)
    else:
        raise AssertionError("cloud role should be blocked")
