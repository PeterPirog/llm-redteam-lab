import asyncio
import json

import httpx
import pytest

from llm_redteam.budget import BudgetExceeded, BudgetLedger
from llm_redteam.campaign_plan import RedPolicyKind
from llm_redteam.domain import CampaignBudget, TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_client import (
    AttackerVariantRoleModelClient,
    BudgetedRoleModelClient,
    ModelMessage,
    ModelRequest,
    OpenAICompatibleRoleModelClient,
    ScriptedRoleModelClient,
)
from llm_redteam.model_roles import ModelRole, ModelsConfig
from llm_redteam.red.runtime import RedAttackerPoolRuntime, RedStrategyRuntime
from llm_redteam.targets.base import SessionMode


def _role(
    model: str,
    *,
    capabilities: list[str],
    endpoint: str,
    max_output_tokens: int = 32,
    location: str = "local",
    fallback: list[str] | None = None,
) -> dict[str, object]:
    return {
        "provider": "ollama" if location == "local" else "cloud-provider",
        "model": model,
        "class": location,
        "capabilities": capabilities,
        "endpoint": endpoint,
        "max_output_tokens": max_output_tokens,
        "fallback": fallback or [],
    }


def _models(*, allow_cloud: bool = False) -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {
                "local_first": True,
                "allow_cloud_fallback": allow_cloud,
            },
            "roles": {
                "red_planner": _role(
                    "primary-planner",
                    capabilities=["text", "reasoning"],
                    endpoint="http://primary.local/v1/chat/completions",
                ),
                "red_mutator": _role(
                    "primary-mutator",
                    capabilities=["text"],
                    endpoint="http://primary.local/v1/chat/completions",
                ),
            },
            "red_attacker_pool": {
                "enabled": True,
                "variants": [
                    {
                        "id": "local-a",
                        "planner": _role(
                            "planner-a",
                            capabilities=["text", "reasoning"],
                            endpoint="http://a.local/v1/chat/completions",
                            max_output_tokens=17,
                            fallback=["availability-only-a"],
                        ),
                        "mutator": _role(
                            "mutator-a",
                            capabilities=["text"],
                            endpoint="http://a.local/v1/chat/completions",
                            max_output_tokens=11,
                        ),
                    },
                    {
                        "id": "local-b",
                        "planner": _role(
                            "planner-b",
                            capabilities=["text", "reasoning"],
                            endpoint="http://b.local/v1/chat/completions",
                            max_output_tokens=23,
                        ),
                        "mutator": _role(
                            "mutator-b",
                            capabilities=["text"],
                            endpoint="http://b.local/v1/chat/completions",
                            max_output_tokens=13,
                        ),
                    },
                ],
            },
        }
    )


def _budget(*, max_model_calls: int = 8) -> CampaignBudget:
    return CampaignBudget(
        max_attacks=4,
        max_generations=4,
        max_turns_per_attack=4,
        max_model_calls=max_model_calls,
        max_model_calls_by_role={"red_planner": max_model_calls},
        max_total_output_tokens=1000,
        max_output_tokens_by_role={"red_planner": 1000},
        max_image_generations=0,
        wall_clock_seconds=60,
    )


def _request(role: ModelRole = ModelRole.RED_PLANNER) -> ModelRequest:
    return ModelRequest(
        role=role,
        messages=(ModelMessage(role="user", content="synthetic attacker request"),),
    )


def test_primary_roles_remain_default_when_no_variant_is_selected() -> None:
    models = _models()

    primary = models.resolve_role_config(ModelRole.RED_PLANNER)
    attacker = models.resolve_role_config(
        ModelRole.RED_PLANNER,
        attacker_variant_id="local-a",
    )

    assert primary.model == "primary-planner"
    assert attacker.model == "planner-a"
    assert attacker.fallback == ("availability-only-a",)
    assert attacker.model != attacker.fallback[0]


def test_attacker_pool_requires_distinct_enabled_variants() -> None:
    raw = _models().model_dump(mode="json", by_alias=True)
    variants = raw["red_attacker_pool"]["variants"]
    assert isinstance(variants, list)
    variants[1]["planner"] = variants[0]["planner"]
    variants[1]["mutator"] = variants[0]["mutator"]

    with pytest.raises(ValueError, match="distinct configurations"):
        ModelsConfig.model_validate(raw)

    variants[1]["enabled"] = False
    with pytest.raises(ValueError, match="at least two enabled"):
        ModelsConfig.model_validate(raw)


def test_local_first_policy_applies_to_attacker_variants() -> None:
    raw = _models().model_dump(mode="json", by_alias=True)
    variants = raw["red_attacker_pool"]["variants"]
    assert isinstance(variants, list)
    variants[1]["planner"]["class"] = "cloud"
    variants[1]["planner"]["provider"] = "remote"

    with pytest.raises(ValueError, match="blocked by local-first policy"):
        ModelsConfig.model_validate(raw)

    raw["policy"]["allow_cloud_fallback"] = True
    config = ModelsConfig.model_validate(raw)
    assert config.attacker_variant("local-b").planner.location.value == "cloud"


def test_attacker_variant_client_stamps_red_requests_and_rejects_conflicts() -> None:
    delegate = ScriptedRoleModelClient({ModelRole.RED_PLANNER: ["ok"]})
    client = AttackerVariantRoleModelClient(delegate, attacker_variant_id="local-a")

    response = asyncio.run(client.complete(_request()))

    assert response.text == "ok"
    assert delegate.requests[0].metadata["attacker_variant_id"] == "local-a"

    conflicting = _request().model_copy(
        update={"metadata": {"attacker_variant_id": "local-b"}}
    )
    with pytest.raises(ValueError, match="conflicting"):
        asyncio.run(client.complete(conflicting))

    with pytest.raises(ValueError, match="non-Red"):
        asyncio.run(
            client.complete(
                _request(ModelRole.JUDGE_SEMANTIC)
            )
        )


def test_budget_reservation_uses_variant_config_but_logical_role_counter() -> None:
    models = _models()
    ledger = BudgetLedger(_budget())
    delegate = ScriptedRoleModelClient({ModelRole.RED_PLANNER: ["ok"]})
    budgeted = BudgetedRoleModelClient(delegate, models=models, budget=ledger)
    client = AttackerVariantRoleModelClient(budgeted, attacker_variant_id="local-a")

    asyncio.run(client.complete(_request()))

    snapshot = ledger.snapshot()
    assert snapshot.model_calls_by_role == (("red_planner", 1),)
    assert snapshot.output_tokens_by_role == (("red_planner", 0),)
    assert delegate.requests[0].metadata["attacker_variant_id"] == "local-a"


def test_openai_client_routes_each_attacker_to_its_configured_model_and_endpoint() -> None:
    models = _models()
    captured: list[tuple[str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.append((str(request.url), body))
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            base = OpenAICompatibleRoleModelClient(models, client=http)
            client_a = AttackerVariantRoleModelClient(base, attacker_variant_id="local-a")
            client_b = AttackerVariantRoleModelClient(base, attacker_variant_id="local-b")
            response_a = await client_a.complete(_request())
            response_b = await client_b.complete(_request())
            assert response_a.provider_metadata["attacker_variant_id"] == "local-a"
            assert response_b.provider_metadata["attacker_variant_id"] == "local-b"

    asyncio.run(run())

    assert captured[0][0] == "http://a.local/v1/chat/completions"
    assert captured[0][1]["model"] == "planner-a"
    assert captured[0][1]["max_tokens"] == 17
    assert captured[1][0] == "http://b.local/v1/chat/completions"
    assert captured[1][1]["model"] == "planner-b"
    assert captured[1][1]["max_tokens"] == 23


def test_red_runtime_descriptor_binds_exact_attacker_variant() -> None:
    models = _models()
    ledger = BudgetLedger(_budget())
    delegate = ScriptedRoleModelClient({})

    runtime_a = RedStrategyRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.STATELESS,
        campaign_budget=_budget(),
        models=models,
        model_client=delegate,
        budget=ledger,
        attacker_variant_id="local-a",
    )
    runtime_b = RedStrategyRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.STATELESS,
        campaign_budget=_budget(),
        models=models,
        model_client=delegate,
        budget=ledger,
        attacker_variant_id="local-b",
    )

    descriptor_a = runtime_a.descriptor()
    descriptor_b = runtime_b.descriptor()
    assert descriptor_a["attacker_variant"]["id"] == "local-a"
    assert descriptor_b["attacker_variant"]["id"] == "local-b"
    assert descriptor_a["red_planner"]["model"] == "planner-a"
    assert descriptor_b["red_planner"]["model"] == "planner-b"
    assert descriptor_a != descriptor_b


def test_pool_runtimes_share_one_global_campaign_budget() -> None:
    models = _models()
    campaign_budget = _budget(max_model_calls=2)
    ledger = BudgetLedger(campaign_budget)
    delegate = ScriptedRoleModelClient(
        {ModelRole.RED_PLANNER: ["a", "b", "should-not-run"]}
    )
    pool = RedAttackerPoolRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.STATELESS,
        campaign_budget=campaign_budget,
        models=models,
        model_client=delegate,
        budget=ledger,
    )

    asyncio.run(pool.runtime_for("local-a").model_client.complete(_request()))
    asyncio.run(pool.runtime_for("local-b").model_client.complete(_request()))
    with pytest.raises(BudgetExceeded, match="model_calls budget exceeded"):
        asyncio.run(pool.runtime_for("local-a").model_client.complete(_request()))

    snapshot = ledger.snapshot()
    assert pool.variant_ids == ("local-a", "local-b")
    assert snapshot.model_calls == 2
    assert snapshot.model_calls_by_role == (("red_planner", 2),)
    assert len(delegate.requests) == 2
    assert [
        request.metadata["attacker_variant_id"] for request in delegate.requests
    ] == ["local-a", "local-b"]


def test_pool_runtime_keeps_evaluation_cross_trial_learning_frozen() -> None:
    pool = RedAttackerPoolRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.EVALUATION,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.STATELESS,
        campaign_budget=_budget(),
        models=_models(),
        model_client=ScriptedRoleModelClient({}),
        budget=BudgetLedger(_budget()),
    )

    assert all(
        pool.runtime_for(variant_id).cross_trial_learning_enabled is False
        for variant_id in pool.variant_ids
    )
    assert pool.pool_fingerprint
