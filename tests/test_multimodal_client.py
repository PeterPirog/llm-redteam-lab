import asyncio
import json

import httpx
import pytest

from llm_redteam.budget import BudgetLedger
from llm_redteam.domain import CampaignBudget
from llm_redteam.image_artifacts import InMemoryImageArtifactStore
from llm_redteam.model_roles import ModelRole, ModelsConfig
from llm_redteam.multimodal_client import (
    BudgetedVisualRoleModelClient,
    OpenAICompatibleVisualRoleModelClient,
    ScriptedVisualRoleModelClient,
    VisualModelRequest,
)


def _models(*, vision: bool = True) -> ModelsConfig:
    judge_capabilities = ["text", "vision"] if vision else ["text"]
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "local",
                    "model": "planner",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "max_output_tokens": 50,
                },
                "red_mutator": {
                    "provider": "local",
                    "model": "mutator",
                    "class": "local",
                    "capabilities": ["text"],
                    "max_output_tokens": 50,
                },
                "judge_multimodal": {
                    "provider": "local",
                    "model": "vision-judge",
                    "class": "local",
                    "endpoint": "http://vision.local/v1/chat/completions",
                    "capabilities": judge_capabilities,
                    "max_output_tokens": 50,
                },
            },
        }
    )


def _request(artifact_id: str) -> VisualModelRequest:
    return VisualModelRequest(
        role=ModelRole.JUDGE_MULTIMODAL,
        system_prompt="judge system",
        user_prompt="judge this synthetic image",
        image_artifact_ids=(artifact_id,),
    )


def test_openai_compatible_visual_client_resolves_artifact_only_for_inference() -> None:
    artifacts = InMemoryImageArtifactStore()
    artifact = artifacts.put(
        b"synthetic-image-bytes",
        mime_type="image/png",
        width=16,
        height=16,
    )
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.update(body)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "{\"ok\":true}"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OpenAICompatibleVisualRoleModelClient(
                _models(),
                artifacts,
                client=http,
            )
            return await client.complete_visual(_request(artifact.artifact_id))

    response = asyncio.run(run())

    assert response.error_kind is None
    assert response.input_tokens == 12
    assert response.output_tokens == 3
    messages = captured["messages"]
    assert isinstance(messages, list)
    user_content = messages[1]["content"]
    assert user_content[0] == {"type": "text", "text": "judge this synthetic image"}
    image_url = user_content[1]["image_url"]["url"]
    assert image_url.startswith("data:image/png;base64,")
    assert artifact.artifact_id not in image_url


def test_visual_client_rejects_text_only_judge_assignment() -> None:
    artifacts = InMemoryImageArtifactStore()
    artifact = artifacts.put(
        b"synthetic-image-bytes",
        mime_type="image/png",
        width=16,
        height=16,
    )
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OpenAICompatibleVisualRoleModelClient(
                _models(vision=False),
                artifacts,
                client=http,
            )
            await client.complete_visual(_request(artifact.artifact_id))

    with pytest.raises(ValueError, match="lacks capabilities: vision"):
        asyncio.run(run())
    assert called is False


def test_budgeted_visual_client_accounts_for_multimodal_role_tokens() -> None:
    artifacts = InMemoryImageArtifactStore()
    artifact = artifacts.put(
        b"synthetic-image-bytes",
        mime_type="image/png",
        width=16,
        height=16,
    )
    delegate = ScriptedVisualRoleModelClient(
        {ModelRole.JUDGE_MULTIMODAL: ['{"objective_violated":null}']}
    )
    budget = BudgetLedger(
        CampaignBudget(
            max_attacks=1,
            max_generations=1,
            max_turns_per_attack=1,
            max_model_calls=2,
            max_model_calls_by_role={"judge_multimodal": 2},
            max_total_output_tokens=100,
            max_output_tokens_by_role={"judge_multimodal": 100},
            max_image_generations=1,
            wall_clock_seconds=60,
            max_non_progress_attempts=2,
        )
    )
    client = BudgetedVisualRoleModelClient(
        delegate,
        models=_models(),
        budget=budget,
    )

    asyncio.run(client.complete_visual(_request(artifact.artifact_id)))
    snapshot = budget.snapshot()

    assert snapshot.model_calls == 1
    assert snapshot.model_calls_by_role == (("judge_multimodal", 1),)
    assert snapshot.output_tokens == 0
