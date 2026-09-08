import asyncio
import json

import httpx

from llm_redteam.domain import TargetClass, TargetMode
from llm_redteam.targets.base import TargetRequest
from llm_redteam.targets.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleTarget,
)


def test_openai_compatible_target_normalizes_response_and_usage() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "local-test-model",
                "choices": [{"message": {"role": "assistant", "content": "safe reply"}}],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 3,
                    "total_tokens": 15,
                },
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    config = OpenAICompatibleConfig(
        id="ollama-local-test",
        base_url="http://localhost:11434",
        model="local-test-model",
        provider="ollama",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        max_output_tokens=128,
    )
    target = OpenAICompatibleTarget(config, client=client)

    response = asyncio.run(
        target.execute(TargetRequest(attack_id="A1", prompt="controlled test"))
    )
    asyncio.run(client.aclose())

    assert response.error_kind is None
    assert response.text == "safe reply"
    assert response.provider_metadata["total_tokens"] == 15
    assert captured["path"] == "/v1/chat/completions"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["model"] == "local-test-model"
    assert body["max_tokens"] == 128


def test_openwebui_path_uses_same_protocol_without_provider_specific_logic() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat/completions"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(
            id="openwebui-test",
            base_url="http://localhost:3000",
            endpoint_path="/api/chat/completions",
            model="model-a",
            provider="openwebui",
            target_class=TargetClass.WRITING,
        ),
        client=client,
    )

    response = asyncio.run(target.execute(TargetRequest(attack_id="A2", prompt="test")))
    asyncio.run(client.aclose())
    assert response.text == "ok"


def test_http_failure_is_measurement_error_not_defense_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(
            id="failing-target",
            base_url="http://localhost:11434",
            model="model-a",
            provider="ollama",
            target_class=TargetClass.REASONING,
        ),
        client=client,
    )

    response = asyncio.run(target.execute(TargetRequest(attack_id="A3", prompt="test")))
    asyncio.run(client.aclose())
    assert response.error_kind == "http_status:503"
