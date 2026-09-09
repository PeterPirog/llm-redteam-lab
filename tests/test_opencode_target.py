import asyncio
import json

import httpx
import pytest

from llm_redteam.targets import OpenCodeConfig, OpenCodeTarget
from llm_redteam.targets.base import (
    ConversationMessage,
    MessageRole,
    SessionMode,
    TargetRequest,
)


def _config(**updates: object) -> OpenCodeConfig:
    values: dict[str, object] = {
        "id": "opencode-test",
        "base_url": "http://opencode.local",
        "model_provider_id": "ollama",
        "model_id": "qwen-test",
        "workspace_root": r"C:\\work\\repo",
        "application_version": "test",
    }
    values.update(updates)
    return OpenCodeConfig.model_validate(values)


def _message(*, status: str = "completed") -> dict[str, object]:
    return {
        "info": {
            "id": "msg-1",
            "finish": "stop",
            "cost": 0,
            "tokens": {"input": 10, "output": 5, "reasoning": 2},
        },
        "parts": [
            {"type": "text", "text": "Synthetic response"},
            {
                "type": "tool",
                "callID": "call-1",
                "sessionID": "session-1",
                "messageID": "msg-1",
                "tool": "bash",
                "state": {
                    "status": status,
                    "input": {"command": "git push origin main"},
                    "output": "synthetic tool output",
                },
            },
        ],
    }


def test_opencode_target_prefers_persisted_tool_state_and_redacts_payload() -> None:
    requests: list[tuple[str, str, object | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        requests.append((request.method, request.url.path, body))
        if request.method == "POST" and request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-1"})
        if request.method == "POST" and request.url.path == "/session/session-1/message":
            return httpx.Response(200, json=_message(status="running"))
        if (
            request.method == "GET"
            and request.url.path == "/session/session-1/message/msg-1"
        ):
            return httpx.Response(200, json=_message(status="completed"))
        return httpx.Response(404)

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = OpenCodeTarget(_config(), client=client)
            return await target.execute(
                TargetRequest(attack_id="case-1", prompt="synthetic agent test")
            )

    response = asyncio.run(run())

    assert requests[0][0:2] == ("POST", "/session")
    assert requests[1][0:2] == ("POST", "/session/session-1/message")
    payload = requests[1][2]
    assert isinstance(payload, dict)
    assert payload["agent"] == "build"
    assert payload["model"] == {"providerID": "ollama", "modelID": "qwen-test"}
    assert payload["parts"] == [{"type": "text", "text": "synthetic agent test"}]

    assert response.session_id == "session-1"
    assert response.text == "Synthetic response"
    assert response.provider_metadata["agent_trace_complete"] is True
    tool_evidence = [item for item in response.evidence if item.kind.value == "tool_call"]
    assert len(tool_evidence) == 1
    evidence = tool_evidence[0]
    assert evidence.data["phase"] == "executed"
    assert {"shell", "git_push", "network"}.issubset(set(evidence.data["categories"]))
    serialized = evidence.model_dump_json()
    assert "git push origin main" not in serialized
    assert "synthetic tool output" not in serialized


def test_persisted_message_failure_marks_agent_trace_incomplete() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-1"})
        if request.method == "POST" and request.url.path == "/session/session-1/message":
            return httpx.Response(
                200,
                json={
                    "info": {"id": "msg-1"},
                    "parts": [{"type": "text", "text": "Immediate response"}],
                },
            )
        if request.method == "GET":
            return httpx.Response(503)
        return httpx.Response(404)

    async def run() -> object:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = OpenCodeTarget(_config(), client=client)
            return await target.execute(
                TargetRequest(attack_id="case-1", prompt="probe")
            )

    response = asyncio.run(run())

    assert response.text == "Immediate response"
    assert response.provider_metadata["durable_trace_verified"] is False
    assert response.provider_metadata["agent_trace_complete"] is False


def test_replay_with_prior_history_fails_closed() -> None:
    async def run() -> object:
        transport = httpx.MockTransport(lambda _: httpx.Response(500))
        async with httpx.AsyncClient(transport=transport) as client:
            target = OpenCodeTarget(_config(), client=client)
            return await target.execute(
                TargetRequest(
                    attack_id="case-1",
                    prompt="next turn",
                    session_mode=SessionMode.REPLAY,
                    conversation=(
                        ConversationMessage(role=MessageRole.USER, content="prior turn"),
                    ),
                )
            )

    response = asyncio.run(run())

    assert response.error_kind == "session:opencode_requires_target_managed_history"


def test_missing_server_password_environment_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENCODE_TEST_PASSWORD", raising=False)

    async def run() -> object:
        transport = httpx.MockTransport(lambda _: httpx.Response(500))
        async with httpx.AsyncClient(transport=transport) as client:
            target = OpenCodeTarget(
                _config(password_env="OPENCODE_TEST_PASSWORD"),
                client=client,
            )
            return await target.execute(
                TargetRequest(attack_id="case-1", prompt="probe")
            )

    response = asyncio.run(run())

    assert response.error_kind == "missing_password_env:OPENCODE_TEST_PASSWORD"
