"""Provider-independent model clients for Red/Judge/Forensic logical roles.

The orchestration layer addresses models by role. Concrete providers, endpoints and
model identifiers stay in runtime configuration. No client is allowed to change
campaign budgets or security policy.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from typing import Protocol, runtime_checkable

import httpx
from pydantic import Field

from .domain import StrictModel
from .model_roles import ModelRole, ModelsConfig


class ModelMessage(StrictModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str = Field(min_length=1)


class ModelRequest(StrictModel):
    role: ModelRole
    messages: tuple[ModelMessage, ...] = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)


class ModelResponse(StrictModel):
    text: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)
    error_kind: str | None = None


@runtime_checkable
class RoleModelClient(Protocol):
    """Complete one request for a logical model role."""

    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class ScriptedRoleModelClient:
    """Deterministic client used to prove orchestration without inference."""

    def __init__(self, scripts: dict[ModelRole, list[str]]) -> None:
        self._scripts = {role: deque(values) for role, values in scripts.items()}
        self.calls: dict[ModelRole, int] = defaultdict(int)
        self.requests: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        self.calls[request.role] += 1
        queue = self._scripts.get(request.role)
        if not queue:
            return ModelResponse(error_kind=f"script_exhausted:{request.role.value}")
        return ModelResponse(text=queue.popleft(), output_tokens=0)


class OpenAICompatibleRoleModelClient:
    """Call configured role models through an OpenAI-compatible chat endpoint.

    This supports local Ollama/OpenWebUI and compatible gateways without making
    provider names part of Red business logic. Each enabled role must declare an
    explicit endpoint in configuration before this client can invoke it.
    """

    def __init__(
        self,
        models: ModelsConfig,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.models = models
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def complete(self, request: ModelRequest) -> ModelResponse:
        config = self.models.role(request.role)
        if not config.endpoint:
            return ModelResponse(error_kind=f"missing_endpoint:{request.role.value}")

        headers = {"Content-Type": "application/json"}
        if config.api_key_env:
            token = os.getenv(config.api_key_env)
            if not token:
                return ModelResponse(error_kind=f"missing_api_key_env:{config.api_key_env}")
            headers["Authorization"] = f"Bearer {token}"

        payload: dict[str, object] = {
            "model": config.model,
            "messages": [message.model_dump() for message in request.messages],
            "temperature": config.temperature,
            "max_tokens": config.max_output_tokens,
            "stream": False,
        }

        try:
            response = await self._client.post(config.endpoint, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            return ModelResponse(error_kind=f"http_status:{exc.response.status_code}")
        except httpx.HTTPError as exc:
            return ModelResponse(error_kind=f"transport:{type(exc).__name__}")
        except json.JSONDecodeError:
            return ModelResponse(error_kind="protocol:invalid_json")

        try:
            text = body["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            return ModelResponse(error_kind="protocol:missing_chat_completion")
        if text is not None and not isinstance(text, str):
            return ModelResponse(error_kind="protocol:non_text_content")

        usage = body.get("usage", {}) if isinstance(body, dict) else {}
        input_tokens = self._token_value(usage, "prompt_tokens", "input_tokens")
        output_tokens = self._token_value(usage, "completion_tokens", "output_tokens")
        metadata: dict[str, str | int | float | bool] = {
            "provider": config.provider,
            "model": config.model,
        }
        if isinstance(body, dict) and isinstance(body.get("model"), str):
            metadata["response_model"] = body["model"]

        return ModelResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider_metadata=metadata,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _token_value(usage: object, *keys: str) -> int | None:
        if not isinstance(usage, dict):
            return None
        for key in keys:
            value = usage.get(key)
            if isinstance(value, int) and value >= 0:
                return value
        return None
