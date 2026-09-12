"""Provider-independent model clients for Red/Judge/Forensic logical roles.

The orchestration layer addresses models by role. Concrete providers, endpoints and
model identifiers stay in runtime configuration. No client is allowed to change
campaign budgets or security policy.

Intentional multi-attacker routing is explicit in request metadata and is allowed only
for Red planner/mutator roles. All variants still consume the same campaign budget.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from typing import Protocol, runtime_checkable

import httpx
from pydantic import Field

from .budget import BudgetLedger
from .domain import StrictModel
from .model_roles import ModelRole, ModelsConfig

_ATTACKER_VARIANT_METADATA_KEY = "attacker_variant_id"
_RED_ROLES = frozenset({ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR})


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


class AttackerVariantRoleModelClient:
    """Stamp one predeclared attacker variant onto Red requests only."""

    def __init__(self, delegate: RoleModelClient, *, attacker_variant_id: str) -> None:
        if not attacker_variant_id:
            raise ValueError("attacker_variant_id must be non-empty")
        self.delegate = delegate
        self.attacker_variant_id = attacker_variant_id

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if request.role not in _RED_ROLES:
            raise ValueError(
                f"attacker variant client cannot route non-Red role: {request.role.value}"
            )
        existing = request.metadata.get(_ATTACKER_VARIANT_METADATA_KEY)
        if existing is not None and existing != self.attacker_variant_id:
            raise ValueError(
                "conflicting attacker_variant_id in Red model request metadata"
            )
        metadata = dict(request.metadata)
        metadata[_ATTACKER_VARIANT_METADATA_KEY] = self.attacker_variant_id
        return await self.delegate.complete(request.model_copy(update={"metadata": metadata}))


class BudgetedRoleModelClient:
    """Decorate any role client with deterministic, role-aware budget accounting."""

    def __init__(
        self,
        delegate: RoleModelClient,
        *,
        models: ModelsConfig,
        budget: BudgetLedger,
    ) -> None:
        self.delegate = delegate
        self.models = models
        self.budget = budget

    async def complete(self, request: ModelRequest) -> ModelResponse:
        config = self.models.resolve_role_config(
            request.role,
            attacker_variant_id=_attacker_variant_id(request),
        )
        reserved = config.max_output_tokens
        self.budget.reserve_model_call(
            role=request.role.value,
            expected_output_tokens=reserved,
        )
        response = await self.delegate.complete(request)
        if response.output_tokens is not None:
            self.budget.record_actual_output_tokens(
                role=request.role.value,
                reserved=reserved,
                actual=response.output_tokens,
            )
        return response


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
        attacker_variant_id = _attacker_variant_id(request)
        config = self.models.resolve_role_config(
            request.role,
            attacker_variant_id=attacker_variant_id,
        )
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
        if attacker_variant_id is not None:
            metadata[_ATTACKER_VARIANT_METADATA_KEY] = attacker_variant_id
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


def _attacker_variant_id(request: ModelRequest) -> str | None:
    variant_id = request.metadata.get(_ATTACKER_VARIANT_METADATA_KEY)
    if variant_id is None:
        return None
    if request.role not in _RED_ROLES:
        raise ValueError(
            f"attacker_variant_id cannot be used with non-Red role: {request.role.value}"
        )
    if not variant_id:
        raise ValueError("attacker_variant_id request metadata cannot be empty")
    return variant_id
