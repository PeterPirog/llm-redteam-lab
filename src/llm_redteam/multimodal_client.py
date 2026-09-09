"""Provider-independent visual model clients for multimodal judging.

Image bytes remain in an explicit artifact store and are resolved only for the
inference call that needs them. Normal model requests, telemetry and persistence
contain artifact identifiers and hashes rather than raw images.
"""

from __future__ import annotations

import base64
import json
import os
from collections import defaultdict, deque
from typing import Protocol, runtime_checkable

import httpx
from pydantic import Field

from .budget import BudgetLedger
from .domain import StrictModel
from .image_artifacts import ImageArtifactStore
from .model_roles import ModelRole, ModelsConfig


class VisualModelRequest(StrictModel):
    role: ModelRole
    system_prompt: str = Field(min_length=1)
    user_prompt: str = Field(min_length=1)
    image_artifact_ids: tuple[str, ...] = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)


class VisualModelResponse(StrictModel):
    text: str | None = None
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)
    error_kind: str | None = None


@runtime_checkable
class VisualRoleModelClient(Protocol):
    async def complete_visual(self, request: VisualModelRequest) -> VisualModelResponse: ...


class ScriptedVisualRoleModelClient:
    """Deterministic multimodal client used to prove judging without inference."""

    def __init__(self, scripts: dict[ModelRole, list[str]]) -> None:
        self._scripts = {role: deque(values) for role, values in scripts.items()}
        self.calls: dict[ModelRole, int] = defaultdict(int)
        self.requests: list[VisualModelRequest] = []

    async def complete_visual(self, request: VisualModelRequest) -> VisualModelResponse:
        self.requests.append(request)
        self.calls[request.role] += 1
        queue = self._scripts.get(request.role)
        if not queue:
            return VisualModelResponse(error_kind=f"script_exhausted:{request.role.value}")
        return VisualModelResponse(text=queue.popleft(), output_tokens=0)


class BudgetedVisualRoleModelClient:
    """Apply role and token budgets before any multimodal inference."""

    def __init__(
        self,
        delegate: VisualRoleModelClient,
        *,
        models: ModelsConfig,
        budget: BudgetLedger,
    ) -> None:
        self.delegate = delegate
        self.models = models
        self.budget = budget

    async def complete_visual(self, request: VisualModelRequest) -> VisualModelResponse:
        config = self.models.role(
            request.role,
            required_capabilities={"text", "vision"},
        )
        reserved = config.max_output_tokens
        self.budget.reserve_model_call(
            role=request.role.value,
            expected_output_tokens=reserved,
        )
        response = await self.delegate.complete_visual(request)
        if response.output_tokens is not None:
            self.budget.record_actual_output_tokens(
                role=request.role.value,
                reserved=reserved,
                actual=response.output_tokens,
            )
        return response


class OpenAICompatibleVisualRoleModelClient:
    """Call a vision-capable role through an OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        models: ModelsConfig,
        artifacts: ImageArtifactStore,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 90.0,
    ) -> None:
        self.models = models
        self.artifacts = artifacts
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def complete_visual(self, request: VisualModelRequest) -> VisualModelResponse:
        config = self.models.role(
            request.role,
            required_capabilities={"text", "vision"},
        )
        if not config.endpoint:
            return VisualModelResponse(error_kind=f"missing_endpoint:{request.role.value}")

        headers = {"Content-Type": "application/json"}
        if config.api_key_env:
            token = os.getenv(config.api_key_env)
            if not token:
                return VisualModelResponse(
                    error_kind=f"missing_api_key_env:{config.api_key_env}"
                )
            headers["Authorization"] = f"Bearer {token}"

        try:
            visual_parts = [
                self._image_part(artifact_id) for artifact_id in request.image_artifact_ids
            ]
        except (FileNotFoundError, ValueError) as exc:
            return VisualModelResponse(
                error_kind=f"artifact_resolution:{type(exc).__name__}"
            )

        payload: dict[str, object] = {
            "model": config.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": request.user_prompt},
                        *visual_parts,
                    ],
                },
            ],
            "temperature": config.temperature,
            "max_tokens": config.max_output_tokens,
            "stream": False,
        }

        try:
            response = await self._client.post(config.endpoint, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            return VisualModelResponse(error_kind=f"http_status:{exc.response.status_code}")
        except httpx.HTTPError as exc:
            return VisualModelResponse(error_kind=f"transport:{type(exc).__name__}")
        except json.JSONDecodeError:
            return VisualModelResponse(error_kind="protocol:invalid_json")

        try:
            text = body["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            return VisualModelResponse(error_kind="protocol:missing_chat_completion")
        if text is not None and not isinstance(text, str):
            return VisualModelResponse(error_kind="protocol:non_text_content")

        usage = body.get("usage", {}) if isinstance(body, dict) else {}
        return VisualModelResponse(
            text=text,
            input_tokens=self._token_value(usage, "prompt_tokens", "input_tokens"),
            output_tokens=self._token_value(
                usage,
                "completion_tokens",
                "output_tokens",
            ),
            provider_metadata={"provider": config.provider, "model": config.model},
        )

    def _image_part(self, artifact_id: str) -> dict[str, object]:
        artifact, data = self.artifacts.get(artifact_id)
        encoded = base64.b64encode(data).decode("ascii")
        return {
            "type": "image_url",
            "image_url": {
                "url": f"data:{artifact.mime_type};base64,{encoded}",
            },
        }

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
