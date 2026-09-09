"""OpenAI-compatible chat-completions target adapter.

The adapter is protocol-oriented and works with compatible local runtimes such
as Ollama as well as gateways exposing the same response shape. OpenWebUI uses a
different path (`/api/chat/completions`) but can reuse the same protocol logic.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from hashlib import sha256

import httpx
from pydantic import Field

from ..domain import (
    EvidenceKind,
    EvidenceRecord,
    StrictModel,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from .base import SessionMode, TargetRequest, TargetResponse


class OpenAICompatibleConfig(StrictModel):
    id: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1, default="openai-compatible")
    target_class: TargetClass
    target_mode: TargetMode = TargetMode.MODEL
    endpoint_path: str = "/v1/chat/completions"
    api_key_env: str | None = None
    timeout_seconds: float = Field(gt=0.0, default=60.0)
    temperature: float = Field(ge=0.0, le=2.0, default=0.0)
    max_output_tokens: int | None = Field(gt=0, default=None)
    capabilities: frozenset[str] = frozenset({"text"})
    supports_target_managed_sessions: bool = False


class OpenAICompatibleTarget:
    """Normalize an OpenAI-compatible chat endpoint into a Blue target."""

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._client = client or httpx.AsyncClient(timeout=config.timeout_seconds)
        self._owns_client = client is None

    @property
    def identity(self) -> TargetIdentity:
        fingerprint = "|".join(
            [
                self.config.base_url.rstrip("/"),
                self.config.endpoint_path,
                self.config.model,
                self.config.provider,
                self.config.target_class.value,
                self.config.target_mode.value,
                str(self.config.temperature),
                str(self.config.max_output_tokens),
                str(self.config.supports_target_managed_sessions),
            ]
        )
        return TargetIdentity(
            id=self.config.id,
            target_class=self.config.target_class,
            target_mode=self.config.target_mode,
            model=self.config.model,
            provider=self.config.provider,
            runtime=self.config.base_url,
            configuration_hash=sha256(fingerprint.encode()).hexdigest(),
            capabilities=self.config.capabilities,
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        if request.input_artifact_refs or any(
            message.artifact_refs for message in request.conversation
        ):
            return TargetResponse(error_kind="input:multimodal_not_supported")
        if (
            request.session_mode == SessionMode.TARGET_MANAGED
            and not self.config.supports_target_managed_sessions
        ):
            return TargetResponse(error_kind="session:target_managed_not_supported")

        url = self.config.base_url.rstrip("/") + self.config.endpoint_path
        headers = {"Content-Type": "application/json"}
        if self.config.api_key_env:
            token = os.getenv(self.config.api_key_env)
            if not token:
                return TargetResponse(error_kind=f"missing_api_key_env:{self.config.api_key_env}")
            headers["Authorization"] = f"Bearer {token}"

        messages = [
            {"role": message.role.value, "content": message.content}
            for message in request.conversation
        ]
        messages.append({"role": "user", "content": request.prompt})

        payload: dict[str, object] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "stream": False,
        }
        if self.config.max_output_tokens is not None:
            payload["max_tokens"] = self.config.max_output_tokens

        try:
            response = await self._client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            return TargetResponse(error_kind=f"http_status:{exc.response.status_code}")
        except httpx.HTTPError as exc:
            return TargetResponse(error_kind=f"transport:{type(exc).__name__}")
        except ValueError:
            return TargetResponse(error_kind="protocol:invalid_json")

        try:
            choice = body["choices"][0]
            message = choice["message"]
            content = message.get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            return TargetResponse(error_kind="protocol:missing_chat_completion")

        if content is not None and not isinstance(content, str):
            return TargetResponse(error_kind="protocol:non_text_content")

        usage = body.get("usage") if isinstance(body, dict) else None
        provider_metadata: dict[str, str | int | float | bool] = {}
        if isinstance(usage, dict):
            for source_key, target_key in (
                ("prompt_tokens", "prompt_tokens"),
                ("completion_tokens", "completion_tokens"),
                ("total_tokens", "total_tokens"),
                ("input_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
            ):
                value = usage.get(source_key)
                if isinstance(value, int):
                    provider_metadata[target_key] = value
        if isinstance(body, dict) and isinstance(body.get("model"), str):
            provider_metadata["response_model"] = body["model"]

        evidence = EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="openai_compatible_target",
            observed_at=datetime.now(UTC).isoformat(),
            data={
                "http_status": response.status_code,
                "endpoint_path": self.config.endpoint_path,
                "session_mode": request.session_mode.value,
                "history_messages": len(request.conversation),
            },
            redacted=True,
        )
        return TargetResponse(
            text=content,
            evidence=(evidence,),
            provider_metadata=provider_metadata,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
