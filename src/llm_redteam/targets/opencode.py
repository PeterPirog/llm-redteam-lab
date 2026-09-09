"""OpenCode AGENT target adapter with durable tool-state evidence.

The adapter uses the headless OpenCode HTTP server. It deliberately treats
persisted message parts as more authoritative than live SSE events so transient
stream loss cannot silently turn missing tool evidence into a PASS.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from hashlib import sha256

import httpx
from pydantic import Field

from ..agent_actions import (
    AgentActionObservation,
    AgentActionPhase,
    canonical_json_hash,
    classify_agent_action,
)
from ..domain import (
    EvidenceKind,
    EvidenceRecord,
    StrictModel,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from .base import SessionMode, TargetRequest, TargetResponse


class OpenCodeConfig(StrictModel):
    id: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    model_provider_id: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    agent: str = Field(min_length=1, default="build")
    workspace_root: str | None = None
    application_version: str | None = None
    timeout_seconds: float = Field(gt=0.0, default=120.0)
    password_env: str | None = None
    username: str = Field(min_length=1, default="opencode")
    session_path: str = "/session"
    message_path_template: str = "/session/{session_id}/message"
    persisted_message_path_template: str = "/session/{session_id}/message/{message_id}"
    capabilities: frozenset[str] = frozenset(
        {"text", "coding", "tools", "filesystem", "shell", "agent"}
    )


class OpenCodeTarget:
    """Normalize a headless OpenCode instance into a first-class AGENT Blue target."""

    def __init__(
        self,
        config: OpenCodeConfig,
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
                self.config.model_provider_id,
                self.config.model_id,
                self.config.agent,
                self.config.workspace_root or "",
                self.config.application_version or "",
                self.config.session_path,
                self.config.message_path_template,
                self.config.persisted_message_path_template,
                str(bool(self.config.password_env)),
            ]
        )
        return TargetIdentity(
            id=self.config.id,
            target_class=TargetClass.CODING,
            target_mode=TargetMode.AGENT,
            model=f"{self.config.model_provider_id}/{self.config.model_id}",
            provider="opencode",
            runtime=self.config.base_url,
            application="OpenCode",
            application_version=self.config.application_version,
            configuration_hash=sha256(fingerprint.encode()).hexdigest(),
            capabilities=self.config.capabilities,
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        if request.input_artifact_refs or any(
            message.artifact_refs for message in request.conversation
        ):
            return TargetResponse(error_kind="input:multimodal_not_supported")
        if request.session_mode == SessionMode.REPLAY and request.conversation:
            return TargetResponse(error_kind="session:opencode_requires_target_managed_history")

        auth = self._auth()
        if isinstance(auth, TargetResponse):
            return auth

        session_id = request.session_id
        if self._requires_new_session(request):
            session_id = await self._create_session(request.attack_id, auth)
            if session_id is None:
                return TargetResponse(error_kind="protocol:session_creation_failed")
        if session_id is None:
            return TargetResponse(error_kind="protocol:missing_session_id")

        message_url = self._url(
            self.config.message_path_template.format(session_id=session_id)
        )
        payload = {
            "agent": self.config.agent,
            "model": {
                "providerID": self.config.model_provider_id,
                "modelID": self.config.model_id,
            },
            "parts": [{"type": "text", "text": request.prompt}],
        }

        try:
            response = await self._client.post(message_url, auth=auth, json=payload)
            response.raise_for_status()
            immediate = response.json()
        except httpx.HTTPStatusError as exc:
            return TargetResponse(
                session_id=session_id,
                error_kind=f"http_status:{exc.response.status_code}",
            )
        except httpx.HTTPError as exc:
            return TargetResponse(
                session_id=session_id,
                error_kind=f"transport:{type(exc).__name__}",
            )
        except ValueError:
            return TargetResponse(
                session_id=session_id,
                error_kind="protocol:invalid_message_json",
            )

        if not isinstance(immediate, dict):
            return TargetResponse(
                session_id=session_id,
                error_kind="protocol:invalid_message_shape",
            )
        message_id = self._message_id(immediate)
        if message_id is None:
            return TargetResponse(
                session_id=session_id,
                error_kind="protocol:missing_message_id",
            )

        durable, durable_verified = await self._load_persisted_message(
            session_id,
            message_id,
            auth,
        )
        source_body = durable if durable_verified and durable is not None else immediate
        text, evidence, trace_protocol_valid, metadata = self._normalize_message(
            source_body,
            session_id=session_id,
            message_id=message_id,
            durable=durable_verified,
        )
        trace_complete = durable_verified and trace_protocol_valid
        metadata["agent_trace_complete"] = trace_complete
        metadata["durable_trace_verified"] = durable_verified

        request_evidence = EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="opencode_target",
            observed_at=datetime.now(UTC).isoformat(),
            data={
                "session_mode": request.session_mode.value,
                "durable_trace_verified": durable_verified,
                "agent_trace_complete": trace_complete,
                "message_id_hash": sha256(message_id.encode()).hexdigest(),
            },
            redacted=True,
        )
        return TargetResponse(
            text=text,
            evidence=(*evidence, request_evidence),
            provider_metadata=metadata,
            session_id=session_id,
        )

    def _requires_new_session(self, request: TargetRequest) -> bool:
        if request.session_id is None:
            return True
        if request.session_mode != SessionMode.TARGET_MANAGED:
            return False
        return request.metadata.get("turn_ordinal") == "1"

    def _auth(self) -> httpx.BasicAuth | None | TargetResponse:
        if self.config.password_env is None:
            return None
        password = os.getenv(self.config.password_env)
        if not password:
            return TargetResponse(error_kind=f"missing_password_env:{self.config.password_env}")
        return httpx.BasicAuth(self.config.username, password)

    async def _create_session(
        self,
        attack_id: str,
        auth: httpx.BasicAuth | None,
    ) -> str | None:
        try:
            response = await self._client.post(
                self._url(self.config.session_path),
                auth=auth,
                json={"title": f"llm-redteam:{attack_id}"},
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return None
        if not isinstance(body, dict):
            return None
        session_id = body.get("id")
        return session_id if isinstance(session_id, str) and session_id else None

    async def _load_persisted_message(
        self,
        session_id: str,
        message_id: str,
        auth: httpx.BasicAuth | None,
    ) -> tuple[dict[str, object] | None, bool]:
        path = self.config.persisted_message_path_template.format(
            session_id=session_id,
            message_id=message_id,
        )
        try:
            response = await self._client.get(self._url(path), auth=auth)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return None, False
        if not isinstance(body, dict):
            return None, False
        return body, True

    def _normalize_message(
        self,
        body: dict[str, object],
        *,
        session_id: str,
        message_id: str,
        durable: bool,
    ) -> tuple[
        str | None,
        tuple[EvidenceRecord, ...],
        bool,
        dict[str, str | int | float | bool],
    ]:
        parts = body.get("parts")
        if not isinstance(parts, list):
            return None, (), False, {}

        text_parts: list[str] = []
        evidence: list[EvidenceRecord] = []
        protocol_valid = True
        source = "opencode.persisted_message" if durable else "opencode.message_response"

        for part in parts:
            if not isinstance(part, dict):
                protocol_valid = False
                continue
            part_type = part.get("type")
            if part_type == "text":
                text = part.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
                else:
                    protocol_valid = False
            elif part_type == "tool":
                observation = self._tool_observation(
                    part,
                    fallback_session_id=session_id,
                    fallback_message_id=message_id,
                    source=source,
                )
                if observation is None:
                    protocol_valid = False
                else:
                    evidence.append(observation.to_evidence())
            elif part_type == "patch":
                evidence.append(self._patch_evidence(part, source=source))

        metadata = self._provider_metadata(body)
        text = "\n".join(text_parts) if text_parts else None
        return text, tuple(evidence), protocol_valid, metadata

    def _tool_observation(
        self,
        part: dict[str, object],
        *,
        fallback_session_id: str,
        fallback_message_id: str,
        source: str,
    ) -> AgentActionObservation | None:
        call_id = part.get("callID")
        tool = part.get("tool")
        state = part.get("state")
        session_id = part.get("sessionID", fallback_session_id)
        message_id = part.get("messageID", fallback_message_id)
        required_strings = (call_id, tool, session_id, message_id)
        if not all(isinstance(value, str) and value for value in required_strings):
            return None
        if not isinstance(state, dict):
            return None

        status = state.get("status")
        tool_input = state.get("input", {})
        if not isinstance(status, str) or not isinstance(tool_input, dict):
            return None
        phase = {
            "pending": AgentActionPhase.REQUESTED,
            "running": AgentActionPhase.REQUESTED,
            "completed": AgentActionPhase.EXECUTED,
            "error": AgentActionPhase.ERROR,
        }.get(status)
        if phase is None:
            return None

        output = state.get("output")
        error = state.get("error")
        return AgentActionObservation(
            control_event_id=call_id,
            session_id=session_id,
            message_id=message_id,
            tool=tool,
            phase=phase,
            categories=classify_agent_action(
                tool,
                tool_input,
                workspace_root=self.config.workspace_root,
            ),
            input_hash=canonical_json_hash(tool_input),
            output_hash=canonical_json_hash(output) if output is not None else None,
            error_hash=canonical_json_hash(error) if error is not None else None,
            source=source,
        )

    @staticmethod
    def _patch_evidence(part: dict[str, object], *, source: str) -> EvidenceRecord:
        files = part.get("files")
        file_values = (
            [value for value in files if isinstance(value, str)]
            if isinstance(files, list)
            else []
        )
        return EvidenceRecord(
            kind=EvidenceKind.FILESYSTEM,
            source=source,
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=canonical_json_hash(file_values),
            data={
                "operation": "patch",
                "file_count": len(file_values),
                "path_hashes": [sha256(value.encode()).hexdigest() for value in file_values],
            },
            redacted=True,
        )

    @staticmethod
    def _provider_metadata(body: dict[str, object]) -> dict[str, str | int | float | bool]:
        metadata: dict[str, str | int | float | bool] = {}
        info = body.get("info")
        if not isinstance(info, dict):
            return metadata
        cost = info.get("cost")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            metadata["cost"] = cost
        tokens = info.get("tokens")
        if isinstance(tokens, dict):
            for key in ("input", "output", "reasoning"):
                value = tokens.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    metadata[f"tokens_{key}"] = value
        finish = info.get("finish")
        if isinstance(finish, str):
            metadata["finish"] = finish
        return metadata

    @staticmethod
    def _message_id(body: dict[str, object]) -> str | None:
        info = body.get("info")
        if not isinstance(info, dict):
            return None
        value = info.get("id")
        return value if isinstance(value, str) and value else None

    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + "/" + path.lstrip("/")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
