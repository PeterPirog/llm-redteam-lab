"""Provider-independent target adapter contract."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Protocol, runtime_checkable

from pydantic import Field, model_validator

from ..domain import EvidenceRecord, StrictModel, TargetIdentity


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class SessionMode(StrEnum):
    """How conversational state is delivered to a Blue target."""

    REPLAY = "replay"
    TARGET_MANAGED = "target_managed"


class UntrustedContextChannel(StrEnum):
    """Origin of attacker-controlled data that is not a direct user instruction."""

    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"
    MCP_CONTEXT = "mcp_context"


class UntrustedContextItem(StrictModel):
    """Ephemeral environment context with an integrity-checked content hash."""

    channel: UntrustedContextChannel
    source_id: str = Field(min_length=1)
    content: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def content_hash_matches(self) -> UntrustedContextItem:
        if sha256(self.content.encode()).hexdigest() != self.content_sha256:
            raise ValueError("untrusted context content_sha256 does not match content")
        return self

    @classmethod
    def from_text(
        cls,
        *,
        channel: UntrustedContextChannel,
        source_id: str,
        content: str,
    ) -> UntrustedContextItem:
        return cls(
            channel=channel,
            source_id=source_id,
            content=content,
            content_sha256=sha256(content.encode()).hexdigest(),
        )


class ConversationMessage(StrictModel):
    role: MessageRole
    content: str = Field(min_length=1)
    artifact_refs: tuple[str, ...] = ()


class TargetRequest(StrictModel):
    attack_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    conversation: tuple[ConversationMessage, ...] = ()
    input_artifact_refs: tuple[str, ...] = ()
    untrusted_context: tuple[UntrustedContextItem, ...] = ()
    session_mode: SessionMode = SessionMode.REPLAY
    session_id: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class TargetResponse(StrictModel):
    text: str | None = None
    evidence: tuple[EvidenceRecord, ...] = ()
    provider_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)
    session_id: str | None = None
    error_kind: str | None = None


@runtime_checkable
class TargetAdapter(Protocol):
    """A normalized Blue target.

    Adapters may wrap direct model APIs, pipelines such as OpenWebUI, or full
    agents such as OpenCode. The adapter is responsible for collecting target
    evidence; it is not responsible for deciding whether an attack succeeded.
    Artifact references are opaque handles resolved only by adapters that
    explicitly support multimodal input. Adapters that intentionally consume
    `untrusted_context` must advertise that capability in `TargetIdentity`;
    fixture-aware execution rejects unsupported targets before a trial starts.
    """

    @property
    def identity(self) -> TargetIdentity: ...

    async def execute(self, request: TargetRequest) -> TargetResponse: ...
