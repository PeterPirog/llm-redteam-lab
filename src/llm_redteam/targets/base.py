"""Provider-independent target adapter contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import Field

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


class ConversationMessage(StrictModel):
    role: MessageRole
    content: str = Field(min_length=1)


class TargetRequest(StrictModel):
    attack_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    conversation: tuple[ConversationMessage, ...] = ()
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
    """

    @property
    def identity(self) -> TargetIdentity: ...

    async def execute(self, request: TargetRequest) -> TargetResponse: ...
