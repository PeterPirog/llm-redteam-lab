"""Provider-independent target adapter contract."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import Field

from ..domain import EvidenceRecord, StrictModel, TargetIdentity


class TargetRequest(StrictModel):
    attack_id: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)


class TargetResponse(StrictModel):
    text: str | None = None
    evidence: tuple[EvidenceRecord, ...] = ()
    provider_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)
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
