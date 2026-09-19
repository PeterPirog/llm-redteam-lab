"""Per-run OpenCode health evidence and target admission gate.

A sandbox attestation proves the execution boundary, but it does not prove that the
expected OpenCode server actually started inside that boundary. This module keeps those
claims separate: health/version evidence is per-run and must bind the same runtime profile
and sandbox attestation before an attested OpenCode target is admitted for execution.
"""

from __future__ import annotations

from pydantic import Field

from .domain import StrictModel, TargetIdentity
from .opencode_runtime import AttestedOpenCodeTarget
from .targets.base import TargetRequest, TargetResponse

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OpenCodeHealthObservation(StrictModel):
    """Hash-only evidence from one trusted OpenCode health probe."""

    version: int = Field(ge=1, default=1)
    healthy: bool
    application_version: str = Field(min_length=1)
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_attestation_sha256: str = Field(pattern=_HASH_PATTERN)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    endpoint_sha256: str = Field(pattern=_HASH_PATTERN)
    response_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_command_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        from .agent_actions import canonical_json_hash

        return canonical_json_hash(self.model_dump(mode="json"))


class HealthGatedOpenCodeTarget:
    """Admit an attested OpenCode target only after matching runtime health evidence."""

    def __init__(
        self,
        target: AttestedOpenCodeTarget,
        health: OpenCodeHealthObservation,
    ) -> None:
        plan = target.launch_plan
        identity = target.identity
        if not health.healthy:
            raise ValueError("OpenCode runtime health observation is unhealthy")
        if health.runtime_profile_sha256 != plan.runtime_profile_sha256:
            raise ValueError("OpenCode health does not bind the target runtime profile")
        if health.sandbox_attestation_sha256 != plan.sandbox_attestation_sha256:
            raise ValueError("OpenCode health does not bind the target sandbox attestation")
        if identity.application_version is None:
            raise ValueError("health-gated OpenCode target requires application_version")
        if health.application_version != identity.application_version:
            raise ValueError("OpenCode health version does not match target application_version")
        self._target = target
        self.health = health

    @property
    def identity(self) -> TargetIdentity:
        base = self._target.identity
        return base.model_copy(
            update={
                "capabilities": base.capabilities | frozenset({"runtime_health_verified"})
            }
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await self._target.execute(request)
        metadata = dict(response.provider_metadata)
        metadata.update(
            {
                "runtime_health_verified": True,
                "runtime_health_proof_sha256": self.health.proof_sha256,
                "runtime_application_version": self.health.application_version,
            }
        )
        return response.model_copy(update={"provider_metadata": metadata})

    async def aclose(self) -> None:
        await self._target.aclose()
