"""Stable measurement binding for target identities and responses.

Runtime evidence such as container IDs must not change the logical target. Stable
measurement inputs such as an exact model artifact or immutable runtime policy must.
This adapter adds one predeclared SHA-256 binding to an existing target identity while
leaving the wrapped execution behavior unchanged.
"""

from __future__ import annotations

from .agent_actions import canonical_json_hash
from .domain import TargetIdentity
from .targets.base import TargetAdapter, TargetRequest, TargetResponse

_HASH_CHARS = frozenset("0123456789abcdef")


def bind_target_measurement_identity(
    identity: TargetIdentity,
    *,
    measurement_binding_sha256: str,
) -> TargetIdentity:
    """Return the same target with stable measurement identity folded into its hash."""

    _require_sha256(measurement_binding_sha256)
    return identity.model_copy(
        update={
            "configuration_hash": canonical_json_hash(
                {
                    "base_target_configuration_hash": identity.configuration_hash,
                    "measurement_binding_sha256": measurement_binding_sha256,
                }
            ),
            "capabilities": identity.capabilities
            | frozenset({"measurement_identity_bound"}),
        }
    )


class MeasurementBoundTarget:
    """Target adapter whose stable identity names one exact measurement configuration."""

    def __init__(
        self,
        target: TargetAdapter,
        *,
        measurement_binding_sha256: str,
    ) -> None:
        _require_sha256(measurement_binding_sha256)
        self._target = target
        self.measurement_binding_sha256 = measurement_binding_sha256

    @property
    def identity(self) -> TargetIdentity:
        return bind_target_measurement_identity(
            self._target.identity,
            measurement_binding_sha256=self.measurement_binding_sha256,
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await self._target.execute(request)
        metadata = dict(response.provider_metadata)
        metadata["measurement_binding_sha256"] = self.measurement_binding_sha256
        return response.model_copy(update={"provider_metadata": metadata})

    async def aclose(self) -> None:
        close = getattr(self._target, "aclose", None)
        if close is not None:
            await close()


def _require_sha256(value: str) -> None:
    if len(value) != 64 or any(character not in _HASH_CHARS for character in value):
        raise ValueError("measurement binding must be a lowercase SHA-256")
