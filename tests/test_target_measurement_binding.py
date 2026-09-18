import asyncio

import pytest

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.target_measurement_binding import (
    MeasurementBoundTarget,
    bind_target_measurement_identity,
)
from llm_redteam.targets.base import TargetResponse


class FakeTarget:
    def __init__(self) -> None:
        self.closed = False
        self._identity = TargetIdentity(
            id="synthetic",
            target_class=TargetClass.CODING,
            target_mode=TargetMode.AGENT,
            model="ollama/model",
            provider="opencode",
            runtime="http://127.0.0.1:4096",
            application="OpenCode",
            application_version="1.2.3",
            configuration_hash="1" * 64,
            capabilities=frozenset({"coding"}),
        )

    @property
    def identity(self):
        return self._identity

    async def execute(self, request):
        del request
        return TargetResponse(text="ok", provider_metadata={"existing": True})

    async def aclose(self) -> None:
        self.closed = True


def test_measurement_binding_changes_target_snapshot_identity() -> None:
    target = FakeTarget()
    binding = "a" * 64

    bound = MeasurementBoundTarget(
        target,
        measurement_binding_sha256=binding,
    )

    assert bound.identity.id == target.identity.id
    assert bound.identity.configuration_hash != target.identity.configuration_hash
    assert "measurement_identity_bound" in bound.identity.capabilities

    expected = bind_target_measurement_identity(
        target.identity,
        measurement_binding_sha256=binding,
    )
    assert bound.identity == expected


def test_measurement_binding_is_exposed_as_response_provenance_and_closes_target() -> None:
    target = FakeTarget()
    binding = "b" * 64
    bound = MeasurementBoundTarget(
        target,
        measurement_binding_sha256=binding,
    )

    response = asyncio.run(bound.execute(object()))
    assert response.provider_metadata["existing"] is True
    assert response.provider_metadata["measurement_binding_sha256"] == binding

    asyncio.run(bound.aclose())
    assert target.closed is True


def test_measurement_binding_rejects_non_sha256_values() -> None:
    target = FakeTarget()

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        MeasurementBoundTarget(
            target,
            measurement_binding_sha256="not-a-hash",
        )
