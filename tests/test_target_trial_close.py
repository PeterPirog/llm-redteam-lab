import asyncio
from hashlib import sha256

import pytest

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.target_trial_close import close_target_trial
from llm_redteam.target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialLease,
)
from llm_redteam.targets.base import TargetRequest, TargetResponse


def _identity() -> TargetIdentity:
    return TargetIdentity(
        id="close-test",
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        model="synthetic/local",
        provider="synthetic",
        configuration_hash=sha256(b"close-test").hexdigest(),
    )


def _attestation() -> TargetTrialIsolationAttestation:
    identity = _identity()
    return TargetTrialIsolationAttestation(
        lease_id_hash=sha256(b"close-lease").hexdigest(),
        provider_fingerprint=sha256(b"provider").hexdigest(),
        isolation_level=TargetIsolationLevel.DISPOSABLE_SANDBOX,
        target_configuration_hash=identity.configuration_hash,
        fresh_state_proof_hash=sha256(b"fresh").hexdigest(),
        control_plane_independent=True,
    )


class AsyncClosableTarget:
    def __init__(self) -> None:
        self.closed = False

    @property
    def identity(self) -> TargetIdentity:
        return _identity()

    async def execute(self, request: TargetRequest) -> TargetResponse:
        return TargetResponse(text=request.prompt)

    async def aclose(self) -> None:
        await asyncio.sleep(0)
        self.closed = True


class NoCloseTarget:
    @property
    def identity(self) -> TargetIdentity:
        return _identity()

    async def execute(self, request: TargetRequest) -> TargetResponse:
        return TargetResponse(text=request.prompt)


class BrokenCloseTarget(AsyncClosableTarget):
    async def aclose(self) -> None:
        raise RuntimeError("synthetic close failure")


class InvalidCloseTarget(NoCloseTarget):
    aclose = "not-callable"


def _lease(target) -> TargetTrialLease:
    return TargetTrialLease(target=target, attestation=_attestation())


def test_async_target_close_is_awaited_inside_existing_event_loop() -> None:
    target = AsyncClosableTarget()

    async def run():
        observation = await close_target_trial(_lease(target))
        assert target.closed is True
        return observation

    observation = asyncio.run(run())

    assert observation.close_kind == "awaited_aclose"
    assert observation.close_completed is True
    assert observation.lease_id_hash == _attestation().lease_id_hash
    assert len(observation.proof_sha256) == 64


def test_target_without_close_hook_is_explicit_noop() -> None:
    observation = asyncio.run(close_target_trial(_lease(NoCloseTarget())))

    assert observation.close_kind == "no_target_close_hook"
    assert observation.close_completed is True


def test_close_failure_propagates_and_cannot_be_reported_complete() -> None:
    with pytest.raises(RuntimeError, match="synthetic close failure"):
        asyncio.run(close_target_trial(_lease(BrokenCloseTarget())))


def test_noncallable_close_hook_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="not callable"):
        asyncio.run(close_target_trial(_lease(InvalidCloseTarget())))
