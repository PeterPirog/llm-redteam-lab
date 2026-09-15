import asyncio

import pytest

from llm_redteam.target_trial_close import release_target_trial_lease
from llm_redteam.target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialIsolationRelease,
    TargetTrialLease,
)
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

_CANARY = "RT_ASYNC_RELEASE_CANARY"


def _lease() -> TargetTrialLease:
    target = EscalatingVaultTarget(canary=_CANARY)
    return TargetTrialLease(
        target=target,
        attestation=TargetTrialIsolationAttestation(
            lease_id_hash="1" * 64,
            provider_fingerprint="2" * 64,
            isolation_level=TargetIsolationLevel.APPLICATION_INSTANCE,
            target_configuration_hash=target.identity.configuration_hash,
            fresh_state_proof_hash="3" * 64,
        ),
    )


def _release(lease: TargetTrialLease) -> TargetTrialIsolationRelease:
    return TargetTrialIsolationRelease(
        lease_id_hash=lease.attestation.lease_id_hash,
        teardown_proof_hash="4" * 64,
        cleanup_complete=True,
    )


class SyncProvider:
    def __init__(self) -> None:
        self.calls = 0

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        self.calls += 1
        return _release(lease)


class AsyncProvider:
    def __init__(self) -> None:
        self.events: list[str] = []

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        raise AssertionError("sync release must not be used when release_async exists")

    async def release_async(
        self,
        lease: TargetTrialLease,
    ) -> TargetTrialIsolationRelease:
        self.events.append("entered")
        await asyncio.sleep(0)
        self.events.append("completed")
        return _release(lease)


@pytest.mark.asyncio
async def test_release_helper_preserves_sync_provider_contract() -> None:
    lease = _lease()
    provider = SyncProvider()

    result = await release_target_trial_lease(provider, lease)  # type: ignore[arg-type]

    assert provider.calls == 1
    assert result.cleanup_complete is True
    assert result.lease_id_hash == lease.attestation.lease_id_hash


@pytest.mark.asyncio
async def test_release_helper_awaits_provider_native_async_teardown() -> None:
    lease = _lease()
    provider = AsyncProvider()

    result = await release_target_trial_lease(provider, lease)  # type: ignore[arg-type]

    assert provider.events == ["entered", "completed"]
    assert result.cleanup_complete is True


@pytest.mark.asyncio
async def test_release_helper_rejects_non_awaitable_release_async() -> None:
    lease = _lease()

    class BrokenProvider(SyncProvider):
        def release_async(self, lease: TargetTrialLease):
            return _release(lease)

    with pytest.raises(RuntimeError, match="must return awaitable"):
        await release_target_trial_lease(BrokenProvider(), lease)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_release_helper_rejects_release_for_another_lease() -> None:
    lease = _lease()

    class WrongLeaseProvider(SyncProvider):
        def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
            return TargetTrialIsolationRelease(
                lease_id_hash="f" * 64,
                teardown_proof_hash="4" * 64,
                cleanup_complete=True,
            )

    with pytest.raises(RuntimeError, match="does not bind"):
        await release_target_trial_lease(WrongLeaseProvider(), lease)  # type: ignore[arg-type]
