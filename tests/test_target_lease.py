import asyncio
from hashlib import sha256

import pytest

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.targets.lease import (
    FactoryTargetLeaseProvider,
    TargetLeaseAssurance,
    TargetLeaseRequest,
)
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

CANARY = "RT_CANARY_TARGET_LEASE_731"


def _request(attack_id: str = "attack-a") -> TargetLeaseRequest:
    return TargetLeaseRequest(
        campaign_id="campaign-lease-test",
        attack_instance_id=attack_id,
        variant_id="attacker-a",
        case_id="case-a",
        replicate=0,
        order_index=0,
    )


def test_factory_provider_issues_fresh_targets_with_stable_identity() -> None:
    prototype = EscalatingVaultTarget(canary=CANARY)
    created: list[EscalatingVaultTarget] = []
    released: list[EscalatingVaultTarget] = []

    def factory(_: TargetLeaseRequest) -> EscalatingVaultTarget:
        target = EscalatingVaultTarget(canary=CANARY)
        created.append(target)
        return target

    def releaser(target: object) -> None:
        assert isinstance(target, EscalatingVaultTarget)
        released.append(target)

    provider = FactoryTargetLeaseProvider(
        target_identity=prototype.identity,
        factory=factory,
        releaser=releaser,
    )

    async def run() -> tuple[object, object]:
        first = await provider.acquire(_request("attack-a"))
        await provider.release(first)
        second = await provider.acquire(_request("attack-b"))
        await provider.release(second)
        return first, second

    first, second = asyncio.run(run())

    assert first.target is not second.target
    assert first.target.identity == prototype.identity
    assert second.target.identity == prototype.identity
    assert first.receipt.assurance == TargetLeaseAssurance.FACTORY_FRESH_INSTANCE
    assert first.receipt.isolation_evidence_sha256 is None
    assert first.receipt.lease_id_sha256 != second.receipt.lease_id_sha256
    assert released == created


def test_factory_provider_refuses_reused_target_instance() -> None:
    target = EscalatingVaultTarget(canary=CANARY)
    provider = FactoryTargetLeaseProvider(
        target_identity=target.identity,
        factory=lambda _: target,
    )

    async def run() -> None:
        first = await provider.acquire(_request("attack-a"))
        await provider.release(first)
        with pytest.raises(RuntimeError, match="reused a prior target instance"):
            await provider.acquire(_request("attack-b"))

    asyncio.run(run())


def test_factory_provider_refuses_duplicate_attack_lease() -> None:
    prototype = EscalatingVaultTarget(canary=CANARY)
    provider = FactoryTargetLeaseProvider(
        target_identity=prototype.identity,
        factory=lambda _: EscalatingVaultTarget(canary=CANARY),
    )

    async def run() -> None:
        lease = await provider.acquire(_request("attack-a"))
        await provider.release(lease)
        with pytest.raises(RuntimeError, match="already issued"):
            await provider.acquire(_request("attack-a"))

    asyncio.run(run())


def test_factory_provider_rejects_target_policy_identity_drift() -> None:
    prototype = EscalatingVaultTarget(canary=CANARY)
    different = EscalatingVaultTarget(canary="RT_CANARY_DIFFERENT_991")
    provider = FactoryTargetLeaseProvider(
        target_identity=prototype.identity,
        factory=lambda _: different,
    )

    with pytest.raises(RuntimeError, match="stable Blue target identity"):
        asyncio.run(provider.acquire(_request()))


def test_lease_receipt_is_hash_only_persistable_metadata() -> None:
    prototype = EscalatingVaultTarget(canary=CANARY)
    provider = FactoryTargetLeaseProvider(
        target_identity=prototype.identity,
        factory=lambda _: EscalatingVaultTarget(canary=CANARY),
    )

    async def run():
        lease = await provider.acquire(_request())
        evidence = lease.receipt.evidence_record()
        await provider.release(lease)
        return lease, evidence

    lease, evidence = asyncio.run(run())

    assert evidence.source == "target_lease"
    assert evidence.redacted is True
    assert evidence.data["assurance"] == "factory_fresh_instance"
    assert evidence.data["lease_id_sha256"] == sha256(lease.lease_id.encode()).hexdigest()
    assert evidence.data["target_configuration_hash"] == prototype.identity.configuration_hash
    assert CANARY not in str(evidence.model_dump(mode="json"))


def test_factory_provider_identity_is_exact_not_only_configuration_hash() -> None:
    prototype = EscalatingVaultTarget(canary=CANARY)
    same_config_but_other_target = TargetIdentity(
        id="different-id",
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        model=prototype.identity.model,
        provider=prototype.identity.provider,
        runtime=prototype.identity.runtime,
        configuration_hash=prototype.identity.configuration_hash,
        capabilities=prototype.identity.capabilities,
    )

    class IdentityOnlyTarget:
        @property
        def identity(self) -> TargetIdentity:
            return same_config_but_other_target

        async def execute(self, request):  # pragma: no cover - acquisition must fail first
            raise AssertionError(request)

    provider = FactoryTargetLeaseProvider(
        target_identity=prototype.identity,
        factory=lambda _: IdentityOnlyTarget(),
    )
    with pytest.raises(RuntimeError, match="stable Blue target identity"):
        asyncio.run(provider.acquire(_request()))
