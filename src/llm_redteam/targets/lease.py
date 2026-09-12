"""Per-trial target lease contracts for state-isolated TARGET_MANAGED execution.

A target lease is issued by trusted harness code, never by attacker-controlled content.
The lease separates stable Blue target policy identity from per-run isolation evidence so
fresh runtime/workspace/session state can be used without fragmenting statistical target
identity across replicates.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Protocol, runtime_checkable

from pydantic import Field

from ..agent_actions import canonical_json_hash
from ..domain import EvidenceKind, EvidenceRecord, StrictModel, TargetIdentity
from .base import TargetAdapter

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class TargetLeaseAssurance(StrEnum):
    """What the lease receipt actually proves about isolation."""

    FACTORY_FRESH_INSTANCE = "factory_fresh_instance"
    ATTESTED_RUNTIME = "attested_runtime"


class TargetLeaseRequest(StrictModel):
    """Scheduler-owned facts used to request exactly one isolated Blue trial."""

    campaign_id: str = Field(min_length=1)
    attack_instance_id: str = Field(min_length=1)
    variant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    order_index: int = Field(ge=0)

    @property
    def request_fingerprint(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class TargetLeaseReceipt(StrictModel):
    """Hash-only per-run evidence; never part of stable Blue target identity."""

    provider_id: str = Field(min_length=1)
    assurance: TargetLeaseAssurance
    lease_id_sha256: str = Field(pattern=_HASH_PATTERN)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN)
    target_configuration_hash: str = Field(min_length=1)
    isolation_evidence_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)

    def evidence_record(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="target_lease",
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=self.isolation_evidence_sha256,
            data={
                "provider_id": self.provider_id,
                "assurance": self.assurance.value,
                "lease_id_sha256": self.lease_id_sha256,
                "request_fingerprint": self.request_fingerprint,
                "target_configuration_hash": self.target_configuration_hash,
                "isolation_evidence_sha256": self.isolation_evidence_sha256,
            },
            redacted=True,
        )


@dataclass(frozen=True, slots=True)
class TargetLease:
    """Runtime-only handle to one fresh target instance and its receipt."""

    lease_id: str
    target: TargetAdapter
    receipt: TargetLeaseReceipt


@runtime_checkable
class TargetLeaseProvider(Protocol):
    """Trusted provider of fresh target instances for bounded attack trials."""

    @property
    def target_identity(self) -> TargetIdentity: ...

    async def acquire(self, request: TargetLeaseRequest) -> TargetLease: ...

    async def release(self, lease: TargetLease) -> None: ...


TargetFactory = Callable[[TargetLeaseRequest], TargetAdapter | Awaitable[TargetAdapter]]
TargetReleaser = Callable[[TargetAdapter], None | Awaitable[None]]


class FactoryTargetLeaseProvider:
    """Deterministic test/development lease provider with no sandbox attestation claim.

    Every acquisition must return a previously unseen target object with the exact stable
    identity declared by the provider. This proves orchestration and state-reset semantics
    with mocks. It MUST NOT be presented as host/container isolation evidence.
    """

    def __init__(
        self,
        *,
        target_identity: TargetIdentity,
        factory: TargetFactory,
        releaser: TargetReleaser | None = None,
        provider_id: str = "factory-target-lease-v1",
    ) -> None:
        if not provider_id:
            raise ValueError("target lease provider_id cannot be empty")
        self._target_identity = target_identity
        self._factory = factory
        self._releaser = releaser
        self._provider_id = provider_id
        self._issued_attack_ids: set[str] = set()
        self._active: dict[str, TargetLease] = {}
        self._issued_targets: list[TargetAdapter] = []

    @property
    def target_identity(self) -> TargetIdentity:
        return self._target_identity

    async def acquire(self, request: TargetLeaseRequest) -> TargetLease:
        if request.attack_instance_id in self._issued_attack_ids:
            raise RuntimeError(
                "target lease request for attack_instance_id was already issued"
            )
        target = self._factory(request)
        if inspect.isawaitable(target):
            target = await target
        if target.identity != self._target_identity:
            await self._best_effort_release_target(target)
            raise RuntimeError("target lease factory changed stable Blue target identity")
        if any(target is previous for previous in self._issued_targets):
            raise RuntimeError("target lease factory reused a prior target instance")

        lease_id = f"lease-{request.request_fingerprint[:32]}"
        if lease_id in self._active:
            raise RuntimeError("target lease ID is already active")
        receipt = TargetLeaseReceipt(
            provider_id=self._provider_id,
            assurance=TargetLeaseAssurance.FACTORY_FRESH_INSTANCE,
            lease_id_sha256=sha256(lease_id.encode()).hexdigest(),
            request_fingerprint=request.request_fingerprint,
            target_configuration_hash=target.identity.configuration_hash,
        )
        lease = TargetLease(lease_id=lease_id, target=target, receipt=receipt)
        self._issued_attack_ids.add(request.attack_instance_id)
        self._issued_targets.append(target)
        self._active[lease_id] = lease
        return lease

    async def release(self, lease: TargetLease) -> None:
        active = self._active.get(lease.lease_id)
        if active is None:
            raise RuntimeError("target lease is not active or was already released")
        if active is not lease:
            raise RuntimeError("target lease ownership token does not match active lease")
        try:
            await self._release_target(lease.target)
        finally:
            self._active.pop(lease.lease_id, None)

    async def _release_target(self, target: TargetAdapter) -> None:
        if self._releaser is not None:
            result = self._releaser(target)
            if inspect.isawaitable(result):
                await result
            return
        close = getattr(target, "aclose", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result

    async def _best_effort_release_target(self, target: TargetAdapter) -> None:
        try:
            await self._release_target(target)
        except Exception:
            pass
