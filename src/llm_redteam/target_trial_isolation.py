"""Per-trial Blue isolation contracts for comparable adversarial evaluation.

Multi-attacker experiments are only comparable when each attacker receives the same
predeclared opportunity from a clean Blue state. This module keeps that guarantee outside
Red and outside the target itself: a trusted lease provider creates an isolated target
scope, emits hash-only attestation, and tears it down after the bounded conversation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha256
from typing import Protocol, runtime_checkable

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import EvidenceKind, EvidenceRecord, StrictModel, TargetIdentity, TargetMode
from .targets.base import SessionMode, TargetAdapter, TargetRequest, TargetResponse

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class TargetIsolationLevel(IntEnum):
    """Strength of independently enforced fresh-state isolation for one trial."""

    SESSION_NAMESPACE = 1
    APPLICATION_INSTANCE = 2
    DISPOSABLE_SANDBOX = 3


class TargetTrialIsolationAttestation(StrictModel):
    """Persistence-safe proof that one clean Blue scope was created for a trial."""

    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    provider_fingerprint: str = Field(pattern=_HASH_PATTERN)
    isolation_level: TargetIsolationLevel
    target_configuration_hash: str = Field(min_length=1)
    fresh_state_proof_hash: str = Field(pattern=_HASH_PATTERN)
    control_plane_independent: bool = True

    def evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="target_trial_isolation",
            observed_at="runtime",
            content_hash=self.fresh_state_proof_hash,
            data={
                "lease_id_hash": self.lease_id_hash,
                "provider_fingerprint": self.provider_fingerprint,
                "isolation_level": self.isolation_level.name.lower(),
                "target_configuration_hash": self.target_configuration_hash,
                "fresh_state_proof_hash": self.fresh_state_proof_hash,
                "control_plane_independent": self.control_plane_independent,
            },
            redacted=True,
        )


class TargetTrialIsolationRelease(StrictModel):
    """Trusted teardown result for one target-isolation lease."""

    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    teardown_proof_hash: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool

    def evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="target_trial_isolation",
            observed_at="runtime",
            content_hash=self.teardown_proof_hash,
            data={
                "lease_id_hash": self.lease_id_hash,
                "teardown_proof_hash": self.teardown_proof_hash,
                "cleanup_complete": self.cleanup_complete,
            },
            redacted=True,
        )


@dataclass(frozen=True, slots=True)
class TargetTrialLease:
    """Ephemeral isolated target handle. Raw provider state is intentionally absent."""

    target: TargetAdapter
    attestation: TargetTrialIsolationAttestation


@runtime_checkable
class TargetTrialLeaseProvider(Protocol):
    """Trusted control-plane boundary that owns Blue state creation and teardown."""

    def acquire(
        self,
        *,
        expected_identity: TargetIdentity,
        trial_id: str,
    ) -> TargetTrialLease: ...

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease: ...


def minimum_isolation_level(
    *,
    target_mode: TargetMode,
    session_mode: SessionMode,
) -> TargetIsolationLevel | None:
    """Return the minimum clean-state boundary required for a comparable trial.

    REPLAY controls only transcript delivery. Pipeline caches, RAG/application memory,
    agent workspaces, tool state and other system state may persist independently of the
    transcript, so non-MODEL targets still require a fresh system boundary under REPLAY.
    """

    if target_mode == TargetMode.AGENT:
        return TargetIsolationLevel.DISPOSABLE_SANDBOX
    if target_mode == TargetMode.PIPELINE:
        return TargetIsolationLevel.APPLICATION_INSTANCE
    if session_mode == SessionMode.TARGET_MANAGED:
        return TargetIsolationLevel.SESSION_NAMESPACE
    return None


def validate_target_trial_lease(
    lease: TargetTrialLease,
    *,
    expected_identity: TargetIdentity,
    session_mode: SessionMode,
) -> None:
    """Fail closed unless the lease proves the required Blue isolation strength."""

    if lease.target.identity != expected_identity:
        raise ValueError("isolated target identity does not match predeclared Blue target")
    attestation = lease.attestation
    if attestation.target_configuration_hash != expected_identity.configuration_hash:
        raise ValueError("target-isolation attestation is bound to a different Blue configuration")
    if not attestation.control_plane_independent:
        raise ValueError("target isolation must be enforced independently from the Blue runtime")
    required = minimum_isolation_level(
        target_mode=expected_identity.target_mode,
        session_mode=session_mode,
    )
    if required is not None and attestation.isolation_level < required:
        raise ValueError(
            "target-isolation level is weaker than required for this target/session mode"
        )


class IsolationProvenanceTarget:
    """Attach clean-state attestation to the first target-visible response of a lease."""

    def __init__(self, target: TargetAdapter, attestation: TargetTrialIsolationAttestation) -> None:
        self._target = target
        self._attestation = attestation
        self._emitted = False

    @property
    def identity(self) -> TargetIdentity:
        return self._target.identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await self._target.execute(request)
        if self._emitted:
            return response
        self._emitted = True
        return response.model_copy(
            update={"evidence": (*response.evidence, self._attestation.evidence())}
        )


class InMemoryFreshTargetLeaseProvider:
    """Fresh-instance lease provider for deterministic/in-memory targets only.

    It proves that every trial receives a previously unseen Python target object whose
    complete mutable state is assumed to live in that object. It MUST NOT be used to
    claim disposable-sandbox isolation for adapters backed by external applications,
    filesystems, databases, containers, or remote services.
    """

    def __init__(
        self,
        *,
        target_factory: Callable[[], TargetAdapter],
        provider_id: str,
        isolation_level: TargetIsolationLevel = TargetIsolationLevel.APPLICATION_INSTANCE,
    ) -> None:
        if not provider_id:
            raise ValueError("target isolation provider_id must be non-empty")
        if isolation_level > TargetIsolationLevel.APPLICATION_INSTANCE:
            raise ValueError(
                "in-memory target leases cannot claim disposable-sandbox isolation"
            )
        self._target_factory = target_factory
        self._provider_id = provider_id
        self._isolation_level = isolation_level
        self._active: dict[str, TargetAdapter] = {}
        self._seen_targets: list[TargetAdapter] = []
        self._counter = 0
        self._provider_fingerprint = canonical_json_hash(
            {
                "kind": "in-memory-fresh-target-v1",
                "provider_id": provider_id,
                "isolation_level": isolation_level.name,
            }
        )

    def acquire(
        self,
        *,
        expected_identity: TargetIdentity,
        trial_id: str,
    ) -> TargetTrialLease:
        if not trial_id:
            raise ValueError("target trial_id must be non-empty")
        target = self._target_factory()
        if any(target is previous for previous in self._seen_targets):
            raise RuntimeError("target factory reused a prior mutable target instance")
        if target.identity != expected_identity:
            raise ValueError("target factory produced a different Blue target identity")
        self._counter += 1
        lease_material = canonical_json_hash(
            {
                "provider_fingerprint": self._provider_fingerprint,
                "trial_id": trial_id,
                "counter": self._counter,
                "target_configuration_hash": expected_identity.configuration_hash,
            }
        )
        lease_id_hash = sha256(f"lease:{lease_material}".encode()).hexdigest()
        fresh_state_proof_hash = canonical_json_hash(
            {
                "lease_id_hash": lease_id_hash,
                "fresh_instance_ordinal": self._counter,
                "target_configuration_hash": expected_identity.configuration_hash,
            }
        )
        self._seen_targets.append(target)
        self._active[lease_id_hash] = target
        return TargetTrialLease(
            target=target,
            attestation=TargetTrialIsolationAttestation(
                lease_id_hash=lease_id_hash,
                provider_fingerprint=self._provider_fingerprint,
                isolation_level=self._isolation_level,
                target_configuration_hash=expected_identity.configuration_hash,
                fresh_state_proof_hash=fresh_state_proof_hash,
                control_plane_independent=True,
            ),
        )

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        lease_id_hash = lease.attestation.lease_id_hash
        target = self._active.get(lease_id_hash)
        if target is None:
            raise RuntimeError("target isolation lease is not active")
        if target is not lease.target:
            raise RuntimeError("target isolation lease target identity changed")
        del self._active[lease_id_hash]
        return TargetTrialIsolationRelease(
            lease_id_hash=lease_id_hash,
            teardown_proof_hash=canonical_json_hash(
                {
                    "lease_id_hash": lease_id_hash,
                    "provider_fingerprint": self._provider_fingerprint,
                    "released": True,
                }
            ),
            cleanup_complete=True,
        )
