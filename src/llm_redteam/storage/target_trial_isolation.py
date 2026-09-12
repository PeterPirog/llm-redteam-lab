"""Persistence for trusted per-trial Blue isolation attestations.

Isolation evidence is stored outside attacker-controlled runtime state and remains visible
even when target execution fails before an ExecutionRow can be produced.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from ..domain import StrictModel
from ..target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialIsolationRelease,
)
from .attacker_pool_execution import AttackerPoolTrialRow
from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TargetTrialIsolationRow(Base):
    __tablename__ = "target_trial_isolation"

    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacker_pool_trials.attack_instance_id"), primary_key=True
    )
    lease_id_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    provider_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    isolation_level: Mapped[int] = mapped_column(Integer, nullable=False)
    target_configuration_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    fresh_state_proof_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    control_plane_independent: Mapped[bool] = mapped_column(Boolean, nullable=False)
    teardown_proof_hash: Mapped[str | None] = mapped_column(String(64))
    cleanup_complete: Mapped[bool | None] = mapped_column(Boolean)
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TargetTrialIsolationRecord(StrictModel):
    attack_instance_id: str = Field(min_length=1)
    lease_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_level: TargetIsolationLevel
    target_configuration_hash: str = Field(min_length=1)
    fresh_state_proof_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    control_plane_independent: bool
    teardown_proof_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    cleanup_complete: bool | None = None


def ensure_target_trial_isolation_schema(engine: Engine) -> None:
    TargetTrialIsolationRow.__table__.create(engine, checkfirst=True)


def record_target_trial_isolation_acquired(
    engine: Engine,
    *,
    attack_instance_id: str,
    attestation: TargetTrialIsolationAttestation,
) -> None:
    """Persist trusted fresh-state proof before Blue target execution starts."""

    with Session(engine) as session, session.begin():
        assignment = session.get(AttackerPoolTrialRow, attack_instance_id)
        if assignment is None:
            raise ValueError(f"unknown attacker-pool assignment: {attack_instance_id}")
        if session.get(TargetTrialIsolationRow, attack_instance_id) is not None:
            raise ValueError("target-isolation attestation already exists for assignment")
        session.add(
            TargetTrialIsolationRow(
                attack_instance_id=attack_instance_id,
                lease_id_hash=attestation.lease_id_hash,
                provider_fingerprint=attestation.provider_fingerprint,
                isolation_level=int(attestation.isolation_level),
                target_configuration_hash=attestation.target_configuration_hash,
                fresh_state_proof_hash=attestation.fresh_state_proof_hash,
                control_plane_independent=attestation.control_plane_independent,
            )
        )


def record_target_trial_isolation_released(
    engine: Engine,
    *,
    attack_instance_id: str,
    release: TargetTrialIsolationRelease,
) -> None:
    """Persist teardown proof exactly once and bind it to the acquired lease."""

    with Session(engine) as session, session.begin():
        row = session.get(TargetTrialIsolationRow, attack_instance_id)
        if row is None:
            raise ValueError(f"target-isolation acquisition is missing: {attack_instance_id}")
        if row.lease_id_hash != release.lease_id_hash:
            raise ValueError("target-isolation release belongs to a different lease")
        if row.teardown_proof_hash is not None:
            raise ValueError("target-isolation release is already recorded")
        row.teardown_proof_hash = release.teardown_proof_hash
        row.cleanup_complete = release.cleanup_complete
        row.released_at = _utcnow()


def load_target_trial_isolation_records(
    engine: Engine,
    *,
    attack_instance_ids: tuple[str, ...] | None = None,
) -> tuple[TargetTrialIsolationRecord, ...]:
    with Session(engine) as session:
        statement = select(TargetTrialIsolationRow).order_by(
            TargetTrialIsolationRow.attack_instance_id
        )
        if attack_instance_ids is not None:
            statement = statement.where(
                TargetTrialIsolationRow.attack_instance_id.in_(attack_instance_ids)
            )
        rows = session.scalars(statement).all()
        return tuple(
            TargetTrialIsolationRecord(
                attack_instance_id=row.attack_instance_id,
                lease_id_hash=row.lease_id_hash,
                provider_fingerprint=row.provider_fingerprint,
                isolation_level=TargetIsolationLevel(row.isolation_level),
                target_configuration_hash=row.target_configuration_hash,
                fresh_state_proof_hash=row.fresh_state_proof_hash,
                control_plane_independent=row.control_plane_independent,
                teardown_proof_hash=row.teardown_proof_hash,
                cleanup_complete=row.cleanup_complete,
            )
            for row in rows
        )
