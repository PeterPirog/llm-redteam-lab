"""Persistence rows for Blue controls and experimentally attributed observations."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class BlueControlRow(Base):
    __tablename__ = "blue_controls"
    __table_args__ = (
        UniqueConstraint(
            "target_snapshot_id",
            "control_id",
            name="uq_blue_control_snapshot_id",
        ),
    )

    profile_control_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    layer: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    declared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    retired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ControlObservationRow(Base):
    __tablename__ = "blue_control_observations"
    __table_args__ = (
        UniqueConstraint("observation_id", name="uq_blue_control_observation_id"),
    )

    observation_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    profile_control_id: Mapped[str] = mapped_column(
        ForeignKey("blue_controls.profile_control_id"), nullable=False, index=True
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    attack_family: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    experiment_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
