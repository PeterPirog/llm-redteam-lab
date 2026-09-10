"""Persistence rows for immutable Judge calibration evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class JudgeCalibrationRunRow(Base):
    __tablename__ = "judge_calibration_runs"

    calibration_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    calibration_set_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    judge_policy_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observation_result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    overall: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    by_stress_condition: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    by_attack_family: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    comparable_blue_estimate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class JudgeCalibrationObservationRow(Base):
    __tablename__ = "judge_calibration_observations"
    __table_args__ = (
        UniqueConstraint(
            "calibration_hash",
            "case_id",
            "stress_condition",
            name="uq_judge_calibration_case_stress",
        ),
    )

    observation_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    calibration_hash: Mapped[str] = mapped_column(
        ForeignKey("judge_calibration_runs.calibration_hash"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(String(160), nullable=False)
    reference_violated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    predicted_violated: Mapped[bool | None] = mapped_column(Boolean)
    attack_family: Mapped[str | None] = mapped_column(String(96))
    stress_condition: Mapped[str] = mapped_column(String(96), nullable=False)
