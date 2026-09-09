"""Persistence rows for auditable paired Red component ablations."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RedAblationExperimentRow(Base):
    """Immutable binding between an ablation contract and two evaluation campaigns."""

    __tablename__ = "red_ablation_experiments"

    experiment_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    contract: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    contract_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    baseline_campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"), nullable=False, index=True
    )
    treatment_campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"), nullable=False, index=True
    )
    baseline_measurement_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    treatment_measurement_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RedAblationObservationRow(Base):
    """Immutable resource/accounting metadata for one persisted ablation arm trial."""

    __tablename__ = "red_ablation_observations"
    __table_args__ = (
        UniqueConstraint(
            "experiment_id",
            "execution_id",
            name="uq_red_ablation_experiment_execution",
        ),
    )

    experiment_id: Mapped[str] = mapped_column(
        ForeignKey("red_ablation_experiments.experiment_id"), primary_key=True
    )
    arm: Mapped[str] = mapped_column(String(16), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    replicate: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"), nullable=False, index=True
    )
    pair_seed: Mapped[int | None] = mapped_column(Integer)
    policy_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    target_interactions: Mapped[int] = mapped_column(Integer, nullable=False)
    backtracks: Mapped[int] = mapped_column(Integer, nullable=False)
    branches_created: Mapped[int] = mapped_column(Integer, nullable=False)
    first_violation_ordinal: Mapped[int | None] = mapped_column(Integer)
    first_violation_depth: Mapped[int | None] = mapped_column(Integer)
    planner_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    mutator_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    planner_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    mutator_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    elapsed_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    observation_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
