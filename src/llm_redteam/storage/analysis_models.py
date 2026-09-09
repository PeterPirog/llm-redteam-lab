"""Persistence rows for derived security analysis artifacts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ReproductionRunRow(Base):
    __tablename__ = "reproduction_runs"
    __table_args__ = (
        UniqueConstraint(
            "original_execution_id",
            "analysis_version",
            name="uq_reproduction_execution_version",
        ),
    )

    reproduction_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    original_execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacks.attack_instance_id"), nullable=False, index=True
    )
    experiment_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    requested_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    conclusive_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    successful_reproductions: Mapped[int] = mapped_column(Integer, nullable=False)
    unresolved_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    rate_value: Mapped[float | None] = mapped_column(Float)
    rate_ci_low: Mapped[float | None] = mapped_column(Float)
    rate_ci_high: Mapped[float | None] = mapped_column(Float)
    confidence_level: Mapped[float] = mapped_column(Float, nullable=False)
    rate_method: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ReproductionAttemptRow(Base):
    __tablename__ = "reproduction_attempts"
    __table_args__ = (
        UniqueConstraint(
            "reproduction_id",
            "ordinal",
            name="uq_reproduction_attempt_ordinal",
        ),
    )

    reproduction_attempt_id: Mapped[str] = mapped_column(String(112), primary_key=True)
    reproduction_id: Mapped[str] = mapped_column(
        ForeignKey("reproduction_runs.reproduction_id"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)


class MinimizationRunRow(Base):
    __tablename__ = "minimization_runs"
    __table_args__ = (
        UniqueConstraint(
            "reference_execution_id",
            "analysis_version",
            name="uq_minimization_execution_version",
        ),
    )

    minimization_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    reference_execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacks.attack_instance_id"), nullable=False, index=True
    )
    experiment_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    original_component_count: Mapped[int] = mapped_column(Integer, nullable=False)
    minimized_component_count: Mapped[int] = mapped_column(Integer, nullable=False)
    removed_component_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    target_executions: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class MinimizedComponentRow(Base):
    __tablename__ = "minimized_components"
    __table_args__ = (
        UniqueConstraint(
            "minimization_id",
            "ordinal",
            name="uq_minimized_component_ordinal",
        ),
    )

    minimized_component_id: Mapped[str] = mapped_column(String(112), primary_key=True)
    minimization_id: Mapped[str] = mapped_column(
        ForeignKey("minimization_runs.minimization_id"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    component_id: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False)


class MinimizationAssessmentRow(Base):
    __tablename__ = "minimization_assessments"
    __table_args__ = (
        UniqueConstraint(
            "minimization_id",
            "ordinal",
            name="uq_minimization_assessment_ordinal",
        ),
    )

    minimization_assessment_id: Mapped[str] = mapped_column(String(112), primary_key=True)
    minimization_id: Mapped[str] = mapped_column(
        ForeignKey("minimization_runs.minimization_id"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    component_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    preserved: Mapped[bool | None] = mapped_column(Boolean)
    successful_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    conclusive_failures: Mapped[int] = mapped_column(Integer, nullable=False)
    unresolved_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    execution_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class CounterfactualRunRow(Base):
    __tablename__ = "counterfactual_runs"
    __table_args__ = (
        UniqueConstraint(
            "reference_execution_id",
            "analysis_version",
            name="uq_counterfactual_execution_version",
        ),
    )

    counterfactual_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    reference_execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacks.attack_instance_id"), nullable=False, index=True
    )
    experiment_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False)
    attack_id: Mapped[str] = mapped_column(String(160), nullable=False)
    evaluated_variants: Mapped[int] = mapped_column(Integer, nullable=False)
    target_executions: Mapped[int] = mapped_column(Integer, nullable=False)
    truncated_by_budget: Mapped[bool] = mapped_column(Boolean, nullable=False)
    empty_baseline_preserved: Mapped[bool | None] = mapped_column(Boolean)
    empty_baseline_execution_ids: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class CounterfactualComponentRow(Base):
    __tablename__ = "counterfactual_components"
    __table_args__ = (
        UniqueConstraint(
            "counterfactual_id",
            "component_id",
            name="uq_counterfactual_component",
        ),
    )

    counterfactual_component_id: Mapped[str] = mapped_column(String(112), primary_key=True)
    counterfactual_id: Mapped[str] = mapped_column(
        ForeignKey("counterfactual_runs.counterfactual_id"), nullable=False, index=True
    )
    component_id: Mapped[str] = mapped_column(String(160), nullable=False)
    necessary_under_test: Mapped[bool | None] = mapped_column(Boolean)
    sufficient_under_test: Mapped[bool | None] = mapped_column(Boolean)
    without_component_preserved: Mapped[bool | None] = mapped_column(Boolean)
    component_alone_preserved: Mapped[bool | None] = mapped_column(Boolean)
    without_execution_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    alone_execution_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class ForensicReportRow(Base):
    __tablename__ = "forensic_reports"
    __table_args__ = (
        UniqueConstraint(
            "execution_id",
            "analysis_version",
            name="uq_forensic_execution_version",
        ),
    )

    forensic_report_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    reproduction_status: Mapped[str] = mapped_column(String(48), nullable=False)
    attack_family: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    model_compromise: Mapped[bool] = mapped_column(Boolean, nullable=False)
    system_compromise: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_layer: Mapped[str | None] = mapped_column(String(255))
    proximate_cause: Mapped[str | None] = mapped_column(String(2048))
    enabling_conditions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    controls_effective: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    controls_bypassed: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    supporting_evidence_refs: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    necessary_component_ids: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    alternative_explanations: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[str] = mapped_column(String(4096), nullable=False)
    error_kind: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
