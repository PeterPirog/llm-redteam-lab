"""Persistence rows for derived security analysis artifacts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


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
