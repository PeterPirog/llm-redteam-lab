"""Persistence row for immutable held-out evaluation set manifests."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EvaluationSetManifestRow(Base):
    """Hash-addressed split metadata; raw attack case content is never stored here."""

    __tablename__ = "evaluation_set_manifests"
    __table_args__ = (
        UniqueConstraint("manifest_id", name="uq_evaluation_set_manifest_id"),
    )

    manifest_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    manifest_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    exposure: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    split_strategy: Mapped[str] = mapped_column(String(255), nullable=False)
    corpus_snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    red_can_access_evaluation_content: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    sequestered_source_id: Mapped[str | None] = mapped_column(String(512))
    discovery_cases: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False)
    evaluation_cases: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False)
    discovery_case_set_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    evaluation_case_set_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
