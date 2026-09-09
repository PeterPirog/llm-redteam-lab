"""Persistence row for campaign measurement provenance."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CampaignMeasurementProtocolRow(Base):
    """Immutable one-to-one measurement contract attached to a campaign."""

    __tablename__ = "campaign_measurement_protocols"

    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"),
        primary_key=True,
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    protocol: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    protocol_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    attack_policy_fingerprint: Mapped[str | None] = mapped_column(String(128))
    held_out_case_set_hash: Mapped[str | None] = mapped_column(String(128))
    corpus_snapshot_hash: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
