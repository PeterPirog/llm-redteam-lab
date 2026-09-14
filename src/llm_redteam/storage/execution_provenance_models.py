"""Immutable campaign execution-provenance rows.

Measurement protocol describes what is being estimated; execution provenance records
which independently admitted runtime conditions were actually used. The payload is
expected to be hash-safe metadata only, never raw prompts, credentials or secrets.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CampaignExecutionProvenanceRow(Base):
    """One immutable provenance descriptor of a given kind for one campaign."""

    __tablename__ = "campaign_execution_provenance"

    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"),
        primary_key=True,
    )
    provenance_kind: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    provenance_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
