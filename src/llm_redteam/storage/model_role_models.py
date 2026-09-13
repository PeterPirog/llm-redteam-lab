"""Persistence rows for exact measurement-side model-role artifact provenance."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CampaignModelRoleQualificationRow(Base):
    """One immutable role/artifact identity participating in a campaign policy."""

    __tablename__ = "campaign_model_role_qualifications"

    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"),
        primary_key=True,
    )
    policy_scope: Mapped[str] = mapped_column(String(32), primary_key=True)
    route_id: Mapped[str] = mapped_column(String(192), primary_key=True)
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    attacker_variant_id: Mapped[str | None] = mapped_column(String(64))
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    model_id: Mapped[str] = mapped_column(String(256), nullable=False)
    role_configuration_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    local_artifact: Mapped[bool] = mapped_column(Boolean, nullable=False)
    qualification_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    role_set_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
    )
