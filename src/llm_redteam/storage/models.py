"""SQLAlchemy persistence schema for reproducible red-team experiments."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TargetSnapshotRow(Base):
    __tablename__ = "target_snapshots"
    __table_args__ = (
        UniqueConstraint("target_id", "configuration_hash", name="uq_target_configuration"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    configuration_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    target_class: Mapped[str] = mapped_column(String(32), nullable=False)
    target_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(255), nullable=False)
    runtime: Mapped[str | None] = mapped_column(String(1024))
    model_digest: Mapped[str | None] = mapped_column(String(255))
    application: Mapped[str | None] = mapped_column(String(255))
    application_version: Mapped[str | None] = mapped_column(String(255))
    system_prompt_hash: Mapped[str | None] = mapped_column(String(128))
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class CampaignRow(Base):
    __tablename__ = "campaigns"

    campaign_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    configuration_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    metric_definition_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="v1"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttackRow(Base):
    __tablename__ = "attacks"
    __table_args__ = (
        Index("ix_attacks_campaign_family", "campaign_id", "attack_family"),
    )

    attack_instance_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    parent_attack_instance_id: Mapped[str | None] = mapped_column(
        ForeignKey("attacks.attack_instance_id")
    )
    hypothesis_id: Mapped[str | None] = mapped_column(String(255))
    attack_family: Mapped[str] = mapped_column(String(255), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    interaction_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_hash: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ExecutionRow(Base):
    __tablename__ = "executions"
    __table_args__ = (
        Index("ix_executions_target_outcome", "target_snapshot_id", "outcome"),
    )

    execution_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacks.attack_instance_id"), nullable=False, index=True
    )
    target_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("target_snapshots.snapshot_id"), nullable=False, index=True
    )
    outcome: Mapped[str] = mapped_column(String(48), nullable=False)
    objective_violated: Mapped[bool | None] = mapped_column(Boolean)
    model_compromise: Mapped[bool] = mapped_column(Boolean, nullable=False)
    system_compromise: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    error_kind: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ConversationRow(Base):
    __tablename__ = "conversations"

    conversation_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, unique=True, index=True
    )
    session_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    flow_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    turn_count: Mapped[int] = mapped_column(Integer, nullable=False)
    backtracks: Mapped[int] = mapped_column(Integer, nullable=False)
    branches: Mapped[int] = mapped_column(Integer, nullable=False)
    first_violation_turn_id: Mapped[str | None] = mapped_column(String(96))
    first_violation_ordinal: Mapped[int | None] = mapped_column(Integer)
    first_violation_depth: Mapped[int | None] = mapped_column(Integer)


class TurnRow(Base):
    __tablename__ = "turns"
    __table_args__ = (
        UniqueConstraint("conversation_id", "ordinal", name="uq_conversation_turn_ordinal"),
        Index("ix_turns_conversation_branch", "conversation_id", "branch_id"),
    )

    turn_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("conversations.conversation_id"), nullable=False, index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    branch_id: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_turn_id: Mapped[str | None] = mapped_column(ForeignKey("turns.turn_id"))
    attacker_message_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    target_response_hash: Mapped[str | None] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(48), nullable=False)
    objective_violated: Mapped[bool | None] = mapped_column(Boolean)
    model_compromise: Mapped[bool | None] = mapped_column(Boolean)
    system_compromise: Mapped[bool | None] = mapped_column(Boolean)
    confidence: Mapped[float | None] = mapped_column(Float)
    judge_type: Mapped[str | None] = mapped_column(String(64))
    error_kind: Mapped[str | None] = mapped_column(String(255))


class EvidenceRow(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_execution_kind", "execution_id", "kind"),
    )

    evidence_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("executions.execution_id"), nullable=False, index=True
    )
    turn_id: Mapped[str | None] = mapped_column(ForeignKey("turns.turn_id"), index=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_at: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(128))
    artifact_ref: Mapped[str | None] = mapped_column(String(2048))
    data: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
