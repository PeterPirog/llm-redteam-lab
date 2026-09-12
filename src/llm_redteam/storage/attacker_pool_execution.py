"""Persistence for predeclared multi-attacker trial allocation and resource facts.

The ordinary attack/execution tables remain the source of truth for security outcomes.
This extension records which predeclared attacker variant owned each bounded conversation
and the resource delta consumed by that trial. It deliberately does not invent finding
fingerprints before minimization/forensics has produced evidence-backed finding identity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from ..domain import StrictModel
from ..red.attacker_pool import AttackerPoolTrialAssignment
from .models import AttackRow, Base, CampaignRow, ExecutionRow


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AttackerPoolTrialStatus(StrEnum):
    ALLOCATED = "allocated"
    COMPLETED = "completed"


class AttackerPoolTrialRow(Base):
    __tablename__ = "attacker_pool_trials"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "variant_id",
            "case_id",
            "replicate",
            name="uq_attacker_pool_trial_opportunity",
        ),
        UniqueConstraint(
            "campaign_id",
            "order_index",
            name="uq_attacker_pool_trial_order",
        ),
    )

    attack_instance_id: Mapped[str] = mapped_column(
        ForeignKey("attacks.attack_instance_id"), primary_key=True
    )
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.campaign_id"), nullable=False, index=True
    )
    contract_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    variant_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    replicate: Mapped[int] = mapped_column(Integer, nullable=False)
    opportunity_index: Mapped[int] = mapped_column(Integer, nullable=False)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AttackerPoolTrialStatus.ALLOCATED.value
    )
    execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("executions.execution_id"), unique=True
    )
    target_interactions: Mapped[int | None] = mapped_column(Integer)
    planner_calls: Mapped[int | None] = mapped_column(Integer)
    mutator_calls: Mapped[int | None] = mapped_column(Integer)
    planner_output_tokens: Mapped[int | None] = mapped_column(Integer)
    mutator_output_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttackerPoolTrialRecord(StrictModel):
    attack_instance_id: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    contract_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    variant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    opportunity_index: int = Field(ge=0)
    order_index: int = Field(ge=0)
    status: AttackerPoolTrialStatus
    execution_id: str | None = None
    target_interactions: int | None = Field(default=None, ge=0)
    planner_calls: int | None = Field(default=None, ge=0)
    mutator_calls: int | None = Field(default=None, ge=0)
    planner_output_tokens: int | None = Field(default=None, ge=0)
    mutator_output_tokens: int | None = Field(default=None, ge=0)


def ensure_attacker_pool_execution_schema(engine: Engine) -> None:
    """Create only the optional attacker-pool extension table when missing."""

    AttackerPoolTrialRow.__table__.create(engine, checkfirst=True)


def validate_attacker_pool_campaign_binding(
    engine: Engine,
    *,
    campaign_id: str,
    target_snapshot_id: str,
) -> None:
    """Fail closed unless the pool is bound to one running campaign/Blue snapshot."""

    with Session(engine) as session:
        campaign = session.get(CampaignRow, campaign_id)
        if campaign is None:
            raise ValueError(f"unknown attacker-pool campaign: {campaign_id}")
        if campaign.target_snapshot_id != target_snapshot_id:
            raise ValueError("attacker-pool target snapshot does not match campaign")
        if campaign.status != "running":
            raise ValueError(
                f"attacker-pool campaign must be running, got status={campaign.status}"
            )


def record_attacker_pool_assignment(
    engine: Engine,
    *,
    campaign_id: str,
    contract_fingerprint: str,
    attack_instance_id: str,
    assignment: AttackerPoolTrialAssignment,
) -> None:
    """Persist allocation before target execution so interrupted trials remain visible."""

    with Session(engine) as session, session.begin():
        campaign = session.get(CampaignRow, campaign_id)
        if campaign is None:
            raise ValueError(f"unknown campaign: {campaign_id}")
        if campaign.status != "running":
            raise ValueError("attacker-pool assignment requires a running campaign")
        attack = session.get(AttackRow, attack_instance_id)
        if attack is None:
            raise ValueError(f"unknown attack instance: {attack_instance_id}")
        if attack.campaign_id != campaign_id:
            raise ValueError("attacker-pool attack belongs to a different campaign")
        if attack.case_id != assignment.case_id:
            raise ValueError("attacker-pool assignment case does not match attack case")
        if session.get(AttackerPoolTrialRow, attack_instance_id) is not None:
            raise ValueError(
                f"attacker-pool assignment already exists: {attack_instance_id}"
            )
        session.add(
            AttackerPoolTrialRow(
                attack_instance_id=attack_instance_id,
                campaign_id=campaign_id,
                contract_fingerprint=contract_fingerprint,
                variant_id=assignment.variant_id,
                case_id=assignment.case_id,
                replicate=assignment.replicate,
                opportunity_index=assignment.opportunity_index,
                order_index=assignment.order_index,
                status=AttackerPoolTrialStatus.ALLOCATED.value,
            )
        )


def complete_attacker_pool_assignment(
    engine: Engine,
    *,
    attack_instance_id: str,
    execution_id: str,
    target_interactions: int,
    planner_calls: int,
    mutator_calls: int,
    planner_output_tokens: int,
    mutator_output_tokens: int,
) -> None:
    """Attach persisted execution and per-trial resource deltas exactly once."""

    counts = {
        "target_interactions": target_interactions,
        "planner_calls": planner_calls,
        "mutator_calls": mutator_calls,
        "planner_output_tokens": planner_output_tokens,
        "mutator_output_tokens": mutator_output_tokens,
    }
    if any(value < 0 for value in counts.values()):
        raise ValueError("attacker-pool resource deltas cannot be negative")

    with Session(engine) as session, session.begin():
        row = session.get(AttackerPoolTrialRow, attack_instance_id)
        if row is None:
            raise ValueError(f"unknown attacker-pool assignment: {attack_instance_id}")
        if row.status != AttackerPoolTrialStatus.ALLOCATED.value:
            raise ValueError("attacker-pool assignment is already completed")
        execution = session.get(ExecutionRow, execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        if execution.attack_instance_id != attack_instance_id:
            raise ValueError("attacker-pool execution does not belong to assignment")

        row.execution_id = execution_id
        row.target_interactions = target_interactions
        row.planner_calls = planner_calls
        row.mutator_calls = mutator_calls
        row.planner_output_tokens = planner_output_tokens
        row.mutator_output_tokens = mutator_output_tokens
        row.status = AttackerPoolTrialStatus.COMPLETED.value
        row.completed_at = _utcnow()


def load_attacker_pool_trial_records(
    engine: Engine,
    *,
    campaign_id: str,
) -> tuple[AttackerPoolTrialRecord, ...]:
    with Session(engine) as session:
        rows = session.scalars(
            select(AttackerPoolTrialRow)
            .where(AttackerPoolTrialRow.campaign_id == campaign_id)
            .order_by(AttackerPoolTrialRow.order_index)
        ).all()
        return tuple(
            AttackerPoolTrialRecord(
                attack_instance_id=row.attack_instance_id,
                campaign_id=row.campaign_id,
                contract_fingerprint=row.contract_fingerprint,
                variant_id=row.variant_id,
                case_id=row.case_id,
                replicate=row.replicate,
                opportunity_index=row.opportunity_index,
                order_index=row.order_index,
                status=AttackerPoolTrialStatus(row.status),
                execution_id=row.execution_id,
                target_interactions=row.target_interactions,
                planner_calls=row.planner_calls,
                mutator_calls=row.mutator_calls,
                planner_output_tokens=row.planner_output_tokens,
                mutator_output_tokens=row.mutator_output_tokens,
            )
            for row in rows
        )
