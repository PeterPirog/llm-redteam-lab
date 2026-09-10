"""Campaign lifecycle status transitions for persisted experiment runs."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from .models import CampaignRow


class CampaignTerminalStatus(StrEnum):
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    ABORTED = "aborted"


def finish_campaign(
    engine: Engine,
    *,
    campaign_id: str,
    status: CampaignTerminalStatus,
) -> None:
    """Close one running campaign exactly once.

    Repeating the same terminal state is idempotent. A different terminal state
    is rejected so post-hoc callers cannot silently rewrite experiment history.
    """

    with Session(engine) as session, session.begin():
        row = session.get(CampaignRow, campaign_id)
        if row is None:
            raise ValueError(f"unknown campaign: {campaign_id}")
        if row.status != "running":
            if row.status == status.value and row.ended_at is not None:
                return
            raise ValueError(
                f"campaign {campaign_id} is already terminal with status={row.status}"
            )
        row.status = status.value
        row.ended_at = datetime.now(UTC)
