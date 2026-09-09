"""Immutable persistence API for campaign measurement provenance."""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field, model_validator
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ..domain import StrictModel
from ..evaluation_protocol import CampaignPurpose, MeasurementProtocol
from .measurement_models import CampaignMeasurementProtocolRow
from .models import CampaignRow

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class CampaignMeasurementSnapshot(StrictModel):
    """Auditable measurement conditions bound to one persisted campaign."""

    schema_version: int = Field(ge=1, default=1)
    campaign_id: str = Field(min_length=1)
    target_snapshot_id: str = Field(min_length=1)
    campaign_configuration_hash: str = Field(min_length=1)
    metric_definition_version: str = Field(min_length=1)
    protocol: MeasurementProtocol
    attack_policy_fingerprint: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
    )
    held_out_case_set_hash: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
    )
    corpus_snapshot_hash: str | None = Field(
        default=None,
        pattern=_HASH_PATTERN,
    )
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def evaluation_has_reproduction_identifiers(self) -> CampaignMeasurementSnapshot:
        if self.protocol.purpose != CampaignPurpose.EVALUATION:
            return self
        missing: list[str] = []
        if self.attack_policy_fingerprint is None:
            missing.append("attack_policy_fingerprint")
        if self.held_out_case_set_hash is None:
            missing.append("held_out_case_set_hash")
        if self.corpus_snapshot_hash is None:
            missing.append("corpus_snapshot_hash")
        if missing:
            raise ValueError(
                "EVALUATION requires " + ", ".join(missing)
            )
        return self


def build_campaign_measurement_snapshot(
    *,
    campaign_id: str,
    target_snapshot_id: str,
    campaign_configuration_hash: str,
    metric_definition_version: str,
    protocol: MeasurementProtocol,
    attack_policy_fingerprint: str | None = None,
    held_out_case_set_hash: str | None = None,
    corpus_snapshot_hash: str | None = None,
) -> CampaignMeasurementSnapshot:
    """Build a canonical hash-bound snapshot before any database write."""

    payload = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "target_snapshot_id": target_snapshot_id,
        "campaign_configuration_hash": campaign_configuration_hash,
        "metric_definition_version": metric_definition_version,
        "protocol": protocol.model_dump(mode="json"),
        "attack_policy_fingerprint": attack_policy_fingerprint,
        "held_out_case_set_hash": held_out_case_set_hash,
        "corpus_snapshot_hash": corpus_snapshot_hash,
    }
    content_hash = _canonical_hash(payload)
    return CampaignMeasurementSnapshot(
        **payload,
        content_hash=content_hash,
    )


def save_campaign_measurement_snapshot(
    engine: Engine,
    snapshot: CampaignMeasurementSnapshot,
) -> str:
    """Persist one immutable measurement snapshot, idempotent for exact repeats."""

    with Session(engine) as session, session.begin():
        campaign = session.get(CampaignRow, snapshot.campaign_id)
        if campaign is None:
            raise ValueError(f"unknown campaign: {snapshot.campaign_id}")
        _verify_campaign_binding(campaign, snapshot)
        existing = session.get(CampaignMeasurementProtocolRow, snapshot.campaign_id)
        if existing is not None:
            if existing.protocol_hash == snapshot.content_hash:
                return snapshot.content_hash
            raise ValueError(
                "campaign measurement protocol is immutable after first persistence"
            )
        session.add(
            CampaignMeasurementProtocolRow(
                campaign_id=snapshot.campaign_id,
                schema_version=snapshot.schema_version,
                purpose=snapshot.protocol.purpose.value,
                protocol=snapshot.protocol.model_dump(mode="json"),
                protocol_hash=snapshot.content_hash,
                attack_policy_fingerprint=snapshot.attack_policy_fingerprint,
                held_out_case_set_hash=snapshot.held_out_case_set_hash,
                corpus_snapshot_hash=snapshot.corpus_snapshot_hash,
            )
        )
    return snapshot.content_hash


def load_campaign_measurement_snapshot(
    engine: Engine,
    campaign_id: str,
) -> CampaignMeasurementSnapshot | None:
    """Load and integrity-check the persisted measurement snapshot."""

    with Session(engine) as session:
        row = session.get(CampaignMeasurementProtocolRow, campaign_id)
        if row is None:
            return None
        campaign = session.get(CampaignRow, campaign_id)
        if campaign is None:
            raise ValueError("measurement snapshot references missing campaign")
        protocol = MeasurementProtocol.model_validate(row.protocol)
        snapshot = build_campaign_measurement_snapshot(
            campaign_id=row.campaign_id,
            target_snapshot_id=campaign.target_snapshot_id,
            campaign_configuration_hash=campaign.configuration_hash,
            metric_definition_version=campaign.metric_definition_version,
            protocol=protocol,
            attack_policy_fingerprint=row.attack_policy_fingerprint,
            held_out_case_set_hash=row.held_out_case_set_hash,
            corpus_snapshot_hash=row.corpus_snapshot_hash,
        )
        if snapshot.schema_version != row.schema_version:
            raise ValueError("measurement snapshot schema version mismatch")
        if snapshot.content_hash != row.protocol_hash:
            raise ValueError("measurement snapshot content hash mismatch")
        if snapshot.protocol.purpose.value != row.purpose:
            raise ValueError("measurement snapshot purpose mismatch")
        return snapshot


def fingerprint_attack_policy(value: object) -> str:
    """Canonical SHA-256 for a serializable frozen Red policy/configuration."""

    return _canonical_hash(value)


def fingerprint_case_set(case_ids: tuple[str, ...]) -> str:
    """Order-independent held-out case-set fingerprint."""

    if not case_ids:
        raise ValueError("case set cannot be empty")
    if any(not case_id for case_id in case_ids):
        raise ValueError("case set contains an empty case id")
    return _canonical_hash(sorted(set(case_ids)))


def fingerprint_corpus_snapshot(value: object) -> str:
    """Canonical SHA-256 binding evaluation to exact corpus content/version."""

    return _canonical_hash(value)


def _verify_campaign_binding(
    campaign: CampaignRow,
    snapshot: CampaignMeasurementSnapshot,
) -> None:
    if campaign.target_snapshot_id != snapshot.target_snapshot_id:
        raise ValueError("measurement target_snapshot_id does not match campaign")
    if campaign.configuration_hash != snapshot.campaign_configuration_hash:
        raise ValueError("measurement configuration hash does not match campaign")
    if campaign.metric_definition_version != snapshot.metric_definition_version:
        raise ValueError("measurement metric definition version does not match campaign")


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
