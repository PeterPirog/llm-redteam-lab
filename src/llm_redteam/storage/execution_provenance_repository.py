"""Hash-bound persistence for campaign execution provenance."""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field, model_validator
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ..domain import StrictModel
from .execution_provenance_models import CampaignExecutionProvenanceRow
from .models import CampaignRow

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_KIND_PATTERN = r"^[a-z0-9][a-z0-9_.:-]{0,63}$"


class ExecutionProvenanceDescriptor(StrictModel):
    """Campaign-independent, hash-safe runtime admission descriptor."""

    schema_version: int = Field(ge=1, default=1)
    kind: str = Field(pattern=_KIND_PATTERN)
    payload: dict[str, object]
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def content_hash_matches(self) -> ExecutionProvenanceDescriptor:
        if _descriptor_hash(
            schema_version=self.schema_version,
            kind=self.kind,
            payload=self.payload,
        ) != self.content_hash:
            raise ValueError("execution provenance content_hash does not match descriptor")
        return self


class CampaignExecutionProvenanceSnapshot(StrictModel):
    """One immutable descriptor bound to one persisted campaign."""

    campaign_id: str = Field(min_length=1)
    descriptor: ExecutionProvenanceDescriptor


def build_execution_provenance_descriptor(
    *,
    kind: str,
    payload: dict[str, object],
) -> ExecutionProvenanceDescriptor:
    """Canonicalize one pre-inference execution condition descriptor."""

    content_hash = _descriptor_hash(schema_version=1, kind=kind, payload=payload)
    return ExecutionProvenanceDescriptor(
        schema_version=1,
        kind=kind,
        payload=payload,
        content_hash=content_hash,
    )


def save_campaign_execution_provenance(
    engine: Engine,
    *,
    campaign_id: str,
    descriptor: ExecutionProvenanceDescriptor,
) -> str:
    """Persist one provenance kind idempotently and reject later mutation."""

    expected_hash = _descriptor_hash(
        schema_version=descriptor.schema_version,
        kind=descriptor.kind,
        payload=descriptor.payload,
    )
    if expected_hash != descriptor.content_hash:
        raise ValueError("execution provenance content_hash does not match descriptor")

    with Session(engine) as session, session.begin():
        if session.get(CampaignRow, campaign_id) is None:
            raise ValueError(f"unknown campaign: {campaign_id}")
        key = (campaign_id, descriptor.kind)
        existing = session.get(CampaignExecutionProvenanceRow, key)
        if existing is not None:
            if (
                existing.schema_version == descriptor.schema_version
                and existing.provenance_hash == descriptor.content_hash
                and existing.provenance == descriptor.payload
            ):
                return descriptor.content_hash
            raise ValueError("campaign execution provenance is immutable after first persistence")
        session.add(
            CampaignExecutionProvenanceRow(
                campaign_id=campaign_id,
                provenance_kind=descriptor.kind,
                schema_version=descriptor.schema_version,
                provenance=descriptor.payload,
                provenance_hash=descriptor.content_hash,
            )
        )
    return descriptor.content_hash


def load_campaign_execution_provenance(
    engine: Engine,
    *,
    campaign_id: str,
    kind: str,
) -> CampaignExecutionProvenanceSnapshot | None:
    """Load and integrity-check one campaign provenance descriptor."""

    with Session(engine) as session:
        row = session.get(CampaignExecutionProvenanceRow, (campaign_id, kind))
        if row is None:
            return None
        if session.get(CampaignRow, campaign_id) is None:
            raise ValueError("execution provenance references missing campaign")
        descriptor = build_execution_provenance_descriptor(
            kind=row.provenance_kind,
            payload=row.provenance,
        )
        if descriptor.schema_version != row.schema_version:
            raise ValueError("execution provenance schema version mismatch")
        if descriptor.content_hash != row.provenance_hash:
            raise ValueError("execution provenance content hash mismatch")
        return CampaignExecutionProvenanceSnapshot(
            campaign_id=campaign_id,
            descriptor=descriptor,
        )


def _descriptor_hash(
    *,
    schema_version: int,
    kind: str,
    payload: dict[str, object],
) -> str:
    raw = json.dumps(
        {
            "schema_version": schema_version,
            "kind": kind,
            "payload": payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
