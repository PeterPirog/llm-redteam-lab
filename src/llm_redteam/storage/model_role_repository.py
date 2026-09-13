"""Immutable persistence API for campaign model-role artifact qualifications."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..agent_actions import canonical_json_hash
from ..domain import StrictModel
from ..model_role_artifact import QualifiedModelRoleIdentity, QualifiedModelRoleSet
from .model_role_models import CampaignModelRoleQualificationRow
from .models import CampaignRow

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class ModelRolePolicyScope(StrEnum):
    ATTACK = "attack"
    JUDGE = "judge"
    FORENSIC = "forensic"


class CampaignModelRoleProvenance(StrictModel):
    """Auditable exact model-role set bound to one campaign policy scope."""

    version: int = Field(ge=1, default=1)
    campaign_id: str = Field(min_length=1)
    policy_scope: ModelRolePolicyScope
    role_set: QualifiedModelRoleSet
    provenance_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def provenance_hash_matches_content(self) -> CampaignModelRoleProvenance:
        if _provenance_hash(
            campaign_id=self.campaign_id,
            policy_scope=self.policy_scope,
            role_set=self.role_set,
        ) != self.provenance_sha256:
            raise ValueError("campaign model-role provenance hash does not match content")
        return self


def build_campaign_model_role_provenance(
    *,
    campaign_id: str,
    policy_scope: ModelRolePolicyScope,
    role_set: QualifiedModelRoleSet,
) -> CampaignModelRoleProvenance:
    return CampaignModelRoleProvenance(
        campaign_id=campaign_id,
        policy_scope=policy_scope,
        role_set=role_set,
        provenance_sha256=_provenance_hash(
            campaign_id=campaign_id,
            policy_scope=policy_scope,
            role_set=role_set,
        ),
    )


def save_campaign_model_role_provenance(
    engine: Engine,
    provenance: CampaignModelRoleProvenance,
) -> str:
    """Persist one role set immutably; exact repeats are idempotent."""

    expected_hash = _provenance_hash(
        campaign_id=provenance.campaign_id,
        policy_scope=provenance.policy_scope,
        role_set=provenance.role_set,
    )
    if expected_hash != provenance.provenance_sha256:
        raise ValueError("campaign model-role provenance hash does not match content")

    with Session(engine) as session, session.begin():
        if session.get(CampaignRow, provenance.campaign_id) is None:
            raise ValueError(f"unknown campaign: {provenance.campaign_id}")

        existing = _rows_for_scope(
            session,
            campaign_id=provenance.campaign_id,
            policy_scope=provenance.policy_scope,
        )
        if existing:
            observed = _provenance_from_rows(existing)
            if observed.provenance_sha256 == provenance.provenance_sha256:
                return provenance.provenance_sha256
            raise ValueError(
                "campaign model-role provenance is immutable after first persistence"
            )

        for identity in provenance.role_set.ordered_identities:
            session.add(
                CampaignModelRoleQualificationRow(
                    campaign_id=provenance.campaign_id,
                    policy_scope=provenance.policy_scope.value,
                    route_id=identity.route_id,
                    role=identity.role.value,
                    attacker_variant_id=identity.attacker_variant_id,
                    provider_id=identity.provider_id,
                    model_id=identity.model_id,
                    role_configuration_fingerprint=identity.role_configuration_fingerprint,
                    artifact_identity_sha256=identity.artifact_identity_sha256,
                    artifact_digest=identity.artifact_digest,
                    local_artifact=identity.local_artifact,
                    qualification_sha256=identity.qualification_sha256,
                    role_set_sha256=provenance.role_set.set_sha256,
                    provenance_sha256=provenance.provenance_sha256,
                )
            )
    return provenance.provenance_sha256


def load_campaign_model_role_provenance(
    engine: Engine,
    *,
    campaign_id: str,
    policy_scope: ModelRolePolicyScope,
) -> CampaignModelRoleProvenance | None:
    """Load and integrity-check exact role/artifact provenance for one campaign scope."""

    with Session(engine) as session:
        rows = _rows_for_scope(
            session,
            campaign_id=campaign_id,
            policy_scope=policy_scope,
        )
        if not rows:
            return None
        return _provenance_from_rows(rows)


def _rows_for_scope(
    session: Session,
    *,
    campaign_id: str,
    policy_scope: ModelRolePolicyScope,
) -> tuple[CampaignModelRoleQualificationRow, ...]:
    rows = session.scalars(
        select(CampaignModelRoleQualificationRow)
        .where(
            CampaignModelRoleQualificationRow.campaign_id == campaign_id,
            CampaignModelRoleQualificationRow.policy_scope == policy_scope.value,
        )
        .order_by(CampaignModelRoleQualificationRow.route_id)
    ).all()
    return tuple(rows)


def _provenance_from_rows(
    rows: tuple[CampaignModelRoleQualificationRow, ...],
) -> CampaignModelRoleProvenance:
    if not rows:
        raise ValueError("cannot reconstruct campaign model-role provenance from no rows")

    campaign_ids = {row.campaign_id for row in rows}
    scopes = {row.policy_scope for row in rows}
    set_hashes = {row.role_set_sha256 for row in rows}
    provenance_hashes = {row.provenance_sha256 for row in rows}
    if len(campaign_ids) != 1 or len(scopes) != 1:
        raise ValueError("campaign model-role provenance rows disagree on campaign or scope")
    if len(set_hashes) != 1 or len(provenance_hashes) != 1:
        raise ValueError("campaign model-role provenance rows disagree on qualification hashes")

    identities = tuple(
        QualifiedModelRoleIdentity(
            role=row.role,
            attacker_variant_id=row.attacker_variant_id,
            provider_id=row.provider_id,
            model_id=row.model_id,
            role_configuration_fingerprint=row.role_configuration_fingerprint,
            artifact_identity_sha256=row.artifact_identity_sha256,
            artifact_digest=row.artifact_digest,
            local_artifact=row.local_artifact,
        )
        for row in rows
    )
    for row, identity in zip(rows, identities, strict=True):
        if identity.route_id != row.route_id:
            raise ValueError("persisted model-role route ID does not match reconstructed identity")
        if identity.qualification_sha256 != row.qualification_sha256:
            raise ValueError("persisted model-role qualification hash does not match identity")

    role_set = QualifiedModelRoleSet(identities=identities)
    expected_set_hash = next(iter(set_hashes))
    if role_set.set_sha256 != expected_set_hash:
        raise ValueError("persisted model-role set hash does not match reconstructed role set")

    campaign_id = next(iter(campaign_ids))
    policy_scope = ModelRolePolicyScope(next(iter(scopes)))
    provenance = build_campaign_model_role_provenance(
        campaign_id=campaign_id,
        policy_scope=policy_scope,
        role_set=role_set,
    )
    expected_provenance_hash = next(iter(provenance_hashes))
    if provenance.provenance_sha256 != expected_provenance_hash:
        raise ValueError("persisted campaign model-role provenance hash does not match content")
    return provenance


def _provenance_hash(
    *,
    campaign_id: str,
    policy_scope: ModelRolePolicyScope,
    role_set: QualifiedModelRoleSet,
) -> str:
    return canonical_json_hash(
        {
            "version": 1,
            "campaign_id": campaign_id,
            "policy_scope": policy_scope.value,
            "role_set": role_set.model_dump(mode="json"),
        }
    )
