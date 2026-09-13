"""Artifact-qualified provenance for model-backed Red policy descriptors."""

from __future__ import annotations

from collections.abc import Mapping

from ..campaign_plan import RedPolicyKind
from ..domain import CampaignBudget, TargetClass, TargetMode
from ..evaluation_protocol import CampaignPurpose
from ..model_artifact import ModelArtifactIdentity
from ..model_role_artifact import (
    ModelRoleQualificationRequest,
    QualifiedModelRoleSet,
    bind_policy_descriptor_to_model_roles,
    qualify_model_roles,
)
from ..model_roles import ModelRole, ModelsConfig
from ..targets.base import SessionMode
from .runtime import build_model_backed_red_policy_descriptor


def qualify_red_model_roles(
    *,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    attacker_variant_id: str | None = None,
) -> QualifiedModelRoleSet:
    """Resolve and artifact-qualify the planner/mutator pair used by one Red route."""

    return qualify_model_roles(
        models=models,
        artifacts=artifacts,
        requests=(
            ModelRoleQualificationRequest(
                role=ModelRole.RED_PLANNER,
                attacker_variant_id=attacker_variant_id,
                required_capabilities=frozenset({"text", "reasoning"}),
            ),
            ModelRoleQualificationRequest(
                role=ModelRole.RED_MUTATOR,
                attacker_variant_id=attacker_variant_id,
                required_capabilities=frozenset({"text"}),
            ),
        ),
    )


def build_artifact_qualified_red_policy_descriptor(
    *,
    policy: RedPolicyKind,
    purpose: CampaignPurpose,
    target_class: TargetClass,
    target_mode: TargetMode,
    session_mode: SessionMode,
    campaign_budget: CampaignBudget,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    duplicate_similarity_threshold: float = 0.92,
    fixture_priming_enabled: bool = False,
    attacker_variant_id: str | None = None,
) -> dict[str, object]:
    """Build the existing Red descriptor and bind it to exact planner/mutator weights.

    No inference is performed. ``artifacts`` must already contain independently verified
    provider-neutral identities. Missing or mismatched artifacts fail before a policy
    fingerprint can be created.
    """

    base = build_model_backed_red_policy_descriptor(
        policy=policy,
        purpose=purpose,
        target_class=target_class,
        target_mode=target_mode,
        session_mode=session_mode,
        campaign_budget=campaign_budget,
        models=models,
        duplicate_similarity_threshold=duplicate_similarity_threshold,
        fixture_priming_enabled=fixture_priming_enabled,
        attacker_variant_id=attacker_variant_id,
    )
    qualified = qualify_red_model_roles(
        models=models,
        artifacts=artifacts,
        attacker_variant_id=attacker_variant_id,
    )
    prefix = f"{attacker_variant_id}:" if attacker_variant_id is not None else ""
    return bind_policy_descriptor_to_model_roles(
        policy_descriptor=base,
        qualified_roles=qualified,
        required_route_ids=(
            f"{prefix}{ModelRole.RED_PLANNER.value}",
            f"{prefix}{ModelRole.RED_MUTATOR.value}",
        ),
    )
