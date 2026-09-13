"""Fail-closed artifact qualification for campaign measurement-side model roles.

This module composes already verified model artifacts with exact Red and Judge policy
descriptors. It performs no model call, no network access and no target execution.

Qualification and campaign admission are intentionally separate. EVALUATION needs policy
fingerprints *before* ordinary preflight can become ready, so callers may first build an
artifact-qualified policy identity, place those fingerprints into ``CampaignPlan``, then
validate the same identity against the ready preflight immediately before execution.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import Field, model_validator

from ..agent_actions import canonical_json_hash
from ..campaign_plan import CampaignPlan, CampaignPreflight
from ..domain import StrictModel
from ..evaluation_protocol import CampaignPurpose
from ..judges.provenance import qualify_judge_model_roles
from ..model_artifact import ModelArtifactIdentity
from ..model_role_artifact import (
    QualifiedModelRoleSet,
    bind_policy_descriptor_to_model_roles,
)
from ..model_roles import ModelRole, ModelsConfig
from ..red.provenance import qualify_red_model_roles
from ..storage.measurement_repository import (
    fingerprint_attack_policy,
    fingerprint_judge_policy,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_RED_ROLES = frozenset({ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR})
_JUDGE_ROLES = frozenset({ModelRole.JUDGE_SEMANTIC, ModelRole.JUDGE_MULTIMODAL})
_SUPPORTED_ROLES = _RED_ROLES | _JUDGE_ROLES


class ArtifactQualifiedCampaignPolicies(StrictModel):
    """Exact attack/Judge policy identities after model-artifact qualification."""

    version: int = Field(ge=1, default=1)
    required_model_roles: tuple[ModelRole, ...]
    attack_policy_descriptor: dict[str, object]
    judge_policy_descriptor: dict[str, object]
    attack_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judge_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    red_model_roles: QualifiedModelRoleSet | None = None
    judge_model_roles: QualifiedModelRoleSet | None = None

    @model_validator(mode="after")
    def qualification_presence_matches_roles(self) -> ArtifactQualifiedCampaignPolicies:
        required = set(self.required_model_roles)
        if bool(required & _RED_ROLES) != (self.red_model_roles is not None):
            raise ValueError("Red model-role qualification does not match required roles")
        if bool(required & _JUDGE_ROLES) != (self.judge_model_roles is not None):
            raise ValueError("Judge model-role qualification does not match required roles")
        return self

    @property
    def red_model_role_set_sha256(self) -> str | None:
        return self.red_model_roles.set_sha256 if self.red_model_roles is not None else None

    @property
    def judge_model_role_set_sha256(self) -> str | None:
        return self.judge_model_roles.set_sha256 if self.judge_model_roles is not None else None

    @property
    def qualification_sha256(self) -> str:
        """Stable campaign-side measurement apparatus identity."""

        return canonical_json_hash(self.model_dump(mode="json"))


def qualify_campaign_policy_descriptors(
    *,
    required_model_roles: Iterable[ModelRole],
    models: ModelsConfig | None,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    attack_policy_descriptor: Mapping[str, object],
    judge_policy_descriptor: Mapping[str, object],
    model_backed_red: bool,
    attacker_variant_id: str | None = None,
) -> ArtifactQualifiedCampaignPolicies:
    """Build exact policy fingerprints before campaign admission.

    This stage is suitable for EVALUATION preparation: it does not require a ready
    ``CampaignPreflight`` or predeclared policy fingerprints. Its output is deterministic
    for the role configuration, exact verified artifacts and policy descriptors supplied.
    """

    required_input = tuple(required_model_roles)
    if len(required_input) != len(set(required_input)):
        raise ValueError("required campaign model roles must be unique")
    required = tuple(sorted(required_input, key=lambda role: role.value))
    unsupported = set(required).difference(_SUPPORTED_ROLES)
    if unsupported:
        raise ValueError(
            "campaign artifact qualification does not support roles: "
            + ", ".join(sorted(role.value for role in unsupported))
        )

    red_required = set(required) & _RED_ROLES
    if red_required and red_required != _RED_ROLES:
        raise ValueError("model-backed Red must require both planner and mutator roles")
    if model_backed_red != bool(red_required):
        raise ValueError("campaign Red policy and required Red model roles are inconsistent")
    if not red_required and attacker_variant_id is not None:
        raise ValueError("attacker_variant_id requires model-backed Red roles")

    judge_required = set(required) & _JUDGE_ROLES
    if required and models is None:
        raise ValueError("campaign model artifact qualification requires ModelsConfig")

    bound_attack = dict(attack_policy_descriptor)
    qualified_red: QualifiedModelRoleSet | None = None
    if red_required:
        assert models is not None
        qualified_red = qualify_red_model_roles(
            models=models,
            artifacts=artifacts,
            attacker_variant_id=attacker_variant_id,
        )
        prefix = f"{attacker_variant_id}:" if attacker_variant_id is not None else ""
        bound_attack = bind_policy_descriptor_to_model_roles(
            policy_descriptor=bound_attack,
            qualified_roles=qualified_red,
            required_route_ids=(
                f"{prefix}{ModelRole.RED_PLANNER.value}",
                f"{prefix}{ModelRole.RED_MUTATOR.value}",
            ),
        )

    bound_judge = dict(judge_policy_descriptor)
    qualified_judge: QualifiedModelRoleSet | None = None
    if judge_required:
        assert models is not None
        semantic = ModelRole.JUDGE_SEMANTIC in judge_required
        multimodal = ModelRole.JUDGE_MULTIMODAL in judge_required
        qualified_judge = qualify_judge_model_roles(
            models=models,
            artifacts=artifacts,
            semantic=semantic,
            multimodal=multimodal,
        )
        bound_judge = bind_policy_descriptor_to_model_roles(
            policy_descriptor=bound_judge,
            qualified_roles=qualified_judge,
            required_route_ids=tuple(role.value for role in judge_required),
        )

    return ArtifactQualifiedCampaignPolicies(
        required_model_roles=required,
        attack_policy_descriptor=bound_attack,
        judge_policy_descriptor=bound_judge,
        attack_policy_fingerprint=fingerprint_attack_policy(bound_attack),
        judge_policy_fingerprint=fingerprint_judge_policy(bound_judge),
        red_model_roles=qualified_red,
        judge_model_roles=qualified_judge,
    )


def validate_artifact_qualified_campaign_policies(
    *,
    plan: CampaignPlan,
    preflight: CampaignPreflight,
    qualified: ArtifactQualifiedCampaignPolicies,
) -> None:
    """Admit one previously qualified policy identity to a ready campaign plan."""

    if not preflight.ready:
        raise ValueError("cannot artifact-qualify a campaign whose preflight is not ready")
    if preflight.purpose != plan.purpose:
        raise ValueError("campaign preflight purpose does not match campaign plan")
    if preflight.target_class != plan.target_class or preflight.target_mode != plan.target_mode:
        raise ValueError("campaign preflight target identity does not match campaign plan")
    if preflight.red_policy != plan.red_policy:
        raise ValueError("campaign preflight Red policy does not match campaign plan")

    preflight_roles = tuple(
        sorted(
            (ModelRole(value) for value in preflight.required_model_roles),
            key=lambda role: role.value,
        )
    )
    if len(preflight_roles) != len(set(preflight_roles)):
        raise ValueError("campaign preflight required model roles must be unique")
    if preflight_roles != qualified.required_model_roles:
        raise ValueError("qualified model roles do not match campaign preflight")
    if plan.red_policy.model_backed != bool(set(preflight_roles) & _RED_ROLES):
        raise ValueError("campaign Red policy and required Red model roles are inconsistent")

    if plan.purpose == CampaignPurpose.EVALUATION:
        missing = [
            name
            for name, value in (
                ("attack_policy_fingerprint", plan.attack_policy_fingerprint),
                ("judge_policy_fingerprint", plan.judge_policy_fingerprint),
            )
            if value is None
        ]
        if missing:
            raise ValueError(
                "EVALUATION artifact qualification requires declared " + ", ".join(missing)
            )

    _require_declared_fingerprint_match(
        label="attack_policy_fingerprint",
        declared=plan.attack_policy_fingerprint,
        observed=qualified.attack_policy_fingerprint,
    )
    _require_declared_fingerprint_match(
        label="judge_policy_fingerprint",
        declared=plan.judge_policy_fingerprint,
        observed=qualified.judge_policy_fingerprint,
    )


def build_artifact_qualified_campaign_policies(
    *,
    plan: CampaignPlan,
    preflight: CampaignPreflight,
    models: ModelsConfig | None,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    attack_policy_descriptor: Mapping[str, object],
    judge_policy_descriptor: Mapping[str, object],
    attacker_variant_id: str | None = None,
) -> ArtifactQualifiedCampaignPolicies:
    """Convenience path for DISCOVERY or already-declared EVALUATION campaigns."""

    required = tuple(ModelRole(value) for value in preflight.required_model_roles)
    qualified = qualify_campaign_policy_descriptors(
        required_model_roles=required,
        models=models,
        artifacts=artifacts,
        attack_policy_descriptor=attack_policy_descriptor,
        judge_policy_descriptor=judge_policy_descriptor,
        model_backed_red=plan.red_policy.model_backed,
        attacker_variant_id=attacker_variant_id,
    )
    validate_artifact_qualified_campaign_policies(
        plan=plan,
        preflight=preflight,
        qualified=qualified,
    )
    return qualified


def _require_declared_fingerprint_match(
    *,
    label: str,
    declared: str | None,
    observed: str,
) -> None:
    if declared is not None and declared != observed:
        raise ValueError(f"campaign {label} does not match artifact-qualified runtime policy")
