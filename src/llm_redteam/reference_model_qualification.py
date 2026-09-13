"""Exact model-artifact identity for paired Reference Evaluation Red arms.

Reference Evaluation v1 compares two Red search policies under a paired/counterbalanced
experimental design.  The changed component is the Red search policy, not the underlying
attacker model.  Both arms therefore must be bound to the same exact planner/mutator
artifacts and the same Judge policy before their attack-policy fingerprints are admitted
into the paired experiment contract.

This module performs no inference and no provider/network operation.  It consumes already
verified ``ModelArtifactIdentity`` objects.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import model_validator

from .agent_actions import canonical_json_hash
from .campaign_plan import RedPolicyKind
from .campaigns.model_qualification import (
    ArtifactQualifiedCampaignPolicies,
    qualify_campaign_policy_descriptors,
    validate_qualified_runtime_policy_descriptors,
)
from .domain import CampaignBudget, StrictModel
from .evaluation_protocol import CampaignPurpose
from .model_artifact import ModelArtifactIdentity
from .model_roles import ModelRole, ModelsConfig
from .red.ablation import AblationArm
from .red.runtime import build_model_backed_red_policy_descriptor
from .reference_evaluation import ReferenceEvaluationSpec, ReferenceEvaluationStage
from .runtime_config import BudgetConfigDocument
from .storage.measurement_repository import fingerprint_budget

_REQUIRED_RED_ROLES = (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR)


class ArtifactQualifiedReferenceArm(StrictModel):
    """One reference arm bound to exact Red artifacts and frozen policy identity."""

    arm: AblationArm
    policy: RedPolicyKind
    qualified_policies: ArtifactQualifiedCampaignPolicies

    @model_validator(mode="after")
    def arm_has_exact_red_only_model_roles(self) -> ArtifactQualifiedReferenceArm:
        if not self.policy.model_backed:
            raise ValueError("reference arm requires a model-backed Red policy")
        if self.qualified_policies.required_model_roles != tuple(
            sorted(_REQUIRED_RED_ROLES, key=lambda role: role.value)
        ):
            raise ValueError("reference arm must qualify exactly Red planner and mutator roles")
        if self.qualified_policies.red_model_roles is None:
            raise ValueError("reference arm is missing Red model-role qualification")
        if self.qualified_policies.judge_model_roles is not None:
            raise ValueError("Reference Evaluation v1 deterministic Judge has no model artifact")
        return self

    @property
    def attack_policy_fingerprint(self) -> str:
        return self.qualified_policies.attack_policy_fingerprint

    @property
    def judge_policy_fingerprint(self) -> str:
        return self.qualified_policies.judge_policy_fingerprint

    @property
    def red_model_role_set_sha256(self) -> str:
        value = self.qualified_policies.red_model_role_set_sha256
        if value is None:
            raise RuntimeError("reference arm lost Red model-role identity")
        return value


class ArtifactQualifiedReferencePolicies(StrictModel):
    """Paired reference identity with model artifacts held constant across arms."""

    version: int = 1
    stage: ReferenceEvaluationStage
    budget_profile: str
    budget_fingerprint: str
    baseline: ArtifactQualifiedReferenceArm
    treatment: ArtifactQualifiedReferenceArm

    @model_validator(mode="after")
    def paired_identity_is_not_confounded_by_model_artifacts(
        self,
    ) -> ArtifactQualifiedReferencePolicies:
        if self.baseline.arm != AblationArm.BASELINE:
            raise ValueError("baseline reference arm has incorrect arm identity")
        if self.treatment.arm != AblationArm.TREATMENT:
            raise ValueError("treatment reference arm has incorrect arm identity")
        if self.baseline.policy == self.treatment.policy:
            raise ValueError("reference arms must use different Red search policies")
        if self.baseline.red_model_role_set_sha256 != self.treatment.red_model_role_set_sha256:
            raise ValueError(
                "paired reference arms must use the same exact Red model artifacts"
            )
        if self.baseline.judge_policy_fingerprint != self.treatment.judge_policy_fingerprint:
            raise ValueError("paired reference arms must use the same Judge policy")
        if self.baseline.attack_policy_fingerprint == self.treatment.attack_policy_fingerprint:
            raise ValueError("different reference Red policies must have distinct fingerprints")
        return self

    @property
    def red_model_role_set_sha256(self) -> str:
        return self.baseline.red_model_role_set_sha256

    @property
    def judge_policy_fingerprint(self) -> str:
        return self.baseline.judge_policy_fingerprint

    @property
    def qualification_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def paired_contract_inputs(self) -> dict[str, str]:
        """Return exact fingerprints consumed by the paired ablation contract."""

        return {
            "baseline_policy_fingerprint": self.baseline.attack_policy_fingerprint,
            "treatment_policy_fingerprint": self.treatment.attack_policy_fingerprint,
            "judge_fingerprint": self.judge_policy_fingerprint,
            "budget_fingerprint": self.budget_fingerprint,
            "red_model_role_set_sha256": self.red_model_role_set_sha256,
            "reference_qualification_sha256": self.qualification_sha256,
        }


def qualify_reference_model_policies(
    *,
    stage: ReferenceEvaluationStage,
    spec: ReferenceEvaluationSpec,
    budgets: BudgetConfigDocument,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    judge_policy_descriptor: Mapping[str, object],
) -> ArtifactQualifiedReferencePolicies:
    """Prepare both paired Red arms with exact artifacts and one deterministic Judge.

    Reference Evaluation v1 intentionally requires a deterministic canary Judge.  A
    model-backed Judge would add a second model-artifact treatment dimension and must be
    introduced by a future reference protocol version rather than silently here.
    """

    if not spec.require_deterministic_canary_judge:
        raise ValueError(
            "artifact-qualified Reference Evaluation v1 requires deterministic canary Judge"
        )
    if judge_policy_descriptor.get("kind") != "deterministic":
        raise ValueError("Reference Evaluation v1 Judge descriptor must be deterministic")
    if "model_role_artifacts" in judge_policy_descriptor:
        raise ValueError("deterministic Reference Evaluation Judge cannot bind model artifacts")

    profile_name = (
        spec.smoke_budget_profile
        if stage == ReferenceEvaluationStage.INSTRUMENTATION_SMOKE
        else spec.qualification_budget_profile
    )
    resolved_profile, effective_budget = budgets.profile(profile_name)
    budget_fingerprint = fingerprint_budget(effective_budget.model_dump(mode="json"))

    baseline = _qualify_arm(
        arm=AblationArm.BASELINE,
        policy=spec.baseline_policy,
        spec=spec,
        effective_budget=effective_budget,
        models=models,
        artifacts=artifacts,
        judge_policy_descriptor=judge_policy_descriptor,
    )
    treatment = _qualify_arm(
        arm=AblationArm.TREATMENT,
        policy=spec.treatment_policy,
        spec=spec,
        effective_budget=effective_budget,
        models=models,
        artifacts=artifacts,
        judge_policy_descriptor=judge_policy_descriptor,
    )

    return ArtifactQualifiedReferencePolicies(
        stage=stage,
        budget_profile=resolved_profile,
        budget_fingerprint=budget_fingerprint,
        baseline=baseline,
        treatment=treatment,
    )


def validate_reference_runtime_policy_descriptors(
    *,
    qualified: ArtifactQualifiedReferencePolicies,
    baseline_runtime_descriptor: Mapping[str, object],
    treatment_runtime_descriptor: Mapping[str, object],
    judge_policy_descriptor: Mapping[str, object],
) -> None:
    """Reject post-preparation drift in either Red arm or the shared Judge policy."""

    validate_qualified_runtime_policy_descriptors(
        qualified=qualified.baseline.qualified_policies,
        attack_policy_descriptor=baseline_runtime_descriptor,
        judge_policy_descriptor=judge_policy_descriptor,
    )
    validate_qualified_runtime_policy_descriptors(
        qualified=qualified.treatment.qualified_policies,
        attack_policy_descriptor=treatment_runtime_descriptor,
        judge_policy_descriptor=judge_policy_descriptor,
    )


def _qualify_arm(
    *,
    arm: AblationArm,
    policy: RedPolicyKind,
    spec: ReferenceEvaluationSpec,
    effective_budget: CampaignBudget,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    judge_policy_descriptor: Mapping[str, object],
) -> ArtifactQualifiedReferenceArm:
    descriptor = build_model_backed_red_policy_descriptor(
        policy=policy,
        purpose=CampaignPurpose.EVALUATION,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=effective_budget,
        models=models,
    )
    qualified = qualify_campaign_policy_descriptors(
        required_model_roles=_REQUIRED_RED_ROLES,
        models=models,
        artifacts=artifacts,
        attack_policy_descriptor=descriptor,
        judge_policy_descriptor=judge_policy_descriptor,
        model_backed_red=True,
    )
    return ArtifactQualifiedReferenceArm(
        arm=arm,
        policy=policy,
        qualified_policies=qualified,
    )
