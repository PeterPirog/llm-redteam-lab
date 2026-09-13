import pytest

from llm_redteam.campaign_plan import CampaignPlan, CampaignPreflight, RedPolicyKind
from llm_redteam.campaigns.model_qualification import (
    qualify_campaign_policy_descriptors,
    validate_artifact_qualified_campaign_policies,
)
from llm_redteam.domain import TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelRole, ModelsConfig


def _models() -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.2,
                    "max_output_tokens": 256,
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "temperature": 0.7,
                    "max_output_tokens": 128,
                },
                "judge_semantic": {
                    "provider": "ollama",
                    "model": "judge:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                },
            },
        }
    )


def _artifact(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
    )


def _artifacts(*, planner_char: str = "a") -> dict[tuple[str, str], ModelArtifactIdentity]:
    return {
        ("ollama", "planner:latest"): _artifact("planner:latest", planner_char),
        ("ollama", "mutator:latest"): _artifact("mutator:latest", "b"),
        ("ollama", "judge:latest"): _artifact("judge:latest", "c"),
    }


def _qualified(*, planner_char: str = "a"):
    return qualify_campaign_policy_descriptors(
        required_model_roles=(
            ModelRole.RED_PLANNER,
            ModelRole.RED_MUTATOR,
            ModelRole.JUDGE_SEMANTIC,
        ),
        models=_models(),
        artifacts=_artifacts(planner_char=planner_char),
        attack_policy_descriptor={"kind": "adaptive", "runtime_version": 2},
        judge_policy_descriptor={"kind": "semantic", "version": 1},
        model_backed_red=True,
    )


def _plan(*, attack_fp: str | None, judge_fp: str | None) -> CampaignPlan:
    return CampaignPlan(
        purpose=CampaignPurpose.EVALUATION,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        budget_profile="reference_qualification",
        red_policy=RedPolicyKind.ADAPTIVE,
        target_snapshot_id="target-snapshot-v1",
        attack_policy_fingerprint=attack_fp,
        judge_policy_fingerprint=judge_fp,
    )


def _ready_preflight() -> CampaignPreflight:
    return CampaignPreflight(
        purpose=CampaignPurpose.EVALUATION,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        budget_profile="reference_qualification",
        red_policy=RedPolicyKind.ADAPTIVE,
        selected_case_ids=("EVAL-001",),
        planned_trials=1,
        minimum_target_interactions=1,
        maximum_target_interactions=3,
        multi_turn_cases=1,
        image_cases=0,
        required_model_roles=("red_planner", "red_mutator", "judge_semantic"),
        issues=(),
    )


def test_evaluation_identity_can_be_precomputed_before_ready_preflight() -> None:
    qualified = _qualified()

    assert len(qualified.attack_policy_fingerprint) == 64
    assert len(qualified.judge_policy_fingerprint) == 64

    plan = _plan(
        attack_fp=qualified.attack_policy_fingerprint,
        judge_fp=qualified.judge_policy_fingerprint,
    )
    validate_artifact_qualified_campaign_policies(
        plan=plan,
        preflight=_ready_preflight(),
        qualified=qualified,
    )


def test_evaluation_admission_rejects_missing_declared_fingerprints() -> None:
    qualified = _qualified()
    with pytest.raises(ValueError, match="requires declared"):
        validate_artifact_qualified_campaign_policies(
            plan=_plan(attack_fp=None, judge_fp=None),
            preflight=_ready_preflight(),
            qualified=qualified,
        )


def test_evaluation_admission_rejects_weights_changed_after_plan_preparation() -> None:
    prepared = _qualified(planner_char="a")
    plan = _plan(
        attack_fp=prepared.attack_policy_fingerprint,
        judge_fp=prepared.judge_policy_fingerprint,
    )
    changed = _qualified(planner_char="d")

    with pytest.raises(ValueError, match="attack_policy_fingerprint"):
        validate_artifact_qualified_campaign_policies(
            plan=plan,
            preflight=_ready_preflight(),
            qualified=changed,
        )


def test_admission_rejects_required_role_drift_after_preparation() -> None:
    qualified = _qualified()
    plan = _plan(
        attack_fp=qualified.attack_policy_fingerprint,
        judge_fp=qualified.judge_policy_fingerprint,
    )
    changed_preflight = _ready_preflight().model_copy(
        update={"required_model_roles": ("red_planner", "red_mutator")}
    )

    with pytest.raises(ValueError, match="qualified model roles"):
        validate_artifact_qualified_campaign_policies(
            plan=plan,
            preflight=changed_preflight,
            qualified=qualified,
        )


def test_preparation_rejects_red_policy_role_inconsistency() -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        qualify_campaign_policy_descriptors(
            required_model_roles=(ModelRole.JUDGE_SEMANTIC,),
            models=_models(),
            artifacts=_artifacts(),
            attack_policy_descriptor={"kind": "adaptive", "runtime_version": 2},
            judge_policy_descriptor={"kind": "semantic", "version": 1},
            model_backed_red=True,
        )
