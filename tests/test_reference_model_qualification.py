import pytest

from llm_redteam.campaign_plan import RedPolicyKind
from llm_redteam.campaigns.lifecycle import deterministic_judge_policy_descriptor
from llm_redteam.domain import CampaignBudget, TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.red.qualification import RedPolicyQualificationPolicy
from llm_redteam.red.runtime import build_model_backed_red_policy_descriptor
from llm_redteam.reference_evaluation import ReferenceEvaluationSpec, ReferenceEvaluationStage
from llm_redteam.reference_model_qualification import (
    qualify_reference_model_policies,
    validate_reference_runtime_policy_descriptors,
)
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy
from llm_redteam.targets.base import SessionMode

CANARY = "RT_REFERENCE_ARTIFACT_CANARY_214"


def _models(*, planner_temperature: float = 0.2) -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner-local",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": planner_temperature,
                    "max_output_tokens": 128,
                    "fallback": [],
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": 0.0,
                    "max_output_tokens": 96,
                    "fallback": [],
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
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def _artifacts(
    *,
    planner_char: str = "a",
) -> dict[tuple[str, str], ModelArtifactIdentity]:
    return {
        ("ollama", "planner-local"): _artifact("planner-local", planner_char),
        ("ollama", "mutator-local"): _artifact("mutator-local", "b"),
    }


def _budget(*, max_turns: int) -> CampaignBudget:
    interactions = 2 * max_turns
    return CampaignBudget(
        max_attacks=2,
        max_generations=1,
        max_turns_per_attack=max_turns,
        max_backtracks_per_attack=1,
        max_branches_per_attack=2,
        max_model_calls=interactions * 2,
        max_model_calls_by_role={
            "red_planner": interactions,
            "red_mutator": interactions,
        },
        max_total_output_tokens=4096,
        max_output_tokens_by_role={"red_planner": 2048, "red_mutator": 1024},
        max_image_generations=0,
        wall_clock_seconds=300,
        max_non_progress_attempts=2,
    )


def _budgets() -> BudgetConfigDocument:
    return BudgetConfigDocument(
        version=1,
        default_profile="smoke",
        profiles={
            "smoke": _budget(max_turns=2),
            "qualification": _budget(max_turns=3),
        },
        policy=RuntimePolicy(),
    )


def _spec() -> ReferenceEvaluationSpec:
    return ReferenceEvaluationSpec(
        version=1,
        experiment_id="artifact-reference-v1",
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.REPLAY,
        required_target_provider="ollama",
        discovery_case_ids=("DISC-001",),
        evaluation_case_ids=("EVAL-001",),
        baseline_policy=RedPolicyKind.ADAPTIVE,
        treatment_policy=RedPolicyKind.MECHANISM,
        smoke_replicates=1,
        qualification_replicates=2,
        smoke_budget_profile="smoke",
        qualification_budget_profile="qualification",
        qualification_policy=RedPolicyQualificationPolicy(min_pair_count=1),
        require_deterministic_canary_judge=True,
    )


def _judge_descriptor() -> dict[str, object]:
    return deterministic_judge_policy_descriptor(canary=CANARY)


def test_reference_arms_hold_exact_red_artifacts_and_judge_constant() -> None:
    qualified = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        spec=_spec(),
        budgets=_budgets(),
        models=_models(),
        artifacts=_artifacts(),
        judge_policy_descriptor=_judge_descriptor(),
    )

    assert (
        qualified.baseline.red_model_role_set_sha256
        == qualified.treatment.red_model_role_set_sha256
    )
    assert (
        qualified.baseline.judge_policy_fingerprint
        == qualified.treatment.judge_policy_fingerprint
    )
    assert (
        qualified.baseline.attack_policy_fingerprint
        != qualified.treatment.attack_policy_fingerprint
    )
    assert qualified.baseline.qualified_policies.red_model_roles is not None
    assert qualified.treatment.qualified_policies.red_model_roles is not None

    contract = qualified.ablation_contract_fingerprints()
    assert (
        contract["baseline_policy_fingerprint"]
        == qualified.baseline.attack_policy_fingerprint
    )
    assert (
        contract["treatment_policy_fingerprint"]
        == qualified.treatment.attack_policy_fingerprint
    )
    assert contract["judge_fingerprint"] == qualified.judge_policy_fingerprint
    assert contract["budget_fingerprint"] == qualified.budget_fingerprint

    provenance = qualified.provenance_identity()
    assert provenance["red_model_role_set_sha256"] == qualified.red_model_role_set_sha256
    assert provenance["reference_qualification_sha256"] == qualified.qualification_sha256


def test_mutable_planner_tag_with_new_weights_changes_both_reference_arm_identities() -> None:
    first = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        spec=_spec(),
        budgets=_budgets(),
        models=_models(),
        artifacts=_artifacts(planner_char="a"),
        judge_policy_descriptor=_judge_descriptor(),
    )
    second = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        spec=_spec(),
        budgets=_budgets(),
        models=_models(),
        artifacts=_artifacts(planner_char="c"),
        judge_policy_descriptor=_judge_descriptor(),
    )

    assert first.red_model_role_set_sha256 != second.red_model_role_set_sha256
    assert (
        first.baseline.attack_policy_fingerprint
        != second.baseline.attack_policy_fingerprint
    )
    assert (
        first.treatment.attack_policy_fingerprint
        != second.treatment.attack_policy_fingerprint
    )
    assert first.qualification_sha256 != second.qualification_sha256


def test_reference_qualification_fails_closed_when_verified_red_artifact_is_missing() -> None:
    with pytest.raises(ValueError, match="verified model artifact missing"):
        qualify_reference_model_policies(
            stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
            spec=_spec(),
            budgets=_budgets(),
            models=_models(),
            artifacts={
                ("ollama", "planner-local"): _artifact("planner-local", "a"),
            },
            judge_policy_descriptor=_judge_descriptor(),
        )


def test_reference_runtime_red_configuration_drift_is_rejected() -> None:
    spec = _spec()
    budgets = _budgets()
    prepared = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        spec=spec,
        budgets=budgets,
        models=_models(planner_temperature=0.2),
        artifacts=_artifacts(),
        judge_policy_descriptor=_judge_descriptor(),
    )
    _, budget = budgets.profile(spec.smoke_budget_profile)
    drifted_models = _models(planner_temperature=0.3)
    baseline_runtime = build_model_backed_red_policy_descriptor(
        policy=spec.baseline_policy,
        purpose=CampaignPurpose.EVALUATION,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=budget,
        models=drifted_models,
    )
    treatment_runtime = build_model_backed_red_policy_descriptor(
        policy=spec.treatment_policy,
        purpose=CampaignPurpose.EVALUATION,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=budget,
        models=drifted_models,
    )

    with pytest.raises(ValueError, match="actual Red runtime descriptor"):
        validate_reference_runtime_policy_descriptors(
            qualified=prepared,
            baseline_runtime_descriptor=baseline_runtime,
            treatment_runtime_descriptor=treatment_runtime,
            judge_policy_descriptor=_judge_descriptor(),
        )


def test_reference_stage_budget_is_part_of_qualified_identity() -> None:
    smoke = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        spec=_spec(),
        budgets=_budgets(),
        models=_models(),
        artifacts=_artifacts(),
        judge_policy_descriptor=_judge_descriptor(),
    )
    qualification = qualify_reference_model_policies(
        stage=ReferenceEvaluationStage.POLICY_QUALIFICATION,
        spec=_spec(),
        budgets=_budgets(),
        models=_models(),
        artifacts=_artifacts(),
        judge_policy_descriptor=_judge_descriptor(),
    )

    assert smoke.budget_profile == "smoke"
    assert qualification.budget_profile == "qualification"
    assert smoke.budget_fingerprint != qualification.budget_fingerprint
    assert (
        smoke.baseline.attack_policy_fingerprint
        != qualification.baseline.attack_policy_fingerprint
    )
    assert smoke.qualification_sha256 != qualification.qualification_sha256


def test_reference_v1_rejects_model_backed_or_untyped_judge_policy() -> None:
    with pytest.raises(ValueError, match="Judge descriptor must be deterministic"):
        qualify_reference_model_policies(
            stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
            spec=_spec(),
            budgets=_budgets(),
            models=_models(),
            artifacts=_artifacts(),
            judge_policy_descriptor={"kind": "semantic-model", "version": 1},
        )
