"""Strict staged contract for the first local multi-turn Red reference experiment."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .campaign_plan import RedPolicyKind
from .domain import AttackCase, StrictModel, TargetClass, TargetIdentity, TargetMode
from .evaluation_sets import (
    EvaluationSetExposure,
    HeldOutEvaluationManifest,
    build_held_out_evaluation_manifest,
)
from .inference_contract import InferenceScope
from .red.qualification import RedPolicyQualificationPolicy
from .runtime_config import BudgetConfigDocument
from .targets.base import SessionMode


class ReferenceEvaluationStage(StrEnum):
    INSTRUMENTATION_SMOKE = "INSTRUMENTATION_SMOKE"
    POLICY_QUALIFICATION = "POLICY_QUALIFICATION"


class ReferenceEvaluationSpec(StrictModel):
    """Versioned experiment design independent of concrete model names."""

    version: int = Field(ge=1)
    experiment_id: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    session_mode: SessionMode
    required_target_provider: str = Field(min_length=1)
    discovery_case_ids: tuple[str, ...] = Field(min_length=1)
    evaluation_case_ids: tuple[str, ...] = Field(min_length=1)
    baseline_policy: RedPolicyKind
    treatment_policy: RedPolicyKind
    smoke_replicates: int = Field(gt=0)
    qualification_replicates: int = Field(gt=0)
    smoke_budget_profile: str = Field(min_length=1)
    qualification_budget_profile: str = Field(min_length=1)
    inference_scope: InferenceScope = InferenceScope.FIXED_CORPUS
    qualification_policy: RedPolicyQualificationPolicy
    require_deterministic_canary_judge: bool = True
    sequence_context_claim_requires_control: bool = True

    @model_validator(mode="after")
    def reference_design_is_valid(self) -> ReferenceEvaluationSpec:
        discovery = set(self.discovery_case_ids)
        evaluation = set(self.evaluation_case_ids)
        if len(discovery) != len(self.discovery_case_ids):
            raise ValueError("discovery_case_ids must be unique")
        if len(evaluation) != len(self.evaluation_case_ids):
            raise ValueError("evaluation_case_ids must be unique")
        if discovery & evaluation:
            raise ValueError("reference discovery and evaluation case IDs must be disjoint")
        if self.target_mode != TargetMode.MODEL:
            raise ValueError("reference evaluation v1 is intentionally limited to MODEL mode")
        if not self.baseline_policy.model_backed or not self.treatment_policy.model_backed:
            raise ValueError("reference evaluation v1 requires model-backed Red policies")
        if self.baseline_policy == self.treatment_policy:
            raise ValueError("baseline and treatment Red policies must differ")
        if self.inference_scope != InferenceScope.FIXED_CORPUS:
            raise ValueError("reference evaluation v1 supports FIXED_CORPUS inference only")
        return self


class ReferenceStagePlan(StrictModel):
    stage: ReferenceEvaluationStage
    experiment_id: str
    case_ids: tuple[str, ...]
    replicates_per_case: int = Field(gt=0)
    pair_count: int = Field(gt=0)
    arm_trials: int = Field(gt=0)
    total_trials_across_arms: int = Field(gt=0)
    budget_profile: str
    max_target_interactions_per_arm: int = Field(gt=0)
    maximum_red_model_calls_per_arm: int = Field(gt=0)
    may_issue_policy_qualification: bool


class ReferenceEvaluationPreflight(StrictModel):
    ready: bool
    target_configuration_hash: str
    smoke: ReferenceStagePlan
    qualification: ReferenceStagePlan
    issues: tuple[str, ...] = ()


def load_reference_evaluation_spec(path: str | Path) -> ReferenceEvaluationSpec:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"reference evaluation specification does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return ReferenceEvaluationSpec.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid reference evaluation specification {source}: {exc}") from exc


def build_reference_evaluation_manifest(
    *,
    spec: ReferenceEvaluationSpec,
    cases: tuple[AttackCase, ...],
    corpus_snapshot_hash: str,
) -> HeldOutEvaluationManifest:
    """Build the exact hash-bound held-out split declared by the reference spec."""

    by_id = {case.id: case for case in cases}
    missing = sorted(
        (set(spec.discovery_case_ids) | set(spec.evaluation_case_ids)) - set(by_id)
    )
    if missing:
        raise ValueError(f"reference manifest cases missing from corpus: {missing}")
    discovery = tuple(by_id[case_id] for case_id in spec.discovery_case_ids)
    evaluation = tuple(by_id[case_id] for case_id in spec.evaluation_case_ids)
    return build_held_out_evaluation_manifest(
        manifest_id=f"{spec.experiment_id}-held-out-v1",
        discovery_cases=discovery,
        evaluation_cases=evaluation,
        corpus_snapshot_hash=corpus_snapshot_hash,
        split_strategy="reference-v1-predeclared-disjoint-native-cases",
        exposure=EvaluationSetExposure.INTERNAL_HELD_OUT,
    )


def preflight_reference_evaluation(
    *,
    spec: ReferenceEvaluationSpec,
    cases: tuple[AttackCase, ...],
    budgets: BudgetConfigDocument,
    target: TargetIdentity,
) -> ReferenceEvaluationPreflight:
    """Validate the complete two-stage experiment without making any inference call."""

    issues: list[str] = []
    case_by_id = {case.id: case for case in cases}
    all_ids = set(spec.discovery_case_ids) | set(spec.evaluation_case_ids)
    missing = sorted(all_ids - set(case_by_id))
    if missing:
        issues.append(f"missing reference experiment cases: {missing}")

    selected = tuple(case_by_id[case_id] for case_id in sorted(all_ids) if case_id in case_by_id)
    for case in selected:
        _validate_reference_case(case, spec, issues)

    if target.target_class != spec.target_class:
        issues.append("actual target class does not match reference specification")
    if target.target_mode != spec.target_mode:
        issues.append("actual target mode does not match reference specification")
    if target.provider.casefold() != spec.required_target_provider.casefold():
        issues.append(
            "actual target provider does not match the provider required by the reference spec"
        )

    smoke = _build_stage_plan(
        spec=spec,
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        replicates=spec.smoke_replicates,
        profile_name=spec.smoke_budget_profile,
        budgets=budgets,
        issues=issues,
    )
    qualification = _build_stage_plan(
        spec=spec,
        stage=ReferenceEvaluationStage.POLICY_QUALIFICATION,
        replicates=spec.qualification_replicates,
        profile_name=spec.qualification_budget_profile,
        budgets=budgets,
        issues=issues,
    )

    if qualification.pair_count < spec.qualification_policy.min_pair_count:
        issues.append(
            "qualification stage pair count is below the predeclared qualification minimum"
        )

    return ReferenceEvaluationPreflight(
        ready=not issues,
        target_configuration_hash=target.configuration_hash,
        smoke=smoke,
        qualification=qualification,
        issues=tuple(issues),
    )


def _validate_reference_case(
    case: AttackCase,
    spec: ReferenceEvaluationSpec,
    issues: list[str],
) -> None:
    if spec.target_class not in case.target_classes:
        issues.append(f"case {case.id} is incompatible with target_class={spec.target_class}")
    if spec.target_mode not in case.target_modes:
        issues.append(f"case {case.id} is incompatible with target_mode={spec.target_mode}")
    if case.interaction_mode != "multi_turn":
        issues.append(f"case {case.id} is not a multi_turn reference case")
    if case.payload.turns is not None:
        issues.append(
            f"case {case.id} has scripted turns; model-backed reference Red requires a goal seed"
        )
    if not case.security_objective.forbidden_effect:
        issues.append(f"case {case.id} has no measurable forbidden_effect")


def _build_stage_plan(
    *,
    spec: ReferenceEvaluationSpec,
    stage: ReferenceEvaluationStage,
    replicates: int,
    profile_name: str,
    budgets: BudgetConfigDocument,
    issues: list[str],
) -> ReferenceStagePlan:
    pair_count = len(spec.evaluation_case_ids) * replicates
    try:
        _, budget = budgets.profile(profile_name)
    except ValueError as exc:
        issues.append(str(exc))
        budget = next(iter(budgets.profiles.values()))

    if pair_count > budget.max_attacks:
        issues.append(
            f"{stage.value} requires {pair_count} trials per arm but "
            f"budget {profile_name} allows {budget.max_attacks}"
        )

    max_target_interactions = pair_count * budget.max_turns_per_attack
    # A model-backed turn consumes one planner call and can consume one mutator call
    # after validation failure. This is a conservative Red instrumentation bound.
    max_red_model_calls = max_target_interactions * 2
    if budget.max_model_calls < max_red_model_calls:
        issues.append(
            f"{stage.value} model-call budget {budget.max_model_calls} is below "
            f"conservative Red upper bound {max_red_model_calls}"
        )
    planner_limit = budget.max_model_calls_by_role.get("red_planner")
    if planner_limit is not None and planner_limit < max_target_interactions:
        issues.append(
            f"{stage.value} red_planner call limit {planner_limit} is below "
            f"target-interaction upper bound {max_target_interactions}"
        )
    mutator_limit = budget.max_model_calls_by_role.get("red_mutator")
    if mutator_limit is not None and mutator_limit < max_target_interactions:
        issues.append(
            f"{stage.value} red_mutator call limit {mutator_limit} is below "
            f"worst-case mutation upper bound {max_target_interactions}"
        )

    return ReferenceStagePlan(
        stage=stage,
        experiment_id=spec.experiment_id,
        case_ids=spec.evaluation_case_ids,
        replicates_per_case=replicates,
        pair_count=pair_count,
        arm_trials=pair_count,
        total_trials_across_arms=pair_count * 2,
        budget_profile=profile_name,
        max_target_interactions_per_arm=max_target_interactions,
        maximum_red_model_calls_per_arm=max_red_model_calls,
        may_issue_policy_qualification=(
            stage == ReferenceEvaluationStage.POLICY_QUALIFICATION
        ),
    )
