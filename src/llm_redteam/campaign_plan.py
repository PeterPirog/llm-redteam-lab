"""Operator-facing campaign planning and fail-closed preflight validation.

A campaign plan is deliberately separate from execution. It binds measurement
purpose, Blue target class/mode, corpus selection, budget and Red policy before
any target or model call can occur.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import Field, computed_field, model_validator

from .corpus import select_cases
from .domain import (
    AttackCase,
    CampaignBudget,
    PayloadTurnRole,
    StrictModel,
    TargetClass,
    TargetMode,
)
from .evaluation_protocol import CampaignPurpose
from .evaluation_sets import HeldOutEvaluationManifest, select_manifest_cases
from .model_roles import ModelRole, ModelsConfig
from .runtime_config import BudgetConfigDocument
from .targets.base import SessionMode


class RedPolicyKind(StrEnum):
    STATIC = "static"
    ADAPTIVE = "adaptive"
    MECHANISM = "mechanism"
    PORTFOLIO = "portfolio"

    @property
    def model_backed(self) -> bool:
        return self != RedPolicyKind.STATIC


class PreflightSeverity(StrEnum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class PreflightIssue(StrictModel):
    code: str = Field(min_length=1)
    severity: PreflightSeverity
    message: str = Field(min_length=1)


class CampaignPlan(StrictModel):
    purpose: CampaignPurpose
    target_class: TargetClass
    target_mode: TargetMode
    budget_profile: str | None = None
    red_policy: RedPolicyKind = RedPolicyKind.STATIC
    replicates: int = Field(gt=0, default=1)
    enabled_only: bool = True
    session_mode: SessionMode = SessionMode.REPLAY
    target_snapshot_id: str | None = None
    attack_policy_fingerprint: str | None = None
    judge_policy_fingerprint: str | None = None
    allow_agent_network: bool = False
    allow_agent_git_push: bool = False

    @model_validator(mode="after")
    def target_specific_options_are_valid(self) -> CampaignPlan:
        if self.target_mode != TargetMode.AGENT and (
            self.allow_agent_network or self.allow_agent_git_push
        ):
            raise ValueError("agent network/git options require target_mode=AGENT")
        return self


class CampaignPreflight(StrictModel):
    purpose: CampaignPurpose
    target_class: TargetClass
    target_mode: TargetMode
    budget_profile: str
    red_policy: RedPolicyKind
    selected_case_ids: tuple[str, ...]
    planned_trials: int
    minimum_target_interactions: int
    maximum_target_interactions: int
    multi_turn_cases: int
    image_cases: int
    required_model_roles: tuple[str, ...]
    issues: tuple[PreflightIssue, ...]

    @computed_field
    @property
    def ready(self) -> bool:
        return not any(issue.severity == PreflightSeverity.ERROR for issue in self.issues)


def load_evaluation_manifest(path: str | Path) -> HeldOutEvaluationManifest:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"evaluation manifest does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return HeldOutEvaluationManifest.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid evaluation manifest {source}: {exc}") from exc


def preflight_campaign(
    *,
    plan: CampaignPlan,
    cases: tuple[AttackCase, ...],
    budgets: BudgetConfigDocument,
    models: ModelsConfig | None = None,
    evaluation_manifest: HeldOutEvaluationManifest | None = None,
) -> CampaignPreflight:
    """Validate a campaign before execution without making any inference call."""

    issues: list[PreflightIssue] = []
    try:
        profile_name, budget = budgets.profile(plan.budget_profile)
    except ValueError as exc:
        profile_name = plan.budget_profile or budgets.default_profile
        budget = next(iter(budgets.profiles.values()))
        _error(issues, "BUDGET_PROFILE", str(exc))

    selected = _select_plan_cases(plan, cases, evaluation_manifest, issues)
    planned_trials = len(selected) * plan.replicates
    if planned_trials > budget.max_attacks:
        _error(
            issues,
            "ATTACK_BUDGET",
            f"planned trials={planned_trials} exceed max_attacks={budget.max_attacks}",
        )

    _validate_payload_execution(plan, selected, budget, issues)
    _validate_security_objectives(selected, issues)
    min_interactions, max_interactions = _interaction_bounds(plan, selected, budget)

    multi_turn = tuple(case for case in selected if case.interaction_mode == "multi_turn")
    if multi_turn and budget.max_turns_per_attack < 2:
        _error(
            issues,
            "MULTITURN_BUDGET",
            "selected multi-turn cases require max_turns_per_attack >= 2",
        )

    image_cases = tuple(
        case for case in selected if TargetClass.IMAGE_GENERATION in case.target_classes
    )
    minimum_image_generations = (
        sum(_case_interaction_bounds(case, plan, budget)[0] for case in image_cases)
        * plan.replicates
    )
    maximum_image_generations = (
        sum(_case_interaction_bounds(case, plan, budget)[1] for case in image_cases)
        * plan.replicates
    )
    if minimum_image_generations > budget.max_image_generations:
        _error(
            issues,
            "IMAGE_BUDGET",
            "image budget cannot provide the minimum generations required by the plan",
        )
    elif maximum_image_generations > budget.max_image_generations:
        message = (
            "image budget is below the planned upper bound; adaptive trajectories may stop early"
        )
        if plan.purpose == CampaignPurpose.EVALUATION:
            _error(issues, "IMAGE_BUDGET_UPPER_BOUND", message)
        else:
            _warning(issues, "IMAGE_BUDGET_UPPER_BOUND", message)

    required_roles = _required_model_roles(plan, selected)
    _validate_model_roles(required_roles, models, plan, issues)
    _validate_measurement_identity(plan, evaluation_manifest, issues)
    _validate_agent_policy(plan, budgets, issues)

    return CampaignPreflight(
        purpose=plan.purpose,
        target_class=plan.target_class,
        target_mode=plan.target_mode,
        budget_profile=profile_name,
        red_policy=plan.red_policy,
        selected_case_ids=tuple(case.id for case in selected),
        planned_trials=planned_trials,
        minimum_target_interactions=min_interactions,
        maximum_target_interactions=max_interactions,
        multi_turn_cases=len(multi_turn),
        image_cases=len(image_cases),
        required_model_roles=tuple(role.value for role in sorted(required_roles, key=str)),
        issues=tuple(issues),
    )


def _select_plan_cases(
    plan: CampaignPlan,
    cases: tuple[AttackCase, ...],
    manifest: HeldOutEvaluationManifest | None,
    issues: list[PreflightIssue],
) -> tuple[AttackCase, ...]:
    if plan.purpose == CampaignPurpose.EVALUATION:
        if manifest is None:
            _error(issues, "HELD_OUT_REQUIRED", "EVALUATION requires a held-out manifest")
            return ()
        try:
            selected = select_manifest_cases(cases, manifest=manifest, evaluation=True)
        except ValueError as exc:
            _error(issues, "HELD_OUT_MISMATCH", str(exc))
            return ()
        incompatible = tuple(
            case
            for case in selected
            if plan.target_class not in case.target_classes
            or plan.target_mode not in case.target_modes
        )
        if incompatible:
            _error(
                issues,
                "TARGET_CASE_MISMATCH",
                "held-out cases incompatible with target: "
                + ", ".join(case.id for case in incompatible),
            )
            return ()
        return selected

    selected = select_cases(
        cases,
        target_class=plan.target_class,
        target_mode=plan.target_mode,
        enabled_only=plan.enabled_only,
    )
    if not selected:
        _error(issues, "NO_CASES", "no compatible attack cases selected")
    return selected


def _validate_payload_execution(
    plan: CampaignPlan,
    selected: tuple[AttackCase, ...],
    budget: CampaignBudget,
    issues: list[PreflightIssue],
) -> None:
    for case in selected:
        if case.payload.fixture is not None or case.payload.artifact is not None:
            _error(
                issues,
                "LIFECYCLE_RUNNER_REQUIRED",
                f"case {case.id} requires a fixture/artifact-aware lifecycle runner",
            )

        if case.payload.turns is not None:
            environment_roles = {
                turn.role
                for turn in case.payload.turns
                if turn.role != PayloadTurnRole.USER
            }
            if environment_roles:
                roles = ", ".join(sorted(role.value for role in environment_roles))
                _error(
                    issues,
                    "ENVIRONMENT_RUNNER_REQUIRED",
                    f"case {case.id} requires an environment-aware runner for roles: {roles}",
                )
            if case.interaction_mode == "multi_turn" and plan.red_policy != RedPolicyKind.STATIC:
                _error(
                    issues,
                    "SEQUENCE_POLICY_CONFLICT",
                    f"case {case.id} has explicit turns and requires red_policy=static",
                )
            if (
                case.interaction_mode == "multi_turn"
                and len(case.payload.turns) > budget.max_turns_per_attack
            ):
                _error(
                    issues,
                    "SEQUENCE_TURN_BUDGET",
                    f"case {case.id} sequence exceeds max_turns_per_attack",
                )
            for turn in case.payload.turns:
                _validate_renderable(case, turn.content, issues)
        elif case.interaction_mode == "multi_turn" and plan.red_policy == RedPolicyKind.STATIC:
            _error(
                issues,
                "STATIC_MULTITURN_SEQUENCE_REQUIRED",
                f"case {case.id} needs explicit turns or a model-backed Red policy",
            )

        if case.payload.template is not None:
            _validate_renderable(case, case.payload.template, issues)

        if case.interaction_mode == "multi_attempt":
            _error(
                issues,
                "RUNNER_UNAVAILABLE",
                f"case {case.id} uses multi_attempt, which has no lifecycle runner yet",
            )


def _validate_security_objectives(
    selected: tuple[AttackCase, ...],
    issues: list[PreflightIssue],
) -> None:
    for case in selected:
        objective = case.security_objective
        if objective.expected_safe_behavior is None and objective.forbidden_effect is None:
            _error(
                issues,
                "OBJECTIVE_UNDERSPECIFIED",
                f"case {case.id} lacks both expected safe behavior and forbidden effect",
            )


def _validate_renderable(
    case: AttackCase,
    template: str,
    issues: list[PreflightIssue],
) -> None:
    rendered = template
    for name, value in case.variables.items():
        rendered = rendered.replace("{{" + name + "}}", str(value))
    if "{{" in rendered or "}}" in rendered:
        _error(
            issues,
            "UNRESOLVED_VARIABLE",
            f"case {case.id} contains unresolved template variables",
        )


def _interaction_bounds(
    plan: CampaignPlan,
    selected: tuple[AttackCase, ...],
    budget: CampaignBudget,
) -> tuple[int, int]:
    minimum = 0
    maximum = 0
    for case in selected:
        case_min, case_max = _case_interaction_bounds(case, plan, budget)
        minimum += case_min * plan.replicates
        maximum += case_max * plan.replicates
    return minimum, maximum


def _case_interaction_bounds(
    case: AttackCase,
    plan: CampaignPlan,
    budget: CampaignBudget,
) -> tuple[int, int]:
    if case.interaction_mode != "multi_turn":
        return 1, 1
    if case.payload.turns is not None:
        count = len(case.payload.turns)
        return count, count
    if plan.red_policy.model_backed:
        return 1, budget.max_turns_per_attack
    return 0, 0


def _required_model_roles(
    plan: CampaignPlan,
    selected: tuple[AttackCase, ...],
) -> set[ModelRole]:
    roles: set[ModelRole] = set()
    if plan.red_policy.model_backed:
        roles.update({ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR})
    preferred = {judge for case in selected for judge in case.grading.preferred}
    if "semantic" in preferred:
        roles.add(ModelRole.JUDGE_SEMANTIC)
    if "multimodal" in preferred or plan.target_class == TargetClass.IMAGE_GENERATION:
        roles.add(ModelRole.JUDGE_MULTIMODAL)
    return roles


def _validate_model_roles(
    required: set[ModelRole],
    models: ModelsConfig | None,
    plan: CampaignPlan,
    issues: list[PreflightIssue],
) -> None:
    if not required:
        return
    if models is None:
        _error(
            issues,
            "MODEL_CONFIG_REQUIRED",
            "campaign requires model roles but no models configuration was supplied",
        )
        return
    for role in sorted(required, key=str):
        capabilities = {"text"}
        if role == ModelRole.JUDGE_MULTIMODAL:
            capabilities.add("vision")
        if role == ModelRole.RED_PLANNER:
            capabilities.add("reasoning")
        try:
            models.role(role, required_capabilities=capabilities)
        except ValueError as exc:
            _error(issues, "MODEL_ROLE", str(exc))

    if plan.target_class == TargetClass.IMAGE_GENERATION:
        try:
            models.role(
                ModelRole.JUDGE_MULTIMODAL,
                required_capabilities={"text", "vision"},
            )
        except ValueError as exc:
            _error(issues, "MULTIMODAL_JUDGE", str(exc))


def _validate_measurement_identity(
    plan: CampaignPlan,
    manifest: HeldOutEvaluationManifest | None,
    issues: list[PreflightIssue],
) -> None:
    if plan.purpose != CampaignPurpose.EVALUATION:
        return
    required = {
        "target_snapshot_id": plan.target_snapshot_id,
        "attack_policy_fingerprint": plan.attack_policy_fingerprint,
        "judge_policy_fingerprint": plan.judge_policy_fingerprint,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        _error(
            issues,
            "MEASUREMENT_IDENTITY",
            "EVALUATION requires immutable measurement identity: " + ", ".join(missing),
        )
    if manifest is not None and manifest.red_can_access_evaluation_content:
        _error(issues, "EVALUATION_LEAKAGE", "held-out content is exposed to Red")


def _validate_agent_policy(
    plan: CampaignPlan,
    budgets: BudgetConfigDocument,
    issues: list[PreflightIssue],
) -> None:
    if plan.target_mode != TargetMode.AGENT:
        return
    if plan.allow_agent_network and budgets.policy.deny_network_by_default_for_agent_targets:
        _warning(
            issues,
            "AGENT_NETWORK_ENABLED",
            "agent network access is explicitly enabled; use an outer disposable sandbox",
        )
    if plan.allow_agent_git_push and budgets.policy.deny_git_push_by_default_for_agent_targets:
        _warning(
            issues,
            "AGENT_GIT_PUSH_ENABLED",
            "agent git push is explicitly enabled; use only an authorized synthetic remote",
        )
    if plan.session_mode == SessionMode.TARGET_MANAGED:
        _warning(
            issues,
            "TARGET_MANAGED_SESSION",
            (
                "target-managed sessions cannot use replay backtracking; "
                "preserve provider session identity"
            ),
        )


def _error(issues: list[PreflightIssue], code: str, message: str) -> None:
    issues.append(PreflightIssue(code=code, severity=PreflightSeverity.ERROR, message=message))


def _warning(issues: list[PreflightIssue], code: str, message: str) -> None:
    issues.append(PreflightIssue(code=code, severity=PreflightSeverity.WARNING, message=message))
