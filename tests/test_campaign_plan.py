from llm_redteam.campaign_plan import (
    CampaignPlan,
    PreflightSeverity,
    RedPolicyKind,
    preflight_campaign,
)
from llm_redteam.domain import (
    AttackCase,
    AttackTier,
    CampaignBudget,
    GradingSpec,
    PayloadSpec,
    PayloadTurn,
    PayloadTurnRole,
    SecurityObjective,
    SourceMode,
    SourceRef,
    TargetClass,
    TargetMode,
)
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy
from llm_redteam.targets.base import SessionMode


def _case(
    *,
    case_id: str = "case-1",
    target_class: TargetClass = TargetClass.WRITING,
    target_mode: TargetMode = TargetMode.MODEL,
    interaction_mode: str = "single_turn",
    preferred: list[str] | None = None,
    payload: PayloadSpec | None = None,
    forbidden_effect: str | None = "Synthetic marker is emitted.",
) -> AttackCase:
    return AttackCase(
        id=case_id,
        name="synthetic-case",
        description="Synthetic campaign-plan test case.",
        target_classes=[target_class],
        target_modes=[target_mode],
        attack_family=["synthetic"],
        complexity_tier=AttackTier.T1,
        interaction_mode=interaction_mode,
        source=SourceRef(mode=SourceMode.NATIVE, name="test"),
        security_objective=SecurityObjective(
            invariant="Synthetic marker remains protected.",
            expected_safe_behavior="Do not emit the marker.",
            forbidden_effect=forbidden_effect,
        ),
        payload=payload or PayloadSpec(text="synthetic probe"),
        grading=GradingSpec(preferred=preferred or ["deterministic"], detectors=["marker"]),
        enabled_by_default=True,
    )


def _budgets(
    *,
    max_turns: int = 4,
    max_attacks: int = 5,
    max_images: int = 2,
    runtime_policy: RuntimePolicy | None = None,
):
    budget = CampaignBudget(
        max_attacks=max_attacks,
        max_generations=1,
        max_turns_per_attack=max_turns,
        max_model_calls=12,
        max_model_calls_by_role={},
        max_total_output_tokens=6000,
        max_output_tokens_by_role={},
        max_image_generations=max_images,
        wall_clock_seconds=300,
        max_non_progress_attempts=2,
    )
    return BudgetConfigDocument(
        version=1,
        default_profile="smoke",
        profiles={"smoke": budget},
        policy=runtime_policy or RuntimePolicy(),
    )


def _codes(report, severity: PreflightSeverity | None = None) -> set[str]:
    return {
        issue.code
        for issue in report.issues
        if severity is None or issue.severity == severity
    }


def test_static_discovery_can_be_planned_without_inference_roles() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
        ),
        cases=(_case(),),
        budgets=_budgets(),
    )

    assert report.ready is True
    assert report.planned_trials == 1
    assert report.required_model_roles == ()


def test_selected_case_requires_explicit_forbidden_effect() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
        ),
        cases=(_case(forbidden_effect=None),),
        budgets=_budgets(),
    )

    assert report.ready is False
    assert "SECURITY_OBJECTIVE_INCOMPLETE" in _codes(report, PreflightSeverity.ERROR)


def test_evaluation_fails_closed_without_held_out_measurement_identity() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.EVALUATION,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
        ),
        cases=(_case(),),
        budgets=_budgets(),
    )

    assert report.ready is False
    errors = _codes(report, PreflightSeverity.ERROR)
    assert "HELD_OUT_REQUIRED" in errors
    assert "MEASUREMENT_IDENTITY" in errors


def test_multi_turn_case_cannot_use_single_turn_budget() -> None:
    case = _case(interaction_mode="multi_turn")
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
        ),
        cases=(case,),
        budgets=_budgets(max_turns=1),
    )

    assert report.ready is False
    assert "MULTITURN_BUDGET" in _codes(report, PreflightSeverity.ERROR)


def test_planned_replicates_must_fit_attack_budget() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
            replicates=3,
        ),
        cases=(_case(case_id="a"), _case(case_id="b")),
        budgets=_budgets(max_attacks=5),
    )

    assert report.ready is False
    assert "ATTACK_BUDGET" in _codes(report, PreflightSeverity.ERROR)


def test_explicit_budget_profile_policy_blocks_implicit_default() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
        ),
        cases=(_case(),),
        budgets=_budgets(
            runtime_policy=RuntimePolicy(require_explicit_profile=True),
        ),
    )

    assert report.ready is False
    assert "EXPLICIT_BUDGET_PROFILE_REQUIRED" in _codes(
        report,
        PreflightSeverity.ERROR,
    )


def test_image_plan_requires_multimodal_model_configuration() -> None:
    case = _case(
        target_class=TargetClass.IMAGE_GENERATION,
        target_mode=TargetMode.PIPELINE,
        preferred=["multimodal"],
    )
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.IMAGE_GENERATION,
            target_mode=TargetMode.PIPELINE,
        ),
        cases=(case,),
        budgets=_budgets(max_images=2),
    )

    assert report.ready is False
    assert "MODEL_CONFIG_REQUIRED" in _codes(report, PreflightSeverity.ERROR)


def test_deterministic_image_plan_can_disable_global_multimodal_requirement() -> None:
    case = _case(
        target_class=TargetClass.IMAGE_GENERATION,
        target_mode=TargetMode.PIPELINE,
        preferred=["deterministic"],
    )
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.IMAGE_GENERATION,
            target_mode=TargetMode.PIPELINE,
        ),
        cases=(case,),
        budgets=_budgets(
            max_images=2,
            runtime_policy=RuntimePolicy(
                require_multimodal_judge_for_image_generation=False,
            ),
        ),
    )

    assert report.ready is True
    assert report.required_model_roles == ()


def test_agent_network_enablement_is_visible_not_silent() -> None:
    case = _case(
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        interaction_mode="agentic",
    )
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.CODING,
            target_mode=TargetMode.AGENT,
            session_mode=SessionMode.TARGET_MANAGED,
            allow_agent_network=True,
        ),
        cases=(case,),
        budgets=_budgets(),
    )

    assert report.ready is True
    warnings = _codes(report, PreflightSeverity.WARNING)
    assert "AGENT_NETWORK_ENABLED" in warnings
    assert "TARGET_MANAGED_SESSION" in warnings


def test_environment_turn_payload_requires_environment_aware_runner() -> None:
    case = _case(
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        interaction_mode="environment_injection",
        payload=PayloadSpec(
            turns=(
                PayloadTurn(
                    role=PayloadTurnRole.EXTERNAL_CONTENT,
                    content="Untrusted synthetic repository instruction.",
                ),
            )
        ),
    )
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.CODING,
            target_mode=TargetMode.AGENT,
        ),
        cases=(case,),
        budgets=_budgets(),
    )

    assert report.ready is False
    assert "ENVIRONMENT_RUNNER_REQUIRED" in _codes(report, PreflightSeverity.ERROR)


def test_model_backed_red_requires_explicit_role_configuration() -> None:
    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
            red_policy=RedPolicyKind.PORTFOLIO,
        ),
        cases=(_case(),),
        budgets=_budgets(),
    )

    assert report.ready is False
    assert set(report.required_model_roles) == {"red_mutator", "red_planner"}
    assert "MODEL_CONFIG_REQUIRED" in _codes(report, PreflightSeverity.ERROR)
