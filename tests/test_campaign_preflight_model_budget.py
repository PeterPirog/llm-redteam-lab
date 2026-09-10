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
    SecurityObjective,
    SourceMode,
    SourceRef,
    TargetClass,
    TargetMode,
)
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_roles import (
    ModelLocation,
    ModelPolicy,
    ModelRole,
    ModelRoleConfig,
    ModelsConfig,
)
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy


def test_model_single_call_output_limit_must_fit_authorized_role_budget() -> None:
    case = AttackCase(
        id="budgeted-multiturn",
        name="budgeted-multiturn",
        description="Synthetic goal seed for preflight budget validation.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["synthetic"],
        complexity_tier=AttackTier.T1,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test"),
        security_objective=SecurityObjective(
            invariant="Synthetic marker remains protected.",
            expected_safe_behavior="Do not emit the marker.",
            forbidden_effect="Synthetic marker is emitted.",
        ),
        payload=PayloadSpec(text="synthetic goal seed"),
        grading=GradingSpec(preferred=["deterministic"], detectors=["marker"]),
        enabled_by_default=True,
    )
    budget = CampaignBudget(
        max_attacks=1,
        max_generations=1,
        max_turns_per_attack=4,
        max_model_calls=8,
        max_model_calls_by_role={"red_planner": 4, "red_mutator": 2},
        max_total_output_tokens=6000,
        max_output_tokens_by_role={"red_planner": 1000, "red_mutator": 1000},
        max_image_generations=0,
        wall_clock_seconds=300,
        max_non_progress_attempts=2,
    )
    budgets = BudgetConfigDocument(
        version=1,
        default_profile="smoke",
        profiles={"smoke": budget},
        policy=RuntimePolicy(),
    )
    models = ModelsConfig(
        version=1,
        policy=ModelPolicy(local_first=True, allow_cloud_fallback=False),
        roles={
            ModelRole.RED_PLANNER: ModelRoleConfig(
                provider="test",
                model="planner",
                **{"class": ModelLocation.LOCAL},
                capabilities=frozenset({"text", "reasoning"}),
                max_output_tokens=1200,
            ),
            ModelRole.RED_MUTATOR: ModelRoleConfig(
                provider="test",
                model="mutator",
                **{"class": ModelLocation.LOCAL},
                capabilities=frozenset({"text"}),
                max_output_tokens=800,
            ),
        },
    )

    report = preflight_campaign(
        plan=CampaignPlan(
            purpose=CampaignPurpose.DISCOVERY,
            target_class=TargetClass.WRITING,
            target_mode=TargetMode.MODEL,
            red_policy=RedPolicyKind.ADAPTIVE,
        ),
        cases=(case,),
        budgets=budgets,
        models=models,
    )

    errors = {
        issue.code
        for issue in report.issues
        if issue.severity == PreflightSeverity.ERROR
    }
    assert report.ready is False
    assert "MODEL_ROLE_OUTPUT_BUDGET" in errors
