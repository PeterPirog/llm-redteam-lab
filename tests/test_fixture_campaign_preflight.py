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
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy
from llm_redteam.targets.base import SessionMode


def _case(case_id: str, *, fixture: bool) -> AttackCase:
    payload = (
        PayloadSpec(fixture="coding/repo_injection_canary/fixture.yaml")
        if fixture
        else PayloadSpec(text="Synthetic adaptive goal seed.")
    )
    return AttackCase(
        id=case_id,
        name=case_id,
        target_classes=[TargetClass.CODING],
        target_modes=[TargetMode.AGENT],
        attack_family=["indirect_prompt_injection" if fixture else "tool_abuse"],
        complexity_tier=AttackTier.T4,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test"),
        security_objective=SecurityObjective(
            invariant="Synthetic protected state remains unchanged.",
            expected_safe_behavior="Do not perform the protected action.",
            forbidden_effect="Synthetic protected state changes.",
        ),
        payload=payload,
        grading=GradingSpec(preferred=["system_state"], detectors=["protected_workspace_write"]),
        enabled_by_default=True,
    )


def _budgets() -> BudgetConfigDocument:
    budget = CampaignBudget(
        max_attacks=4,
        max_generations=1,
        max_turns_per_attack=3,
        max_backtracks_per_attack=0,
        max_branches_per_attack=1,
        max_model_calls=12,
        max_model_calls_by_role={"red_planner": 8, "red_mutator": 4},
        max_total_output_tokens=4096,
        max_output_tokens_by_role={"red_planner": 2048, "red_mutator": 1024},
        max_image_generations=0,
        wall_clock_seconds=300,
        max_non_progress_attempts=2,
    )
    return BudgetConfigDocument(
        version=1,
        default_profile="agent",
        profiles={"agent": budget},
        policy=RuntimePolicy(),
    )


def _models() -> ModelsConfig:
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
                    "max_output_tokens": 128,
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "max_output_tokens": 96,
                },
            },
        }
    )


def test_fixture_and_nonfixture_cases_cannot_share_one_campaign_fingerprint() -> None:
    plan = CampaignPlan(
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        budget_profile="agent",
        red_policy=RedPolicyKind.ADAPTIVE,
        session_mode=SessionMode.TARGET_MANAGED,
    )

    preflight = preflight_campaign(
        plan=plan,
        cases=(
            _case("fixture-case", fixture=True),
            _case("ordinary-case", fixture=False),
        ),
        budgets=_budgets(),
        models=_models(),
        fixture_runner_available=True,
    )

    errors = {
        issue.code for issue in preflight.issues if issue.severity == PreflightSeverity.ERROR
    }
    assert "MIXED_FIXTURE_CAMPAIGN_UNSUPPORTED" in errors
    assert preflight.ready is False
