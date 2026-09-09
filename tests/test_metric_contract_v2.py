from llm_redteam.domain import CampaignBudget


def test_campaign_budget_accepts_role_specific_inference_limits() -> None:
    budget = CampaignBudget(
        max_attacks=2,
        max_generations=1,
        max_turns_per_attack=4,
        max_model_calls=10,
        max_model_calls_by_role={"red_planner": 6, "red_mutator": 3},
        max_total_output_tokens=5000,
        max_output_tokens_by_role={"red_planner": 3000, "red_mutator": 1500},
        max_image_generations=0,
        wall_clock_seconds=300,
    )

    assert budget.max_model_calls_by_role["red_planner"] == 6
    assert budget.max_output_tokens_by_role["red_mutator"] == 1500
