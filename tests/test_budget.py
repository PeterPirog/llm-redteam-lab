import pytest

from llm_redteam.budget import BudgetExceeded, BudgetLedger
from llm_redteam.domain import CampaignBudget


def _budget() -> CampaignBudget:
    return CampaignBudget(
        max_attacks=2,
        max_generations=2,
        max_turns_per_attack=3,
        max_model_calls=4,
        max_model_calls_by_role={"red_planner": 2, "red_mutator": 1},
        max_total_output_tokens=200,
        max_output_tokens_by_role={"red_planner": 100, "red_mutator": 40},
        max_image_generations=1,
        wall_clock_seconds=60,
        max_non_progress_attempts=2,
    )


def test_attack_budget_fails_closed_before_exceeding_limit() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_attack()
    ledger.reserve_attack()

    with pytest.raises(BudgetExceeded):
        ledger.reserve_attack()

    assert ledger.snapshot().attacks == 2


def test_turn_budget_is_enforced_per_attack_not_globally() -> None:
    ledger = BudgetLedger(_budget())
    for _ in range(3):
        ledger.reserve_turn(attack_id="attack-a")
    for _ in range(3):
        ledger.reserve_turn(attack_id="attack-b")

    with pytest.raises(BudgetExceeded):
        ledger.reserve_turn(attack_id="attack-a")

    snapshot = ledger.snapshot()
    assert snapshot.turns == 6
    assert snapshot.turns_by_attack == (("attack-a", 3), ("attack-b", 3))


def test_model_call_reserves_token_budget_atomically() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(expected_output_tokens=120)

    with pytest.raises(BudgetExceeded):
        ledger.reserve_model_call(expected_output_tokens=90)

    snapshot = ledger.snapshot()
    assert snapshot.model_calls == 1
    assert snapshot.output_tokens == 120


def test_role_specific_model_call_limit_fails_closed() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(role="red_planner", expected_output_tokens=30)
    ledger.reserve_model_call(role="red_planner", expected_output_tokens=30)

    with pytest.raises(BudgetExceeded):
        ledger.reserve_model_call(role="red_planner", expected_output_tokens=10)

    snapshot = ledger.snapshot()
    assert snapshot.model_calls_by_role == (("red_planner", 2),)
    assert snapshot.output_tokens_by_role == (("red_planner", 60),)


def test_role_specific_output_token_limit_fails_closed() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(role="red_mutator", expected_output_tokens=30)

    with pytest.raises(BudgetExceeded):
        ledger.record_actual_output_tokens(
            role="red_mutator",
            reserved=30,
            actual=41,
        )

    assert ledger.snapshot().output_tokens_by_role == (("red_mutator", 30),)


def test_actual_token_count_can_consume_remaining_budget() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(expected_output_tokens=40)
    ledger.record_actual_output_tokens(reserved=40, actual=70)
    assert ledger.snapshot().output_tokens == 70

    with pytest.raises(BudgetExceeded):
        ledger.reserve_model_call(expected_output_tokens=131)


def test_non_progress_limit_resets_after_progress() -> None:
    ledger = BudgetLedger(_budget())
    ledger.record_progress(made_progress=False)
    ledger.record_progress(made_progress=False)
    ledger.record_progress(made_progress=True)
    ledger.record_progress(made_progress=False)

    assert ledger.snapshot().non_progress_attempts == 1
