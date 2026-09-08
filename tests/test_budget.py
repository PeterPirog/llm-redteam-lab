import pytest

from llm_redteam.budget import BudgetExceeded, BudgetLedger
from llm_redteam.domain import CampaignBudget


def _budget() -> CampaignBudget:
    return CampaignBudget(
        max_attacks=2,
        max_generations=2,
        max_turns_per_attack=3,
        max_model_calls=2,
        max_total_output_tokens=100,
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


def test_model_call_reserves_token_budget_atomically() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(expected_output_tokens=60)

    with pytest.raises(BudgetExceeded):
        ledger.reserve_model_call(expected_output_tokens=50)

    snapshot = ledger.snapshot()
    assert snapshot.model_calls == 1
    assert snapshot.output_tokens == 60


def test_actual_token_count_can_consume_remaining_budget() -> None:
    ledger = BudgetLedger(_budget())
    ledger.reserve_model_call(expected_output_tokens=40)
    ledger.record_actual_output_tokens(reserved=40, actual=70)
    assert ledger.snapshot().output_tokens == 70

    with pytest.raises(BudgetExceeded):
        ledger.reserve_model_call(expected_output_tokens=31)


def test_non_progress_limit_resets_after_progress() -> None:
    ledger = BudgetLedger(_budget())
    ledger.record_progress(made_progress=False)
    ledger.record_progress(made_progress=False)
    ledger.record_progress(made_progress=True)
    ledger.record_progress(made_progress=False)

    assert ledger.snapshot().non_progress_attempts == 1
