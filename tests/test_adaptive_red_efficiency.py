from llm_redteam.budget import BudgetSnapshot
from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.red.efficiency import summarize_adaptive_red
from llm_redteam.targets.base import SessionMode


def _turn(ordinal: int) -> ConversationTurn:
    return ConversationTurn(
        turn_id=f"turn-{ordinal}",
        ordinal=ordinal,
        depth=ordinal,
        branch_id="b0",
        parent_turn_id=f"turn-{ordinal - 1}" if ordinal > 1 else None,
        attacker_message=f"synthetic probe {ordinal}",
        target_response="controlled response",
        outcome=CompromiseOutcome.PASS,
    )


def _result(
    *,
    conversation_id: str,
    turns: int,
    success_at: int | None,
    backtracks: int = 0,
    branches: int = 1,
) -> ConversationRunResult:
    successful = success_at is not None
    execution = ExecutionResult(
        execution_id=f"exec-{conversation_id}",
        attack_id="case-1",
        target_id="target-1",
        outcome=(
            CompromiseOutcome.MODEL_COMPROMISE
            if successful
            else CompromiseOutcome.PASS
        ),
        objective_violated=successful,
        model_compromise=successful,
        system_compromise=False,
        confidence=1.0,
    )
    return ConversationRunResult(
        execution=execution,
        conversation_id=conversation_id,
        session_mode=SessionMode.REPLAY,
        turns=tuple(_turn(index) for index in range(1, turns + 1)),
        backtracks=backtracks,
        branches=branches,
        first_violation_turn_id=f"turn-{success_at}" if success_at else None,
        first_violation_ordinal=success_at,
        first_violation_depth=success_at,
        flow_fingerprint="flow-test",
    )


def test_adaptive_efficiency_separates_success_from_query_cost() -> None:
    results = (
        _result(conversation_id="a", turns=4, success_at=3, backtracks=1, branches=2),
        _result(conversation_id="b", turns=2, success_at=None),
    )
    budget = BudgetSnapshot(
        attacks=2,
        generations=1,
        turns=6,
        turns_by_attack=(("a", 4), ("b", 2)),
        model_calls=8,
        model_calls_by_role=(("red_mutator", 2), ("red_planner", 6)),
        output_tokens=1000,
        output_tokens_by_role=(("red_mutator", 250), ("red_planner", 750)),
        image_generations=0,
        non_progress_attempts=0,
        elapsed_seconds=5.0,
    )

    metrics = summarize_adaptive_red(results, budget)

    assert metrics.conversations == 2
    assert metrics.conclusive_conversations == 2
    assert metrics.successful_conversations == 1
    assert metrics.target_interactions == 6
    assert metrics.backtracks == 1
    assert metrics.branches_created == 1
    assert metrics.successes_per_100_target_interactions == 100.0 / 6.0
    assert metrics.mean_target_interactions_per_conversation == 3.0
    assert metrics.median_target_interactions_to_success == 3.0
    assert metrics.median_first_violation_depth == 3.0
    assert metrics.planner_calls == 6
    assert metrics.mutator_calls == 2
    assert metrics.planner_output_tokens == 750
    assert metrics.mutator_output_tokens == 250


def test_empty_efficiency_dataset_reports_unavailable_rates() -> None:
    budget = BudgetSnapshot(
        attacks=0,
        generations=0,
        turns=0,
        turns_by_attack=(),
        model_calls=0,
        model_calls_by_role=(),
        output_tokens=0,
        output_tokens_by_role=(),
        image_generations=0,
        non_progress_attempts=0,
        elapsed_seconds=0.0,
    )

    metrics = summarize_adaptive_red((), budget)

    assert metrics.successes_per_100_target_interactions is None
    assert metrics.mean_target_interactions_per_conversation is None
    assert metrics.median_target_interactions_to_success is None
    assert metrics.median_first_violation_depth is None
