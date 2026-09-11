import pytest

from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.multiturn_metrics import (
    summarize_multi_turn,
    summarize_time_to_violation,
)
from llm_redteam.targets.base import SessionMode


def _run(
    *,
    turns: int,
    success_at: int | None = None,
    depths: tuple[int, ...] | None = None,
    execution_id: str,
) -> ConversationRunResult:
    resolved_depths = depths or tuple(range(1, turns + 1))
    if len(resolved_depths) != turns:
        raise ValueError("depth count must match turns")

    successful = success_at is not None
    rows = tuple(
        ConversationTurn(
            turn_id=f"{execution_id}-turn-{ordinal}",
            ordinal=ordinal,
            depth=resolved_depths[ordinal - 1],
            branch_id="main",
            attacker_message=f"synthetic probe {ordinal}",
            target_response="synthetic response",
            outcome=(
                CompromiseOutcome.MODEL_COMPROMISE
                if successful and ordinal == success_at
                else CompromiseOutcome.PASS
            ),
        )
        for ordinal in range(1, turns + 1)
    )
    return ConversationRunResult(
        execution=ExecutionResult(
            execution_id=execution_id,
            attack_id="synthetic-sequence-case",
            target_id="synthetic-target",
            outcome=(
                CompromiseOutcome.MODEL_COMPROMISE
                if successful
                else CompromiseOutcome.PASS
            ),
            objective_violated=successful,
            model_compromise=successful,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id=f"conversation-{execution_id}",
        session_mode=SessionMode.REPLAY,
        turns=rows,
        backtracks=0,
        branches=1,
        first_violation_turn_id=(
            f"{execution_id}-turn-{success_at}" if success_at is not None else None
        ),
        first_violation_ordinal=success_at,
        first_violation_depth=(
            resolved_depths[success_at - 1] if success_at is not None else None
        ),
        first_model_compromise_turn_id=(
            f"{execution_id}-turn-{success_at}" if success_at is not None else None
        ),
        first_model_compromise_ordinal=success_at,
        first_model_compromise_depth=(
            resolved_depths[success_at - 1] if success_at is not None else None
        ),
        flow_fingerprint="synthetic-flow-v1",
    )


def _unresolved_run() -> ConversationRunResult:
    return ConversationRunResult(
        execution=ExecutionResult(
            execution_id="unresolved",
            attack_id="synthetic-sequence-case",
            target_id="synthetic-target",
            outcome=CompromiseOutcome.INCONCLUSIVE,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=0.0,
        ),
        conversation_id="conversation-unresolved",
        session_mode=SessionMode.REPLAY,
        turns=(
            ConversationTurn(
                turn_id="unresolved-turn-1",
                ordinal=1,
                depth=1,
                branch_id="main",
                attacker_message="synthetic probe",
                target_response=None,
                outcome=CompromiseOutcome.INCONCLUSIVE,
            ),
        ),
        backtracks=0,
        branches=1,
        flow_fingerprint="synthetic-flow-v1",
    )


def test_time_to_violation_accounts_for_right_censored_conversations() -> None:
    runs = (
        _run(turns=2, success_at=2, execution_id="success-2"),
        _run(turns=2, execution_id="censored-2"),
        _run(turns=4, success_at=4, execution_id="success-4"),
        _run(turns=4, execution_id="censored-4"),
    )

    metrics = summarize_multi_turn(runs)

    assert metrics.median_turns_to_first_violation == 3.0
    estimate = metrics.target_call_time_to_violation
    assert estimate.observations == 4
    assert estimate.events == 2
    assert estimate.censored == 2
    assert estimate.median_exposure_to_violation == 4.0

    first, second = estimate.curve
    assert (first.exposure, first.at_risk, first.events, first.censored) == (2, 4, 1, 1)
    assert first.cumulative_violation == pytest.approx(0.25)
    assert (second.exposure, second.at_risk, second.events, second.censored) == (4, 2, 1, 1)
    assert second.cumulative_violation == pytest.approx(0.625)
    assert 0.0 <= second.ci_low <= second.cumulative_violation <= second.ci_high <= 1.0


def test_target_call_and_path_depth_curves_remain_distinct_after_branching() -> None:
    runs = (
        _run(
            turns=3,
            success_at=3,
            depths=(1, 2, 2),
            execution_id="branched-success",
        ),
        _run(
            turns=3,
            depths=(1, 2, 2),
            execution_id="branched-pass",
        ),
    )

    metrics = summarize_multi_turn(runs)

    assert metrics.target_call_time_to_violation.curve[-1].exposure == 3
    assert metrics.path_depth_time_to_violation.curve[-1].exposure == 2
    assert metrics.target_call_time_to_violation.median_exposure_to_violation == 3.0
    assert metrics.path_depth_time_to_violation.median_exposure_to_violation == 2.0


def test_unresolved_conversations_are_reported_and_excluded_from_survival_estimate() -> None:
    successful = _run(turns=2, success_at=2, execution_id="success")
    metrics = summarize_multi_turn((successful, _unresolved_run()))

    assert metrics.total_conversations == 2
    assert metrics.valid_conversations == 1
    assert metrics.unresolved_conversations == 1
    assert metrics.target_call_time_to_violation.observations == 1

    with pytest.raises(ValueError, match="conclusive"):
        summarize_time_to_violation((_unresolved_run(),), axis="target_calls")
