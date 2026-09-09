import asyncio
from collections import deque

import pytest

from llm_redteam.domain import CompromiseOutcome, ExecutionResult, FindingStatus
from llm_redteam.reproduction import ReproductionPolicy, reproduce_finding


def _execution(
    execution_id: str,
    outcome: CompromiseOutcome,
) -> ExecutionResult:
    if outcome == CompromiseOutcome.MODEL_COMPROMISE:
        return ExecutionResult(
            execution_id=execution_id,
            attack_id="attack-1",
            target_id="target-1",
            outcome=outcome,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        )
    if outcome == CompromiseOutcome.PASS:
        return ExecutionResult(
            execution_id=execution_id,
            attack_id="attack-1",
            target_id="target-1",
            outcome=outcome,
            objective_violated=False,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
        )
    if outcome == CompromiseOutcome.ERROR:
        return ExecutionResult(
            execution_id=execution_id,
            attack_id="attack-1",
            target_id="target-1",
            outcome=outcome,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
            error_kind="controlled_test_error",
        )
    return ExecutionResult(
        execution_id=execution_id,
        attack_id="attack-1",
        target_id="target-1",
        outcome=CompromiseOutcome.INCONCLUSIVE,
        objective_violated=None,
        model_compromise=False,
        system_compromise=False,
        confidence=0.0,
    )


async def _run_sequence(outcomes: list[CompromiseOutcome]):
    queue = deque(outcomes)

    async def runner() -> ExecutionResult:
        index = len(outcomes) - len(queue) + 1
        return _execution(f"repeat-{index}", queue.popleft())

    initial = _execution("initial", CompromiseOutcome.MODEL_COMPROMISE)
    return await reproduce_finding(
        initial,
        runner,
        policy=ReproductionPolicy(repetitions=len(outcomes), min_reproducible_successes=2),
    )


def test_three_successful_reproductions_confirm_finding() -> None:
    result = asyncio.run(
        _run_sequence([CompromiseOutcome.MODEL_COMPROMISE] * 3)
    )

    assert result.status == FindingStatus.CONFIRMED
    assert result.successful_reproductions == 3
    assert result.conclusive_attempts == 3
    assert result.unresolved_attempts == 0
    assert result.reproduction_rate.value == 1.0


def test_two_of_three_successes_are_reproducible_not_confirmed() -> None:
    result = asyncio.run(
        _run_sequence(
            [
                CompromiseOutcome.MODEL_COMPROMISE,
                CompromiseOutcome.PASS,
                CompromiseOutcome.MODEL_COMPROMISE,
            ]
        )
    )

    assert result.status == FindingStatus.REPRODUCIBLE
    assert result.successful_reproductions == 2
    assert result.reproduction_rate.trials == 3


def test_one_of_three_successes_is_flaky() -> None:
    result = asyncio.run(
        _run_sequence(
            [
                CompromiseOutcome.PASS,
                CompromiseOutcome.MODEL_COMPROMISE,
                CompromiseOutcome.PASS,
            ]
        )
    )

    assert result.status == FindingStatus.FLAKY
    assert result.successful_reproductions == 1


def test_measurement_errors_are_unresolved_not_defense_successes() -> None:
    result = asyncio.run(
        _run_sequence(
            [
                CompromiseOutcome.ERROR,
                CompromiseOutcome.INCONCLUSIVE,
                CompromiseOutcome.ERROR,
            ]
        )
    )

    assert result.status == FindingStatus.SINGLE_OBSERVATION
    assert result.conclusive_attempts == 0
    assert result.unresolved_attempts == 3
    assert result.reproduction_rate.value is None
    assert result.reproduction_rate.trials == 0


def test_reproduction_rejects_non_successful_initial_execution() -> None:
    initial = _execution("initial-pass", CompromiseOutcome.PASS)

    async def runner() -> ExecutionResult:
        return _execution("repeat", CompromiseOutcome.MODEL_COMPROMISE)

    with pytest.raises(ValueError, match="initial objective-violating"):
        asyncio.run(reproduce_finding(initial, runner))


def test_reproduction_policy_rejects_impossible_threshold() -> None:
    with pytest.raises(ValueError, match="cannot exceed repetitions"):
        ReproductionPolicy(repetitions=2, min_reproducible_successes=3)
