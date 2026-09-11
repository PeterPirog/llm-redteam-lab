import pytest

from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.multiturn_metrics import (
    summarize_layer_time_to_compromise,
    summarize_multi_turn,
)
from llm_redteam.targets.base import SessionMode


def _run(
    *,
    execution_id: str,
    turns: int,
    model_at: int | None = None,
    system_at: int | None = None,
    depths: tuple[int, ...] | None = None,
    unresolved: bool = False,
) -> ConversationRunResult:
    resolved_depths = depths or tuple(range(1, turns + 1))
    if len(resolved_depths) != turns:
        raise ValueError("depth count must match turns")
    if model_at is not None and not 1 <= model_at <= turns:
        raise ValueError("model_at must identify an observed turn")
    if system_at is not None and not 1 <= system_at <= turns:
        raise ValueError("system_at must identify an observed turn")

    model_compromise = model_at is not None
    system_compromise = system_at is not None
    if unresolved:
        outcome = CompromiseOutcome.PARTIAL
        objective_violated = None
    elif model_compromise and system_compromise:
        outcome = CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
        objective_violated = True
    elif model_compromise:
        outcome = CompromiseOutcome.MODEL_COMPROMISE
        objective_violated = True
    elif system_compromise:
        outcome = CompromiseOutcome.SYSTEM_COMPROMISE
        objective_violated = True
    else:
        outcome = CompromiseOutcome.PASS
        objective_violated = False

    first_violation = min(
        (value for value in (model_at, system_at) if value is not None),
        default=None,
    )
    rows = []
    for ordinal in range(1, turns + 1):
        if model_at is not None and ordinal >= model_at:
            turn_model = True
        else:
            turn_model = False
        if system_at is not None and ordinal >= system_at:
            turn_system = True
        else:
            turn_system = False
        if turn_model and turn_system:
            turn_outcome = CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
        elif turn_model:
            turn_outcome = CompromiseOutcome.MODEL_COMPROMISE
        elif turn_system:
            turn_outcome = CompromiseOutcome.SYSTEM_COMPROMISE
        else:
            turn_outcome = CompromiseOutcome.PASS
        rows.append(
            ConversationTurn(
                turn_id=f"{execution_id}-turn-{ordinal}",
                ordinal=ordinal,
                depth=resolved_depths[ordinal - 1],
                branch_id="main",
                attacker_message=f"probe {ordinal}",
                target_response="synthetic target response",
                outcome=turn_outcome,
            )
        )

    return ConversationRunResult(
        execution=ExecutionResult(
            execution_id=execution_id,
            attack_id="layer-aware-case",
            target_id="agent-target",
            outcome=outcome,
            objective_violated=objective_violated,
            model_compromise=model_compromise,
            system_compromise=system_compromise,
            confidence=1.0,
        ),
        conversation_id=f"conversation-{execution_id}",
        session_mode=SessionMode.TARGET_MANAGED,
        turns=tuple(rows),
        backtracks=0,
        branches=1,
        first_violation_turn_id=(
            f"{execution_id}-turn-{first_violation}"
            if first_violation is not None
            else None
        ),
        first_violation_ordinal=first_violation,
        first_violation_depth=(
            resolved_depths[first_violation - 1]
            if first_violation is not None
            else None
        ),
        first_model_compromise_turn_id=(
            f"{execution_id}-turn-{model_at}" if model_at is not None else None
        ),
        first_model_compromise_ordinal=model_at,
        first_model_compromise_depth=(
            resolved_depths[model_at - 1] if model_at is not None else None
        ),
        first_system_compromise_turn_id=(
            f"{execution_id}-turn-{system_at}" if system_at is not None else None
        ),
        first_system_compromise_ordinal=system_at,
        first_system_compromise_depth=(
            resolved_depths[system_at - 1] if system_at is not None else None
        ),
        flow_fingerprint="layer-aware-flow-v1",
    )


def test_model_and_system_compromise_have_distinct_rates_and_time_curves() -> None:
    escalated = _run(
        execution_id="escalated",
        turns=4,
        model_at=2,
        system_at=4,
    )
    contained = _run(
        execution_id="contained",
        turns=4,
        model_at=2,
    )

    metrics = summarize_multi_turn((escalated, contained))

    assert metrics.model_compromise_rate.value == pytest.approx(1.0)
    assert metrics.system_compromise_rate.value == pytest.approx(0.5)
    assert metrics.model_to_system_escalation_rate.value == pytest.approx(0.5)

    model_curve = metrics.model_target_call_time_to_compromise
    assert (model_curve.events, model_curve.censored, model_curve.unresolved) == (2, 0, 0)
    assert model_curve.median_exposure_to_compromise == 2.0

    system_curve = metrics.system_target_call_time_to_compromise
    assert (system_curve.events, system_curve.censored, system_curve.unresolved) == (1, 1, 0)
    assert system_curve.curve[-1].exposure == 4
    assert system_curve.curve[-1].cumulative_violation == pytest.approx(0.5)
    assert system_curve.median_exposure_to_compromise == 4.0


def test_known_model_compromise_survives_partial_while_system_remains_unresolved() -> None:
    partial = _run(
        execution_id="partial-model-known",
        turns=3,
        model_at=2,
        unresolved=True,
    )

    model = summarize_layer_time_to_compromise(
        (partial,),
        layer="model",
        axis="target_calls",
    )
    system = summarize_layer_time_to_compromise(
        (partial,),
        layer="system",
        axis="target_calls",
    )

    assert (model.observations, model.events, model.censored, model.unresolved) == (1, 1, 0, 0)
    assert model.median_exposure_to_compromise == 2.0
    assert (system.observations, system.events, system.censored, system.unresolved) == (0, 0, 0, 1)
    assert system.curve == ()


def test_layer_target_call_and_path_depth_axes_remain_distinct() -> None:
    branched_shape = _run(
        execution_id="branch-shaped",
        turns=4,
        model_at=3,
        system_at=4,
        depths=(1, 2, 2, 3),
    )

    metrics = summarize_multi_turn((branched_shape,))

    assert metrics.model_target_call_time_to_compromise.curve[-1].exposure == 3
    assert metrics.model_path_depth_time_to_compromise.curve[-1].exposure == 2
    assert metrics.system_target_call_time_to_compromise.curve[-1].exposure == 4
    assert metrics.system_path_depth_time_to_compromise.curve[-1].exposure == 3


def test_positive_layer_without_first_compromise_metadata_fails_closed() -> None:
    compromised = _run(
        execution_id="missing-layer-metadata",
        turns=2,
        model_at=2,
    )
    broken = compromised.model_copy(
        update={
            "first_model_compromise_turn_id": None,
            "first_model_compromise_ordinal": None,
            "first_model_compromise_depth": None,
        }
    )

    with pytest.raises(ValueError, match="first-model-compromise"):
        summarize_layer_time_to_compromise(
            (broken,),
            layer="model",
            axis="target_calls",
        )
