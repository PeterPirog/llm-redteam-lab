import pytest

from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.evaluation_protocol import (
    CampaignPurpose,
    MeasurementProtocol,
    discovery_protocol,
    held_out_evaluation_protocol,
    summarize_discovery,
    summarize_evaluation,
)


def _execution(index: int, outcome: CompromiseOutcome) -> ExecutionResult:
    compromised = outcome == CompromiseOutcome.MODEL_COMPROMISE
    if outcome == CompromiseOutcome.ERROR:
        return ExecutionResult(
            execution_id=f"exec-{index}",
            attack_id=f"attack-{index}",
            target_id="target",
            outcome=outcome,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
            error_kind="synthetic_error",
        )
    return ExecutionResult(
        execution_id=f"exec-{index}",
        attack_id=f"attack-{index}",
        target_id="target",
        outcome=outcome,
        objective_violated=compromised,
        model_compromise=compromised,
        system_compromise=False,
        confidence=1.0,
    )


def test_discovery_reports_observed_yield_without_claiming_comparable_blue_asr() -> None:
    rows = (
        _execution(1, CompromiseOutcome.PASS),
        _execution(2, CompromiseOutcome.MODEL_COMPROMISE),
        _execution(3, CompromiseOutcome.ERROR),
    )

    metrics = summarize_discovery(rows)

    assert metrics.total_executions == 3
    assert metrics.conclusive_executions == 2
    assert metrics.objective_violations_observed == 1
    assert metrics.observed_violation_rate.value == 0.5
    assert metrics.unresolved_rate.value == pytest.approx(1 / 3)
    assert metrics.comparable_blue_estimate is False


def test_evaluation_protocol_rejects_learning_from_same_campaign() -> None:
    with pytest.raises(ValueError, match="cannot learn"):
        MeasurementProtocol(
            purpose=CampaignPurpose.EVALUATION,
            attack_policy_frozen_across_trials=True,
            learns_from_current_campaign_outcomes=True,
            held_out_cases=True,
            target_snapshot_pinned=True,
        )


def test_evaluation_protocol_requires_frozen_held_out_pinned_conditions() -> None:
    invalid = (
        {
            "attack_policy_frozen_across_trials": False,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": True,
            "target_snapshot_pinned": True,
        },
        {
            "attack_policy_frozen_across_trials": True,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": False,
            "target_snapshot_pinned": True,
        },
        {
            "attack_policy_frozen_across_trials": True,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": True,
            "target_snapshot_pinned": False,
        },
    )
    for values in invalid:
        with pytest.raises(ValueError):
            MeasurementProtocol(purpose=CampaignPurpose.EVALUATION, **values)


def test_held_out_evaluation_is_allowed_to_report_comparable_blue_metrics() -> None:
    rows = (
        _execution(1, CompromiseOutcome.PASS),
        _execution(2, CompromiseOutcome.MODEL_COMPROMISE),
    )
    protocol = held_out_evaluation_protocol()

    report = summarize_evaluation(rows, protocol)

    assert report.comparable_blue_estimate is True
    assert report.protocol.purpose == CampaignPurpose.EVALUATION
    assert report.campaign.attack_success_rate.value == 0.5
    assert report.campaign.attack_success_rate.trials == 2


def test_discovery_protocol_cannot_be_used_for_comparative_blue_metrics() -> None:
    with pytest.raises(ValueError, match="EVALUATION"):
        summarize_evaluation(
            (_execution(1, CompromiseOutcome.MODEL_COMPROMISE),),
            discovery_protocol(),
        )
