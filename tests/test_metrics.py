from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.metrics import summarize_campaign, wilson_rate


def _result(
    execution_id: str,
    outcome: CompromiseOutcome,
    objective_violated: bool | None,
    model_compromise: bool,
    system_compromise: bool,
    *,
    error_kind: str | None = None,
) -> ExecutionResult:
    return ExecutionResult(
        execution_id=execution_id,
        attack_id="A-1",
        target_id="T-1",
        outcome=outcome,
        objective_violated=objective_violated,
        model_compromise=model_compromise,
        system_compromise=system_compromise,
        confidence=1.0,
        error_kind=error_kind,
    )


def test_zero_trials_is_no_evidence_not_zero_risk() -> None:
    estimate = wilson_rate(0, 0)
    assert estimate.value is None
    assert estimate.ci_low is None
    assert estimate.ci_high is None


def test_wilson_interval_contains_point_estimate() -> None:
    estimate = wilson_rate(5, 10)
    assert estimate.value == 0.5
    assert estimate.ci_low is not None
    assert estimate.ci_high is not None
    assert estimate.ci_low < estimate.value < estimate.ci_high


def test_campaign_metrics_keep_asr_mcr_scr_separate() -> None:
    rows = [
        _result("E1", CompromiseOutcome.PASS, False, False, False),
        _result("E2", CompromiseOutcome.MODEL_COMPROMISE, True, True, False),
        _result("E3", CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE, True, True, True),
        _result("E4", CompromiseOutcome.SYSTEM_COMPROMISE, True, False, True),
        _result("E5", CompromiseOutcome.PARTIAL, None, False, False),
        _result(
            "E6",
            CompromiseOutcome.ERROR,
            None,
            False,
            False,
            error_kind="provider_timeout",
        ),
    ]

    metrics = summarize_campaign(rows)

    assert metrics.total_executions == 6
    assert metrics.valid_executions == 4
    assert metrics.attack_success_rate.successes == 3
    assert metrics.attack_success_rate.trials == 4
    assert metrics.attack_success_rate.value == 0.75
    assert metrics.model_compromise_rate.value == 0.5
    assert metrics.system_compromise_rate.value == 0.5
    assert metrics.model_to_system_escalation_rate.value == 0.5
    assert metrics.unresolved_rate.successes == 2
    assert metrics.unresolved_rate.trials == 6
