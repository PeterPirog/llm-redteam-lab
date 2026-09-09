from llm_redteam.red.adaptive import RedLearningRecord
from llm_redteam.red.sequence_metrics import summarize_red_sequences


def _record(
    *,
    steps: tuple[str, ...],
    successful: bool,
    ordinal: int | None = None,
    depth: int | None = None,
) -> RedLearningRecord:
    return RedLearningRecord(
        attack_family="multi_turn_escalation",
        tactics=tuple(step.split(":", 1)[-1] for step in steps),
        phase_tactics=steps,
        successful=successful,
        error=False,
        target_interactions=len(steps),
        backtracks=0,
        first_violation_ordinal=ordinal,
        first_violation_depth=depth,
    )


def test_sequence_metrics_keep_adaptive_search_separate_from_blue_asr() -> None:
    strong = (
        "primer:context_probe",
        "planner:state_shift",
        "finisher:objective_probe",
    )
    weak = (
        "primer:context_probe",
        "planner:repeat_probe",
        "finisher:objective_probe",
    )
    metrics = summarize_red_sequences(
        (
            _record(steps=strong, successful=True, ordinal=3, depth=3),
            _record(steps=strong, successful=True, ordinal=3, depth=3),
            _record(steps=weak, successful=False),
        )
    )

    assert metrics.records == 3
    assert metrics.successful_records == 2
    assert metrics.comparable_blue_estimate is False
    assert metrics.median_turn_to_success == 3.0
    assert metrics.median_depth_to_success == 3.0

    best = metrics.sequence_summaries[0]
    assert best.signature == ">".join(strong)
    assert best.successes == 2
    assert best.attempts == 2
    assert best.observed_success_rate.value == 1.0
    assert best.observed_success_rate.ci_low is not None
    assert best.observed_success_rate.ci_low < 1.0


def test_transition_metrics_preserve_order() -> None:
    metrics = summarize_red_sequences(
        (
            _record(
                steps=("primer:a", "planner:b", "finisher:c"),
                successful=True,
                ordinal=3,
                depth=3,
            ),
            _record(
                steps=("primer:a", "planner:c", "finisher:b"),
                successful=False,
            ),
        )
    )
    signatures = {row.signature for row in metrics.transition_summaries}
    assert "primer:a->planner:b" in signatures
    assert "planner:b->finisher:c" in signatures
    assert "primer:a->planner:c" in signatures
    assert "planner:c->finisher:b" in signatures
