from llm_redteam.red import AttackObservation
from llm_redteam.red.metrics import summarize_red_history


def test_red_metrics_report_search_efficiency_and_family_rates() -> None:
    history = (
        AttackObservation(
            attack_id="A1",
            hypothesis_id="H1",
            attack_family="family-a",
            generation=0,
            objective_violated=False,
            model_compromise=False,
            system_compromise=False,
            novelty_score=1.0,
        ),
        AttackObservation(
            attack_id="A2",
            hypothesis_id="H2",
            attack_family="family-b",
            generation=0,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            novelty_score=0.8,
        ),
        AttackObservation(
            attack_id="A3",
            parent_attack_id="A2",
            hypothesis_id="H3",
            attack_family="family-b",
            generation=1,
            objective_violated=True,
            model_compromise=True,
            system_compromise=True,
            novelty_score=0.6,
        ),
    )

    metrics = summarize_red_history(history)

    assert metrics.total_attempts == 3
    assert metrics.unique_families_tried == 2
    assert metrics.successful_families == 1
    assert metrics.first_violation_attempt == 2

    family_b = next(item for item in metrics.family_summaries if item.family == "family-b")
    assert family_b.attack_success_rate.value == 1.0
    assert family_b.attack_success_rate.trials == 2
    assert family_b.mean_novelty == 0.7
