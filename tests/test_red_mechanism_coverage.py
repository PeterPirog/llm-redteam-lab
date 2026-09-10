import pytest

from llm_redteam.campaigns.multiturn import ConversationBudget
from llm_redteam.red.coverage import (
    RedCoveragePolicy,
    RedCoverageStatus,
    assess_red_coverage,
    eligible_mechanisms_for_runtime,
    summarize_mechanism_coverage,
)
from llm_redteam.red.mechanisms import AttackMechanism, MechanismMemorySnapshot
from llm_redteam.targets.base import SessionMode


def _snapshot(
    *,
    trials: int = 6,
    mechanism_trials: dict[str, int] | None = None,
    mechanism_successes: dict[str, int] | None = None,
    transitions: dict[str, int] | None = None,
    sequences: dict[str, int] | None = None,
) -> MechanismMemorySnapshot:
    return MechanismMemorySnapshot(
        attack_family="multi_turn_escalation",
        trials=trials,
        successes=2,
        errors=0,
        target_interactions=12,
        mechanism_trials=mechanism_trials or {},
        mechanism_successes=mechanism_successes or {},
        transition_trials=transitions or {},
        transition_successes={},
        sequence_trials=sequences or {},
        sequence_successes={},
    )


def test_coverage_exposes_blind_spots_without_becoming_blue_asr() -> None:
    eligible = (
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.SEMANTIC_REFRAMING,
        AttackMechanism.CROSS_TURN_COMPOSITION,
        AttackMechanism.OBJECTIVE_PROBE,
    )
    snapshot = _snapshot(
        mechanism_trials={
            "context_accumulation": 4,
            "semantic_reframing": 2,
            "objective_probe": 1,
        },
        mechanism_successes={
            "context_accumulation": 2,
            "objective_probe": 1,
        },
        transitions={
            "context_accumulation->semantic_reframing": 2,
            "semantic_reframing->objective_probe": 1,
        },
        sequences={
            "context_accumulation>semantic_reframing>objective_probe": 1,
        },
    )

    report = summarize_mechanism_coverage((snapshot,), eligible_mechanisms=eligible)

    assert report.conversations == 6
    assert report.mechanism_coverage_ratio == 0.75
    assert report.successful_mechanism_coverage_ratio == 0.5
    assert report.unobserved_mechanisms == (AttackMechanism.CROSS_TURN_COMPOSITION,)
    assert report.unique_transition_signatures == 2
    assert report.unique_sequence_signatures == 1
    assert report.max_mechanism_exposure_share == pytest.approx(4 / 7)
    assert 0.0 < report.normalized_exposure_entropy < 1.0
    assert report.effective_mechanism_count > 2.0
    assert report.comparable_blue_estimate is False


def test_predeclared_coverage_policy_rejects_local_optimum_blind_spot() -> None:
    eligible = (
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.SEMANTIC_REFRAMING,
        AttackMechanism.CROSS_TURN_COMPOSITION,
    )
    report = summarize_mechanism_coverage(
        (
            _snapshot(
                mechanism_trials={
                    "context_accumulation": 9,
                    "semantic_reframing": 1,
                },
                mechanism_successes={"context_accumulation": 4},
            ),
        ),
        eligible_mechanisms=eligible,
    )
    policy = RedCoveragePolicy(
        required_mechanisms=eligible,
        min_conversation_exposures_per_mechanism=1,
        max_single_mechanism_exposure_share=0.8,
        min_normalized_exposure_entropy=0.45,
    )

    assessment = assess_red_coverage(report, policy=policy)

    assert assessment.status == RedCoverageStatus.INCOMPLETE
    assert any("cross_turn_composition" in reason for reason in assessment.reasons)
    assert any("concentration" in reason for reason in assessment.reasons)
    assert assessment.comparable_blue_estimate is False


def test_balanced_required_mechanisms_can_be_ready_for_later_evaluation() -> None:
    eligible = (
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.SEMANTIC_REFRAMING,
        AttackMechanism.CROSS_TURN_COMPOSITION,
    )
    report = summarize_mechanism_coverage(
        (
            _snapshot(
                mechanism_trials={
                    "context_accumulation": 3,
                    "semantic_reframing": 3,
                    "cross_turn_composition": 3,
                },
                transitions={
                    "context_accumulation->semantic_reframing": 2,
                    "semantic_reframing->cross_turn_composition": 2,
                },
                sequences={
                    "context_accumulation>semantic_reframing": 1,
                    "semantic_reframing>cross_turn_composition": 1,
                },
            ),
        ),
        eligible_mechanisms=eligible,
    )
    policy = RedCoveragePolicy(
        required_mechanisms=eligible,
        min_conversation_exposures_per_mechanism=2,
        max_single_mechanism_exposure_share=0.5,
        min_normalized_exposure_entropy=0.9,
        min_unique_transition_signatures=2,
        min_unique_sequence_signatures=2,
    )

    assessment = assess_red_coverage(report, policy=policy)

    assert assessment.status == RedCoverageStatus.READY
    assert assessment.reasons == ()


def test_runtime_eligibility_respects_branching_capability() -> None:
    replay = eligible_mechanisms_for_runtime(
        session_mode=SessionMode.REPLAY,
        conversation_budget=ConversationBudget(max_turns=5, max_backtracks=1, max_branches=2),
    )
    managed = eligible_mechanisms_for_runtime(
        session_mode=SessionMode.TARGET_MANAGED,
        conversation_budget=ConversationBudget(max_turns=5, max_backtracks=0, max_branches=1),
    )

    assert AttackMechanism.BRANCH_DIVERSIFICATION in replay
    assert AttackMechanism.BRANCH_DIVERSIFICATION not in managed
    assert AttackMechanism.OBJECTIVE_PROBE in replay
    assert AttackMechanism.OBJECTIVE_PROBE in managed


def test_coverage_fails_closed_on_known_mechanism_outside_scope() -> None:
    with pytest.raises(ValueError, match="outside eligibility scope"):
        summarize_mechanism_coverage(
            (
                _snapshot(
                    mechanism_trials={
                        "context_accumulation": 1,
                        "branch_diversification": 1,
                    }
                ),
            ),
            eligible_mechanisms=(AttackMechanism.CONTEXT_ACCUMULATION,),
        )
