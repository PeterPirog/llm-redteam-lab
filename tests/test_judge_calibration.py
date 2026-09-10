from hashlib import sha256

import pytest

from llm_redteam.domain import TargetClass
from llm_redteam.judge_calibration import (
    JudgeCalibrationObservation,
    JudgeKind,
    JudgeReferenceKind,
    fingerprint_calibration_reference_set,
    fingerprint_calibration_results,
    summarize_judge_calibration,
)

JUDGE_FP = sha256(b"judge-policy-v2").hexdigest()


def _observation(
    case_id: str,
    reference: bool,
    predicted: bool | None,
    *,
    confidence: float | None = None,
    family: str = "synthetic",
    stress: str = "clean",
    reference_kind: JudgeReferenceKind = JudgeReferenceKind.DETERMINISTIC_VERIFIER,
    target_class: TargetClass = TargetClass.WRITING,
) -> JudgeCalibrationObservation:
    return JudgeCalibrationObservation(
        case_id=case_id,
        reference_violated=reference,
        predicted_violated=predicted,
        predicted_confidence=confidence,
        reference_kind=reference_kind,
        target_class=target_class,
        attack_family=family,
        stress_condition=stress,
    )


def test_perfect_judge_has_expected_confusion_and_rates() -> None:
    observations = (
        _observation("p1", True, True, confidence=0.95),
        _observation("p2", True, True, confidence=0.95),
        _observation("n1", False, False, confidence=0.95),
        _observation("n2", False, False, confidence=0.95),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
        judge_kind=JudgeKind.SEMANTIC,
    )

    counts = report.overall.confusion
    assert counts.true_positive == 2
    assert counts.true_negative == 2
    assert counts.false_positive == 0
    assert counts.false_negative == 0
    assert report.overall.accuracy.value == 1.0
    assert report.overall.precision.value == 1.0
    assert report.overall.recall.value == 1.0
    assert report.overall.specificity.value == 1.0
    assert report.overall.violation_detection_rate.value == 1.0
    assert report.overall.safe_clearance_rate.value == 1.0
    assert report.overall.f1 == 1.0
    assert report.overall.balanced_accuracy == 1.0
    assert report.overall.coverage_rate.value == 1.0
    assert report.overall.abstention_rate.value == 0.0
    assert report.overall.confidence_brier_score == pytest.approx(0.0025)
    assert report.overall.confidence_ece == pytest.approx(0.05)
    assert report.overall.wrong_at_high_confidence_rate.value == 0.0
    assert report.comparable_blue_estimate is False


def test_abstentions_reduce_class_coverage_and_end_to_end_detection() -> None:
    observations = (
        _observation("p1", True, None),
        _observation("p2", True, True),
        _observation("n1", False, False),
        _observation("n2", False, None),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    assert report.overall.total_cases == 4
    assert report.overall.reference_positive_cases == 2
    assert report.overall.reference_negative_cases == 2
    assert report.overall.conclusive_cases == 2
    assert report.overall.abstentions == 2
    assert report.overall.positive_abstentions == 1
    assert report.overall.negative_abstentions == 1
    assert report.overall.coverage_rate.value == 0.5
    assert report.overall.positive_coverage_rate.value == 0.5
    assert report.overall.negative_coverage_rate.value == 0.5
    assert report.overall.accuracy.value == 1.0
    assert report.overall.recall.value == 1.0
    assert report.overall.violation_detection_rate.value == 0.5
    assert report.overall.safe_clearance_rate.value == 0.5


def test_false_positive_and_false_negative_are_not_hidden() -> None:
    observations = (
        _observation("tp", True, True),
        _observation("fn", True, False),
        _observation("tn", False, False),
        _observation("fp", False, True),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    counts = report.overall.confusion
    assert (counts.true_positive, counts.false_negative) == (1, 1)
    assert (counts.true_negative, counts.false_positive) == (1, 1)
    assert report.overall.precision.value == 0.5
    assert report.overall.recall.value == 0.5
    assert report.overall.specificity.value == 0.5
    assert report.overall.negative_predictive_value.value == 0.5
    assert report.overall.f1 == 0.5
    assert report.overall.balanced_accuracy == 0.5


def test_undefined_class_metrics_remain_unavailable_not_zero() -> None:
    observations = (
        _observation("n1", False, False),
        _observation("n2", False, False),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    assert report.overall.recall.trials == 0
    assert report.overall.recall.value is None
    assert report.overall.precision.trials == 0
    assert report.overall.precision.value is None
    assert report.overall.specificity.value == 1.0
    assert report.overall.negative_predictive_value.value == 1.0
    assert report.overall.balanced_accuracy is None
    assert report.overall.violation_detection_rate.value is None


def test_self_confidence_calibration_exposes_confident_errors() -> None:
    observations = (
        _observation("correct", True, True, confidence=0.95),
        _observation("wrong", True, False, confidence=0.95),
        _observation("low", False, False, confidence=0.55),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    assert report.overall.confidence_case_count == 3
    assert report.overall.confidence_brier_score is not None
    assert report.overall.confidence_ece is not None
    assert report.overall.wrong_at_high_confidence_rate.trials == 2
    assert report.overall.wrong_at_high_confidence_rate.value == 0.5


def test_abstention_cannot_claim_prediction_confidence() -> None:
    with pytest.raises(ValueError, match="abstention"):
        _observation("a", True, None, confidence=0.9)


def test_reference_fingerprint_is_prediction_independent() -> None:
    first = (
        _observation("a", True, True),
        _observation("b", False, False, stress="benign-framing"),
    )
    second = (
        _observation("a", True, False),
        _observation("b", False, True, stress="benign-framing"),
    )

    assert fingerprint_calibration_reference_set(first) == fingerprint_calibration_reference_set(
        second
    )
    assert fingerprint_calibration_results(first) != fingerprint_calibration_results(second)


def test_reference_fingerprint_changes_when_ground_truth_source_changes() -> None:
    first = (_observation("a", True, True),)
    second = (
        _observation(
            "a",
            True,
            True,
            reference_kind=JudgeReferenceKind.HUMAN_MAJORITY,
        ),
    )

    assert fingerprint_calibration_reference_set(first) != fingerprint_calibration_reference_set(
        second
    )


def test_stress_family_and_target_slices_are_reported_separately() -> None:
    observations = (
        _observation("a", True, True, family="direct", stress="clean"),
        _observation("b", True, False, family="direct", stress="benign-framing"),
        _observation(
            "c",
            False,
            False,
            family="reframe",
            stress="clean",
            target_class=TargetClass.REASONING,
        ),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    stress = {item.name: item for item in report.by_stress_condition}
    family = {item.name: item for item in report.by_attack_family}
    targets = {item.name: item for item in report.by_target_class}
    assert stress["stress:clean"].accuracy.value == 1.0
    assert stress["stress:benign-framing"].accuracy.value == 0.0
    assert family["family:direct"].accuracy.value == 0.5
    assert family["family:reframe"].accuracy.value == 1.0
    assert targets["target:writing"].accuracy.value == 0.5
    assert targets["target:reasoning"].accuracy.value == 1.0


def test_paired_stress_robustness_counts_flips_degradation_and_abstention() -> None:
    observations = (
        _observation("a", True, True, stress="clean"),
        _observation("a", True, False, stress="benign-framing"),
        _observation("b", False, False, stress="clean"),
        _observation("b", False, False, stress="benign-framing"),
        _observation("c", True, True, stress="clean"),
        _observation("c", True, None, stress="benign-framing"),
        _observation("d", False, True, stress="clean"),
        _observation("d", False, False, stress="benign-framing"),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    comparison = report.stress_robustness[0]
    assert comparison.stress_condition == "benign-framing"
    assert comparison.matched_cases == 4
    assert comparison.both_conclusive == 3
    assert comparison.verdict_flips == 2
    assert comparison.correct_to_incorrect == 1
    assert comparison.incorrect_to_correct == 1
    assert comparison.new_abstentions_under_stress == 1
    assert comparison.flip_rate.value == pytest.approx(2 / 3)
    assert comparison.degradation_rate.value == 0.5


def test_paired_stress_variants_must_share_reference_facts() -> None:
    observations = (
        _observation("a", True, True, stress="clean"),
        _observation("a", False, False, stress="benign-framing"),
    )

    with pytest.raises(ValueError, match="reference facts"):
        summarize_judge_calibration(
            observations,
            judge_policy_fingerprint=JUDGE_FP,
        )


def test_duplicate_case_and_stress_key_is_rejected() -> None:
    observations = (
        _observation("a", True, True),
        _observation("a", True, False),
    )

    with pytest.raises(ValueError, match="duplicate Judge calibration observation"):
        summarize_judge_calibration(
            observations,
            judge_policy_fingerprint=JUDGE_FP,
        )


def test_invalid_judge_fingerprint_fails_closed() -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        summarize_judge_calibration(
            (_observation("a", True, True),),
            judge_policy_fingerprint="not-a-hash",
        )
