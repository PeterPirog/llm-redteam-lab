from hashlib import sha256

import pytest

from llm_redteam.judge_calibration import (
    JudgeCalibrationObservation,
    fingerprint_calibration_reference_set,
    fingerprint_calibration_results,
    summarize_judge_calibration,
)

JUDGE_FP = sha256(b"judge-policy-v1").hexdigest()


def _observation(
    case_id: str,
    reference: bool,
    predicted: bool | None,
    *,
    family: str = "synthetic",
    stress: str = "clean",
) -> JudgeCalibrationObservation:
    return JudgeCalibrationObservation(
        case_id=case_id,
        reference_violated=reference,
        predicted_violated=predicted,
        attack_family=family,
        stress_condition=stress,
    )


def test_perfect_judge_has_expected_confusion_and_rates() -> None:
    observations = (
        _observation("p1", True, True),
        _observation("p2", True, True),
        _observation("n1", False, False),
        _observation("n2", False, False),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
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
    assert report.overall.negative_predictive_value.value == 1.0
    assert report.overall.f1 == 1.0
    assert report.overall.balanced_accuracy == 1.0
    assert report.overall.coverage_rate.value == 1.0
    assert report.overall.abstention_rate.value == 0.0
    assert report.comparable_blue_estimate is False


def test_abstentions_reduce_coverage_without_becoming_safe_predictions() -> None:
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
    assert report.overall.conclusive_cases == 2
    assert report.overall.abstentions == 2
    assert report.overall.coverage_rate.value == 0.5
    assert report.overall.abstention_rate.value == 0.5
    assert report.overall.accuracy.trials == 2
    assert report.overall.accuracy.value == 1.0


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


def test_reference_fingerprint_changes_when_ground_truth_changes() -> None:
    first = (_observation("a", True, True),)
    second = (_observation("a", False, True),)

    assert fingerprint_calibration_reference_set(first) != fingerprint_calibration_reference_set(
        second
    )


def test_stress_and_family_slices_are_reported_separately() -> None:
    observations = (
        _observation("a", True, True, family="direct", stress="clean"),
        _observation("b", True, False, family="direct", stress="benign-framing"),
        _observation("c", False, False, family="reframe", stress="clean"),
    )

    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )

    stress = {item.name: item for item in report.by_stress_condition}
    family = {item.name: item for item in report.by_attack_family}
    assert stress["stress:clean"].accuracy.value == 1.0
    assert stress["stress:benign-framing"].accuracy.value == 0.0
    assert family["family:direct"].accuracy.value == 0.5
    assert family["family:reframe"].accuracy.value == 1.0


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
