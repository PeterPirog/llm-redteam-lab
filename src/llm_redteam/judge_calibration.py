"""Deterministic calibration metrics for semantic and multimodal Judges.

Judge calibration is measurement-instrument quality evidence. It is deliberately
separate from Blue campaign ASR and never rewrites campaign outcomes. Reference
labels must come from deterministic verification or an explicitly curated human
reference set, never from the Judge being calibrated.
"""

from __future__ import annotations

import json
from collections import Counter
from hashlib import sha256

from pydantic import Field, model_validator

from .domain import StrictModel
from .metrics import RateEstimate, wilson_rate

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class JudgeCalibrationObservation(StrictModel):
    """One reference-vs-Judge decision without raw prompt or response content."""

    case_id: str = Field(min_length=1, max_length=160)
    reference_violated: bool
    predicted_violated: bool | None
    attack_family: str | None = Field(default=None, min_length=1, max_length=96)
    stress_condition: str = Field(default="clean", min_length=1, max_length=96)


class CalibrationRate(StrictModel):
    successes: int = Field(ge=0)
    trials: int = Field(ge=0)
    value: float | None = Field(default=None, ge=0.0, le=1.0)
    ci_low: float | None = Field(default=None, ge=0.0, le=1.0)
    ci_high: float | None = Field(default=None, ge=0.0, le=1.0)
    confidence_level: float = Field(gt=0.0, lt=1.0)
    method: str = "wilson"


class ConfusionCounts(StrictModel):
    true_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)


class JudgeCalibrationSlice(StrictModel):
    """Instrument-quality metrics for one deterministic observation slice."""

    name: str = Field(min_length=1, max_length=192)
    total_cases: int = Field(ge=0)
    conclusive_cases: int = Field(ge=0)
    abstentions: int = Field(ge=0)
    confusion: ConfusionCounts
    coverage_rate: CalibrationRate
    abstention_rate: CalibrationRate
    accuracy: CalibrationRate
    precision: CalibrationRate
    recall: CalibrationRate
    specificity: CalibrationRate
    negative_predictive_value: CalibrationRate
    f1: float | None = Field(default=None, ge=0.0, le=1.0)
    balanced_accuracy: float | None = Field(default=None, ge=0.0, le=1.0)


class JudgeCalibrationReport(StrictModel):
    """Hash-bound calibration report for one exact reference set and Judge policy."""

    schema_version: int = Field(default=1, ge=1)
    calibration_set_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judge_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    observation_result_hash: str = Field(pattern=_HASH_PATTERN)
    overall: JudgeCalibrationSlice
    by_stress_condition: tuple[JudgeCalibrationSlice, ...] = ()
    by_attack_family: tuple[JudgeCalibrationSlice, ...] = ()
    comparable_blue_estimate: bool = False
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def report_hash_is_valid(self) -> JudgeCalibrationReport:
        if self.comparable_blue_estimate:
            raise ValueError("Judge calibration is not a comparative Blue estimate")
        expected = _canonical_hash(self._hash_payload())
        if self.content_hash != expected:
            raise ValueError("Judge calibration content_hash does not match report content")
        return self

    def _hash_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "calibration_set_fingerprint": self.calibration_set_fingerprint,
            "judge_policy_fingerprint": self.judge_policy_fingerprint,
            "observation_result_hash": self.observation_result_hash,
            "overall": self.overall.model_dump(mode="json"),
            "by_stress_condition": [
                item.model_dump(mode="json") for item in self.by_stress_condition
            ],
            "by_attack_family": [
                item.model_dump(mode="json") for item in self.by_attack_family
            ],
            "comparable_blue_estimate": False,
        }


def fingerprint_calibration_reference_set(
    observations: tuple[JudgeCalibrationObservation, ...],
) -> str:
    """Fingerprint reference-labelled cases independently from Judge predictions."""

    _validate_unique_observations(observations)
    rows = sorted(
        (
            {
                "case_id": item.case_id,
                "reference_violated": item.reference_violated,
                "attack_family": item.attack_family,
                "stress_condition": item.stress_condition,
            }
            for item in observations
        ),
        key=lambda row: (str(row["case_id"]), str(row["stress_condition"])),
    )
    return _canonical_hash(rows)


def fingerprint_calibration_results(
    observations: tuple[JudgeCalibrationObservation, ...],
) -> str:
    """Fingerprint reference labels and observed Judge decisions for audit/replay."""

    _validate_unique_observations(observations)
    rows = sorted(
        (item.model_dump(mode="json") for item in observations),
        key=lambda row: (str(row["case_id"]), str(row["stress_condition"])),
    )
    return _canonical_hash(rows)


def summarize_judge_calibration(
    observations: tuple[JudgeCalibrationObservation, ...],
    *,
    judge_policy_fingerprint: str,
    confidence_level: float = 0.95,
) -> JudgeCalibrationReport:
    """Summarize Judge quality against independent reference labels.

    `predicted_violated=None` is an abstention/unresolved decision and is excluded
    from confusion-matrix denominators while remaining visible in coverage and
    abstention rates. This prevents evaluator failure from masquerading as a safe
    prediction.
    """

    if not observations:
        raise ValueError("Judge calibration requires at least one observation")
    if len(judge_policy_fingerprint) != 64 or any(
        char not in "0123456789abcdef" for char in judge_policy_fingerprint
    ):
        raise ValueError("judge_policy_fingerprint must be a lowercase SHA-256 hex digest")
    _validate_unique_observations(observations)

    overall = _summarize_slice(
        "overall",
        observations,
        confidence_level=confidence_level,
    )
    stress_values = sorted({item.stress_condition for item in observations})
    family_values = sorted(
        {item.attack_family for item in observations if item.attack_family is not None}
    )
    by_stress = tuple(
        _summarize_slice(
            f"stress:{value}",
            tuple(item for item in observations if item.stress_condition == value),
            confidence_level=confidence_level,
        )
        for value in stress_values
    )
    by_family = tuple(
        _summarize_slice(
            f"family:{value}",
            tuple(item for item in observations if item.attack_family == value),
            confidence_level=confidence_level,
        )
        for value in family_values
    )
    payload = {
        "schema_version": 1,
        "calibration_set_fingerprint": fingerprint_calibration_reference_set(observations),
        "judge_policy_fingerprint": judge_policy_fingerprint,
        "observation_result_hash": fingerprint_calibration_results(observations),
        "overall": overall.model_dump(mode="json"),
        "by_stress_condition": [item.model_dump(mode="json") for item in by_stress],
        "by_attack_family": [item.model_dump(mode="json") for item in by_family],
        "comparable_blue_estimate": False,
    }
    return JudgeCalibrationReport(**payload, content_hash=_canonical_hash(payload))


def _summarize_slice(
    name: str,
    observations: tuple[JudgeCalibrationObservation, ...],
    *,
    confidence_level: float,
) -> JudgeCalibrationSlice:
    conclusive = tuple(item for item in observations if item.predicted_violated is not None)
    abstentions = len(observations) - len(conclusive)
    counts = Counter(
        (item.reference_violated, bool(item.predicted_violated)) for item in conclusive
    )
    tp = counts[(True, True)]
    tn = counts[(False, False)]
    fp = counts[(False, True)]
    fn = counts[(True, False)]

    precision = _rate(tp, tp + fp, confidence_level)
    recall = _rate(tp, tp + fn, confidence_level)
    specificity = _rate(tn, tn + fp, confidence_level)
    npv = _rate(tn, tn + fn, confidence_level)
    f1_denominator = 2 * tp + fp + fn
    f1 = (2 * tp / f1_denominator) if f1_denominator else None
    balanced_accuracy = (
        (recall.value + specificity.value) / 2.0
        if recall.value is not None and specificity.value is not None
        else None
    )

    return JudgeCalibrationSlice(
        name=name,
        total_cases=len(observations),
        conclusive_cases=len(conclusive),
        abstentions=abstentions,
        confusion=ConfusionCounts(
            true_positive=tp,
            true_negative=tn,
            false_positive=fp,
            false_negative=fn,
        ),
        coverage_rate=_rate(len(conclusive), len(observations), confidence_level),
        abstention_rate=_rate(abstentions, len(observations), confidence_level),
        accuracy=_rate(tp + tn, len(conclusive), confidence_level),
        precision=precision,
        recall=recall,
        specificity=specificity,
        negative_predictive_value=npv,
        f1=f1,
        balanced_accuracy=balanced_accuracy,
    )


def _rate(successes: int, trials: int, confidence_level: float) -> CalibrationRate:
    estimate: RateEstimate = wilson_rate(successes, trials, confidence_level)
    return CalibrationRate(
        successes=estimate.successes,
        trials=estimate.trials,
        value=estimate.value,
        ci_low=estimate.ci_low,
        ci_high=estimate.ci_high,
        confidence_level=estimate.confidence_level,
        method=estimate.method,
    )


def _validate_unique_observations(
    observations: tuple[JudgeCalibrationObservation, ...],
) -> None:
    keys = [(item.case_id, item.stress_condition) for item in observations]
    duplicates = [key for key, count in Counter(keys).items() if count > 1]
    if duplicates:
        rendered = ", ".join(f"{case_id}/{stress}" for case_id, stress in sorted(duplicates))
        raise ValueError(f"duplicate Judge calibration observation keys: {rendered}")


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
