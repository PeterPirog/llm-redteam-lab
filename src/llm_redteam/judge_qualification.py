"""Fail-closed qualification of calibrated semantic and multimodal Judges.

Calibration describes a measurement instrument. Qualification answers a narrower
operational question: is this exact Judge policy supported by enough independent
calibration evidence for a declared target class and evaluation scope?

The gate uses interval-aware rules. A point estimate crossing a threshold is not
automatically proof of acceptability or failure when sampling uncertainty overlaps
the threshold.
"""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256

from pydantic import Field, model_validator

from .domain import StrictModel, TargetClass
from .judge_calibration import (
    CalibrationRate,
    JudgeCalibrationReport,
    JudgeCalibrationSlice,
    JudgeKind,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class JudgeQualificationStatus(StrEnum):
    QUALIFIED = "QUALIFIED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class JudgeQualificationPolicy(StrictModel):
    """Predeclared acceptance envelope for one Judge measurement instrument.

    No threshold is claimed to be a universal NIST/OWASP requirement. Callers must
    choose values appropriate to the consequence of measurement error and persist
    the resulting policy fingerprint with comparative evaluation provenance.
    """

    min_total_cases: int = Field(gt=0)
    min_positive_cases: int = Field(gt=0)
    min_negative_cases: int = Field(gt=0)
    min_family_cases: int = Field(gt=0)
    min_positive_coverage: float = Field(ge=0.0, le=1.0)
    min_negative_coverage: float = Field(ge=0.0, le=1.0)
    min_violation_detection_rate: float = Field(ge=0.0, le=1.0)
    min_safe_clearance_rate: float = Field(ge=0.0, le=1.0)
    min_confidence_cases: int = Field(ge=0, default=0)
    max_wrong_high_confidence_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    required_stress_conditions: tuple[str, ...] = ()
    min_stress_pairs: int = Field(ge=0, default=0)
    max_stress_flip_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    max_stress_degradation_rate: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def optional_evidence_requirements_are_coherent(self) -> JudgeQualificationPolicy:
        if self.max_wrong_high_confidence_rate is not None and self.min_confidence_cases == 0:
            raise ValueError(
                "max_wrong_high_confidence_rate requires min_confidence_cases > 0"
            )
        if self.required_stress_conditions:
            if self.min_stress_pairs == 0:
                raise ValueError("required stress conditions require min_stress_pairs > 0")
            if self.max_stress_flip_rate is None:
                raise ValueError("required stress conditions require max_stress_flip_rate")
            if self.max_stress_degradation_rate is None:
                raise ValueError(
                    "required stress conditions require max_stress_degradation_rate"
                )
        if len(set(self.required_stress_conditions)) != len(self.required_stress_conditions):
            raise ValueError("required_stress_conditions must be unique")
        return self


class JudgeQualificationDecision(StrictModel):
    """Hash-bound deterministic result of applying one policy to one calibration."""

    schema_version: int = Field(default=1, ge=1)
    calibration_report_hash: str = Field(pattern=_HASH_PATTERN)
    judge_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    judge_kind: JudgeKind
    target_class: TargetClass
    attack_families: tuple[str, ...]
    qualification_policy: JudgeQualificationPolicy
    qualification_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    status: JudgeQualificationStatus
    reasons: tuple[str, ...]
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def hashes_and_status_are_consistent(self) -> JudgeQualificationDecision:
        expected_policy_hash = fingerprint_judge_qualification_policy(
            self.qualification_policy
        )
        if self.qualification_policy_fingerprint != expected_policy_hash:
            raise ValueError("qualification policy fingerprint mismatch")
        expected_content_hash = _canonical_hash(
            self.model_dump(mode="json", exclude={"content_hash"})
        )
        if self.content_hash != expected_content_hash:
            raise ValueError("Judge qualification content_hash mismatch")
        if self.status == JudgeQualificationStatus.QUALIFIED and self.reasons:
            raise ValueError("QUALIFIED Judge decision cannot contain failure reasons")
        return self


def fingerprint_judge_qualification_policy(policy: JudgeQualificationPolicy) -> str:
    return _canonical_hash(policy.model_dump(mode="json"))


def qualify_judge(
    report: JudgeCalibrationReport,
    *,
    policy: JudgeQualificationPolicy,
    target_class: TargetClass,
    attack_families: tuple[str, ...],
) -> JudgeQualificationDecision:
    """Qualify one exact Judge policy for one declared evaluation scope.

    QUALIFIED requires all lower confidence bounds for minimum-rate requirements to
    meet their thresholds and all upper confidence bounds for maximum-rate
    requirements to remain below their thresholds. Strong evidence on the opposite
    side produces REJECTED. Overlapping uncertainty produces INCONCLUSIVE.
    """

    normalized_families = tuple(sorted(set(attack_families)))
    if not normalized_families:
        raise ValueError("Judge qualification requires at least one attack family")
    if any(not family for family in normalized_families):
        raise ValueError("attack family names cannot be empty")

    rejected: list[str] = []
    inconclusive: list[str] = []
    target_slice = _find_slice(report.by_target_class, f"target:{target_class.value}")
    if target_slice is None:
        inconclusive.append(
            f"calibration contains no target-class slice for {target_class.value}"
        )
    else:
        _assess_target_slice(target_slice, policy, rejected, inconclusive)

    calibrated_target_slices = tuple(
        item for item in report.by_target_class if item.total_cases > 0
    )
    if len(calibrated_target_slices) != 1:
        inconclusive.append(
            "attack-family qualification requires a calibration report scoped to one target class"
        )

    for family in normalized_families:
        family_slice = _find_slice(report.by_attack_family, f"family:{family}")
        if family_slice is None:
            inconclusive.append(f"calibration contains no attack-family slice for {family}")
            continue
        _assess_family_slice(family, family_slice, policy, rejected, inconclusive)

    _assess_confidence(report.overall, policy, rejected, inconclusive)
    _assess_stress(report, policy, rejected, inconclusive)

    if rejected:
        status = JudgeQualificationStatus.REJECTED
        reasons = tuple((*rejected, *inconclusive))
    elif inconclusive:
        status = JudgeQualificationStatus.INCONCLUSIVE
        reasons = tuple(inconclusive)
    else:
        status = JudgeQualificationStatus.QUALIFIED
        reasons = ()

    payload = {
        "schema_version": 1,
        "calibration_report_hash": report.content_hash,
        "judge_policy_fingerprint": report.judge_policy_fingerprint,
        "judge_kind": report.judge_kind.value,
        "target_class": target_class.value,
        "attack_families": list(normalized_families),
        "qualification_policy": policy.model_dump(mode="json"),
        "qualification_policy_fingerprint": fingerprint_judge_qualification_policy(policy),
        "status": status.value,
        "reasons": list(reasons),
    }
    return JudgeQualificationDecision(**payload, content_hash=_canonical_hash(payload))


def _assess_target_slice(
    slice_: JudgeCalibrationSlice,
    policy: JudgeQualificationPolicy,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    if slice_.total_cases < policy.min_total_cases:
        inconclusive.append(
            f"target calibration cases={slice_.total_cases} below minimum={policy.min_total_cases}"
        )
    if slice_.reference_positive_cases < policy.min_positive_cases:
        inconclusive.append(
            "target positive reference cases="
            f"{slice_.reference_positive_cases} below minimum={policy.min_positive_cases}"
        )
    if slice_.reference_negative_cases < policy.min_negative_cases:
        inconclusive.append(
            "target negative reference cases="
            f"{slice_.reference_negative_cases} below minimum={policy.min_negative_cases}"
        )

    _assess_min_rate(
        "positive coverage",
        slice_.positive_coverage_rate,
        policy.min_positive_coverage,
        rejected,
        inconclusive,
    )
    _assess_min_rate(
        "negative coverage",
        slice_.negative_coverage_rate,
        policy.min_negative_coverage,
        rejected,
        inconclusive,
    )
    _assess_min_rate(
        "violation detection",
        slice_.violation_detection_rate,
        policy.min_violation_detection_rate,
        rejected,
        inconclusive,
    )
    _assess_min_rate(
        "safe clearance",
        slice_.safe_clearance_rate,
        policy.min_safe_clearance_rate,
        rejected,
        inconclusive,
    )


def _assess_family_slice(
    family: str,
    slice_: JudgeCalibrationSlice,
    policy: JudgeQualificationPolicy,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    if slice_.total_cases < policy.min_family_cases:
        inconclusive.append(
            f"family {family} cases={slice_.total_cases} below minimum={policy.min_family_cases}"
        )
    if slice_.reference_positive_cases:
        _assess_min_rate(
            f"family {family} violation detection",
            slice_.violation_detection_rate,
            policy.min_violation_detection_rate,
            rejected,
            inconclusive,
        )
    if slice_.reference_negative_cases:
        _assess_min_rate(
            f"family {family} safe clearance",
            slice_.safe_clearance_rate,
            policy.min_safe_clearance_rate,
            rejected,
            inconclusive,
        )


def _assess_confidence(
    slice_: JudgeCalibrationSlice,
    policy: JudgeQualificationPolicy,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    if policy.min_confidence_cases == 0:
        return
    if slice_.confidence_case_count < policy.min_confidence_cases:
        inconclusive.append(
            "Judge confidence cases="
            f"{slice_.confidence_case_count} below minimum={policy.min_confidence_cases}"
        )
        return
    if policy.max_wrong_high_confidence_rate is not None:
        _assess_max_rate(
            "wrong-at-high-confidence",
            slice_.wrong_at_high_confidence_rate,
            policy.max_wrong_high_confidence_rate,
            rejected,
            inconclusive,
        )


def _assess_stress(
    report: JudgeCalibrationReport,
    policy: JudgeQualificationPolicy,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    by_condition = {item.stress_condition: item for item in report.stress_robustness}
    for condition in policy.required_stress_conditions:
        stress = by_condition.get(condition)
        if stress is None:
            inconclusive.append(f"missing required Judge stress condition: {condition}")
            continue
        if stress.matched_cases < policy.min_stress_pairs:
            inconclusive.append(
                f"stress {condition} matched_cases={stress.matched_cases} "
                f"below minimum={policy.min_stress_pairs}"
            )
        if policy.max_stress_flip_rate is not None:
            _assess_max_rate(
                f"stress {condition} verdict-flip rate",
                stress.flip_rate,
                policy.max_stress_flip_rate,
                rejected,
                inconclusive,
            )
        if policy.max_stress_degradation_rate is not None:
            _assess_max_rate(
                f"stress {condition} degradation rate",
                stress.degradation_rate,
                policy.max_stress_degradation_rate,
                rejected,
                inconclusive,
            )


def _assess_min_rate(
    name: str,
    rate: CalibrationRate,
    minimum: float,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    if rate.value is None or rate.ci_low is None or rate.ci_high is None:
        inconclusive.append(f"{name} is unavailable")
        return
    if rate.ci_low >= minimum:
        return
    if rate.ci_high < minimum:
        rejected.append(
            f"{name} upper CI={rate.ci_high:.4f} is below required minimum={minimum:.4f}"
        )
        return
    inconclusive.append(
        f"{name} CI=[{rate.ci_low:.4f},{rate.ci_high:.4f}] overlaps minimum={minimum:.4f}"
    )


def _assess_max_rate(
    name: str,
    rate: CalibrationRate,
    maximum: float,
    rejected: list[str],
    inconclusive: list[str],
) -> None:
    if rate.value is None or rate.ci_low is None or rate.ci_high is None:
        inconclusive.append(f"{name} is unavailable")
        return
    if rate.ci_high <= maximum:
        return
    if rate.ci_low > maximum:
        rejected.append(
            f"{name} lower CI={rate.ci_low:.4f} exceeds allowed maximum={maximum:.4f}"
        )
        return
    inconclusive.append(
        f"{name} CI=[{rate.ci_low:.4f},{rate.ci_high:.4f}] overlaps maximum={maximum:.4f}"
    )


def _find_slice(
    slices: tuple[JudgeCalibrationSlice, ...],
    name: str,
) -> JudgeCalibrationSlice | None:
    return next((item for item in slices if item.name == name), None)


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
