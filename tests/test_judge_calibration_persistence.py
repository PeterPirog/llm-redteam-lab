from hashlib import sha256

import pytest
from sqlalchemy.orm import Session

from llm_redteam.domain import TargetClass
from llm_redteam.judge_calibration import (
    JudgeCalibrationObservation,
    JudgeKind,
    JudgeReferenceKind,
    summarize_judge_calibration,
)
from llm_redteam.storage import (
    ExperimentRepository,
    JudgeCalibrationObservationRow,
    load_judge_calibration,
    save_judge_calibration,
)

JUDGE_FP = sha256(b"judge-calibration-persistence").hexdigest()


def _repository() -> ExperimentRepository:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    return repository


def _observation(
    case_id: str,
    reference: bool,
    predicted: bool | None,
    *,
    stress: str = "clean",
    confidence: float | None = None,
) -> JudgeCalibrationObservation:
    return JudgeCalibrationObservation(
        case_id=case_id,
        reference_violated=reference,
        predicted_violated=predicted,
        predicted_confidence=confidence,
        reference_kind=JudgeReferenceKind.HUMAN_MAJORITY,
        target_class=TargetClass.REASONING,
        attack_family="multi_turn_jailbreak",
        stress_condition=stress,
    )


def _observations() -> tuple[JudgeCalibrationObservation, ...]:
    return (
        _observation("case-b", False, False, confidence=0.92),
        _observation("case-a", True, True, confidence=0.96),
        _observation("case-a", True, False, stress="benign-framing", confidence=0.94),
        _observation("case-b", False, False, stress="benign-framing", confidence=0.91),
    )


def test_calibration_round_trip_recomputes_metrics() -> None:
    repository = _repository()
    observations = _observations()
    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
        judge_kind=JudgeKind.SEMANTIC,
    )

    saved = save_judge_calibration(repository.engine, report, observations)
    restored = load_judge_calibration(repository.engine, saved)

    assert saved == report.content_hash
    assert restored is not None
    restored_report, restored_observations = restored
    assert restored_report == report
    assert restored_observations == tuple(
        sorted(observations, key=lambda item: (item.case_id, item.stress_condition))
    )


def test_identical_calibration_is_idempotent_across_input_order() -> None:
    repository = _repository()
    observations = _observations()
    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
        judge_kind=JudgeKind.SEMANTIC,
    )

    first = save_judge_calibration(repository.engine, report, observations)
    second = save_judge_calibration(repository.engine, report, tuple(reversed(observations)))

    assert first == second == report.content_hash


def test_report_cannot_be_persisted_against_different_observations() -> None:
    repository = _repository()
    observations = _observations()
    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )
    changed = (
        *observations[:-1],
        _observation(
            "case-b",
            False,
            True,
            stress="benign-framing",
            confidence=0.91,
        ),
    )

    with pytest.raises(ValueError, match="does not match"):
        save_judge_calibration(repository.engine, report, changed)


def test_tampered_observation_fails_on_load() -> None:
    repository = _repository()
    observations = _observations()
    report = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=JUDGE_FP,
    )
    save_judge_calibration(repository.engine, report, observations)

    with Session(repository.engine) as session, session.begin():
        row = (
            session.query(JudgeCalibrationObservationRow)
            .filter_by(calibration_hash=report.content_hash, case_id="case-a", stress_condition="clean")
            .one()
        )
        row.predicted_violated = False

    with pytest.raises(ValueError, match="does not match observation evidence"):
        load_judge_calibration(repository.engine, report.content_hash)
