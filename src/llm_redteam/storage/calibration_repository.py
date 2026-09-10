"""Immutable persistence and verification for Judge calibration reports."""

from __future__ import annotations

from hashlib import sha256

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..domain import TargetClass
from ..judge_calibration import (
    JudgeCalibrationObservation,
    JudgeCalibrationReport,
    JudgeKind,
    JudgeReferenceKind,
    summarize_judge_calibration,
)
from .calibration_models import JudgeCalibrationObservationRow, JudgeCalibrationRunRow


def save_judge_calibration(
    engine: Engine,
    report: JudgeCalibrationReport,
    observations: tuple[JudgeCalibrationObservation, ...],
) -> str:
    """Persist calibration results immutably after recomputing all report metrics."""

    expected = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=report.judge_policy_fingerprint,
        judge_kind=report.judge_kind,
        confidence_level=report.overall.coverage_rate.confidence_level,
    )
    if expected != report:
        raise ValueError("Judge calibration report does not match supplied observations")

    with Session(engine) as session, session.begin():
        existing = session.get(JudgeCalibrationRunRow, report.content_hash)
        if existing is not None:
            restored = _load_from_session(session, report.content_hash)
            if restored is not None and restored[0] == report and restored[1] == observations:
                return report.content_hash
            raise ValueError("Judge calibration hash collision or corrupted stored report")

        session.add(
            JudgeCalibrationRunRow(
                calibration_hash=report.content_hash,
                schema_version=report.schema_version,
                judge_kind=report.judge_kind.value,
                calibration_set_fingerprint=report.calibration_set_fingerprint,
                judge_policy_fingerprint=report.judge_policy_fingerprint,
                observation_result_hash=report.observation_result_hash,
                overall=report.overall.model_dump(mode="json"),
                by_stress_condition=[
                    item.model_dump(mode="json") for item in report.by_stress_condition
                ],
                by_attack_family=[
                    item.model_dump(mode="json") for item in report.by_attack_family
                ],
                by_target_class=[
                    item.model_dump(mode="json") for item in report.by_target_class
                ],
                stress_robustness=[
                    item.model_dump(mode="json") for item in report.stress_robustness
                ],
                comparable_blue_estimate=report.comparable_blue_estimate,
            )
        )
        for item in observations:
            session.add(
                JudgeCalibrationObservationRow(
                    observation_id=_observation_id(report.content_hash, item),
                    calibration_hash=report.content_hash,
                    case_id=item.case_id,
                    reference_violated=item.reference_violated,
                    predicted_violated=item.predicted_violated,
                    predicted_confidence=item.predicted_confidence,
                    reference_kind=item.reference_kind.value,
                    target_class=item.target_class.value if item.target_class else None,
                    attack_family=item.attack_family,
                    stress_condition=item.stress_condition,
                )
            )
    return report.content_hash


def load_judge_calibration(
    engine: Engine,
    calibration_hash: str,
) -> tuple[JudgeCalibrationReport, tuple[JudgeCalibrationObservation, ...]] | None:
    """Load calibration evidence and independently recompute report integrity."""

    with Session(engine) as session:
        return _load_from_session(session, calibration_hash)


def _load_from_session(
    session: Session,
    calibration_hash: str,
) -> tuple[JudgeCalibrationReport, tuple[JudgeCalibrationObservation, ...]] | None:
    row = session.get(JudgeCalibrationRunRow, calibration_hash)
    if row is None:
        return None
    observations = tuple(
        JudgeCalibrationObservation(
            case_id=item.case_id,
            reference_violated=item.reference_violated,
            predicted_violated=item.predicted_violated,
            predicted_confidence=item.predicted_confidence,
            reference_kind=JudgeReferenceKind(item.reference_kind),
            target_class=TargetClass(item.target_class) if item.target_class else None,
            attack_family=item.attack_family,
            stress_condition=item.stress_condition,
        )
        for item in session.scalars(
            select(JudgeCalibrationObservationRow)
            .where(JudgeCalibrationObservationRow.calibration_hash == calibration_hash)
            .order_by(
                JudgeCalibrationObservationRow.case_id,
                JudgeCalibrationObservationRow.stress_condition,
            )
        )
    )
    stored_report = JudgeCalibrationReport(
        schema_version=row.schema_version,
        judge_kind=JudgeKind(row.judge_kind),
        calibration_set_fingerprint=row.calibration_set_fingerprint,
        judge_policy_fingerprint=row.judge_policy_fingerprint,
        observation_result_hash=row.observation_result_hash,
        overall=row.overall,
        by_stress_condition=tuple(row.by_stress_condition),
        by_attack_family=tuple(row.by_attack_family),
        by_target_class=tuple(row.by_target_class),
        stress_robustness=tuple(row.stress_robustness),
        comparable_blue_estimate=row.comparable_blue_estimate,
        content_hash=row.calibration_hash,
    )
    recomputed = summarize_judge_calibration(
        observations,
        judge_policy_fingerprint=stored_report.judge_policy_fingerprint,
        judge_kind=stored_report.judge_kind,
        confidence_level=stored_report.overall.coverage_rate.confidence_level,
    )
    if recomputed != stored_report:
        raise ValueError("persisted Judge calibration does not match observation evidence")
    return stored_report, observations


def _observation_id(calibration_hash: str, item: JudgeCalibrationObservation) -> str:
    digest = sha256(
        f"{calibration_hash}:{item.case_id}:{item.stress_condition}".encode()
    ).hexdigest()[:32]
    return f"jcal-observation-{digest}"
