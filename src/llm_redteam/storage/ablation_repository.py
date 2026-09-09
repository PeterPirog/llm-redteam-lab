"""Immutable provenance for paired Red component ablation experiments."""

from __future__ import annotations

import json
from collections.abc import Iterable
from hashlib import sha256

from pydantic import Field, model_validator
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..domain import CompromiseOutcome, ExecutionResult, StrictModel
from ..evaluation_protocol import CampaignPurpose
from ..red.ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairedRedObservation,
    summarize_paired_red_ablation,
)
from .ablation_models import RedAblationExperimentRow, RedAblationObservationRow
from .evaluation_set_repository import load_evaluation_set_manifest
from .measurement_repository import (
    CampaignMeasurementSnapshot,
    load_campaign_measurement_snapshot,
)
from .models import AttackRow, ConversationRow, ExecutionRow, TargetSnapshotRow

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class RedAblationExperimentSnapshot(StrictModel):
    """Hash-bound association between one ablation contract and two real campaigns."""

    schema_version: int = Field(ge=1, default=1)
    experiment_id: str = Field(min_length=1)
    contract: PairedRedAblationContract
    baseline_campaign_id: str = Field(min_length=1)
    treatment_campaign_id: str = Field(min_length=1)
    baseline_measurement_hash: str = Field(pattern=_HASH_PATTERN)
    treatment_measurement_hash: str = Field(pattern=_HASH_PATTERN)
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def identity_is_consistent(self) -> RedAblationExperimentSnapshot:
        if self.experiment_id != self.contract.experiment_id:
            raise ValueError("ablation experiment_id must match the contract")
        if self.baseline_campaign_id == self.treatment_campaign_id:
            raise ValueError("paired ablation requires distinct baseline/treatment campaigns")
        return self

    @model_validator(mode="after")
    def content_hash_matches_snapshot(self) -> RedAblationExperimentSnapshot:
        if _experiment_content_hash(self) != self.content_hash:
            raise ValueError("Red ablation experiment content_hash does not match snapshot")
        return self


def build_red_ablation_experiment_snapshot(
    *,
    contract: PairedRedAblationContract,
    baseline_campaign_id: str,
    treatment_campaign_id: str,
    baseline_measurement_hash: str,
    treatment_measurement_hash: str,
) -> RedAblationExperimentSnapshot:
    """Build a canonical experiment snapshot before persistence."""

    payload = {
        "schema_version": 1,
        "experiment_id": contract.experiment_id,
        "contract": contract.model_dump(mode="json"),
        "baseline_campaign_id": baseline_campaign_id,
        "treatment_campaign_id": treatment_campaign_id,
        "baseline_measurement_hash": baseline_measurement_hash,
        "treatment_measurement_hash": treatment_measurement_hash,
    }
    return RedAblationExperimentSnapshot(
        **payload,
        content_hash=_canonical_hash(payload),
    )


def save_red_ablation_experiment(
    engine: Engine,
    snapshot: RedAblationExperimentSnapshot,
) -> str:
    """Persist one immutable paired experiment after verifying both campaign snapshots."""

    if _experiment_content_hash(snapshot) != snapshot.content_hash:
        raise ValueError("Red ablation experiment content_hash does not match snapshot")

    baseline = _required_measurement(engine, snapshot.baseline_campaign_id)
    treatment = _required_measurement(engine, snapshot.treatment_campaign_id)
    _verify_experiment_measurements(snapshot, baseline, treatment)

    with Session(engine) as session, session.begin():
        existing = session.get(RedAblationExperimentRow, snapshot.experiment_id)
        if existing is not None:
            if existing.content_hash == snapshot.content_hash:
                return snapshot.content_hash
            raise ValueError("Red ablation experiment is immutable after first persistence")
        session.add(
            RedAblationExperimentRow(
                experiment_id=snapshot.experiment_id,
                schema_version=snapshot.schema_version,
                contract=snapshot.contract.model_dump(mode="json"),
                contract_hash=_canonical_hash(snapshot.contract.model_dump(mode="json")),
                baseline_campaign_id=snapshot.baseline_campaign_id,
                treatment_campaign_id=snapshot.treatment_campaign_id,
                baseline_measurement_hash=snapshot.baseline_measurement_hash,
                treatment_measurement_hash=snapshot.treatment_measurement_hash,
                content_hash=snapshot.content_hash,
            )
        )
    return snapshot.content_hash


def load_red_ablation_experiment(
    engine: Engine,
    experiment_id: str,
) -> RedAblationExperimentSnapshot | None:
    """Load an experiment and re-verify its immutable campaign provenance."""

    with Session(engine) as session:
        row = session.get(RedAblationExperimentRow, experiment_id)
        if row is None:
            return None
        contract = PairedRedAblationContract.model_validate(row.contract)
        snapshot = build_red_ablation_experiment_snapshot(
            contract=contract,
            baseline_campaign_id=row.baseline_campaign_id,
            treatment_campaign_id=row.treatment_campaign_id,
            baseline_measurement_hash=row.baseline_measurement_hash,
            treatment_measurement_hash=row.treatment_measurement_hash,
        )
        if snapshot.schema_version != row.schema_version:
            raise ValueError("Red ablation experiment schema version mismatch")
        if _canonical_hash(contract.model_dump(mode="json")) != row.contract_hash:
            raise ValueError("Red ablation contract hash mismatch")
        if snapshot.content_hash != row.content_hash:
            raise ValueError("Red ablation experiment content hash mismatch")

    baseline = _required_measurement(engine, snapshot.baseline_campaign_id)
    treatment = _required_measurement(engine, snapshot.treatment_campaign_id)
    _verify_experiment_measurements(snapshot, baseline, treatment)
    return snapshot


def save_red_ablation_observation(
    engine: Engine,
    *,
    experiment_id: str,
    observation: PairedRedObservation,
) -> str:
    """Bind one paired observation to the real persisted execution and conversation."""

    experiment = load_red_ablation_experiment(engine, experiment_id)
    if experiment is None:
        raise ValueError(f"unknown Red ablation experiment: {experiment_id}")
    campaign_id = _expected_campaign(experiment, observation.arm)

    with Session(engine) as session, session.begin():
        _verify_observation_against_persistence(
            session,
            experiment=experiment,
            campaign_id=campaign_id,
            observation=observation,
        )
        payload = _observation_payload(
            experiment_id=experiment_id,
            campaign_id=campaign_id,
            observation=observation,
        )
        observation_hash = _canonical_hash(payload)
        key = (
            experiment_id,
            observation.arm.value,
            observation.case_id,
            observation.replicate,
        )
        existing = session.get(RedAblationObservationRow, key)
        if existing is not None:
            if existing.observation_hash == observation_hash:
                return observation_hash
            raise ValueError("Red ablation observation is immutable after first persistence")
        session.add(
            RedAblationObservationRow(
                experiment_id=experiment_id,
                arm=observation.arm.value,
                case_id=observation.case_id,
                replicate=observation.replicate,
                execution_id=observation.execution.execution_id,
                campaign_id=campaign_id,
                pair_seed=observation.pair_seed,
                policy_fingerprint=observation.policy_fingerprint,
                target_interactions=observation.target_interactions,
                backtracks=observation.backtracks,
                branches_created=observation.branches_created,
                first_violation_ordinal=observation.first_violation_ordinal,
                first_violation_depth=observation.first_violation_depth,
                planner_calls=observation.planner_calls,
                mutator_calls=observation.mutator_calls,
                planner_output_tokens=observation.planner_output_tokens,
                mutator_output_tokens=observation.mutator_output_tokens,
                elapsed_seconds=observation.elapsed_seconds,
                observation_hash=observation_hash,
            )
        )
    return observation_hash


def save_red_ablation_observations(
    engine: Engine,
    *,
    experiment_id: str,
    observations: Iterable[PairedRedObservation],
) -> tuple[str, ...]:
    """Persist a complete collection of paired observations using per-row checks."""

    return tuple(
        save_red_ablation_observation(
            engine,
            experiment_id=experiment_id,
            observation=observation,
        )
        for observation in observations
    )


def load_red_ablation_observations(
    engine: Engine,
    experiment_id: str,
) -> tuple[PairedRedObservation, ...]:
    """Load observations from execution truth and verify their stored metadata hashes."""

    experiment = load_red_ablation_experiment(engine, experiment_id)
    if experiment is None:
        raise ValueError(f"unknown Red ablation experiment: {experiment_id}")

    with Session(engine) as session:
        rows = session.scalars(
            select(RedAblationObservationRow)
            .where(RedAblationObservationRow.experiment_id == experiment_id)
            .order_by(
                RedAblationObservationRow.case_id,
                RedAblationObservationRow.replicate,
                RedAblationObservationRow.arm,
            )
        ).all()
        observations: list[PairedRedObservation] = []
        for row in rows:
            observation = _observation_from_row(session, row)
            expected_campaign = _expected_campaign(experiment, observation.arm)
            if row.campaign_id != expected_campaign:
                raise ValueError("stored Red ablation observation campaign mismatch")
            _verify_observation_against_persistence(
                session,
                experiment=experiment,
                campaign_id=expected_campaign,
                observation=observation,
            )
            payload = _observation_payload(
                experiment_id=experiment_id,
                campaign_id=expected_campaign,
                observation=observation,
            )
            if _canonical_hash(payload) != row.observation_hash:
                raise ValueError("Red ablation observation content hash mismatch")
            observations.append(observation)
        return tuple(observations)


def summarize_persisted_red_ablation(
    engine: Engine,
    experiment_id: str,
    *,
    confidence_level: float = 0.95,
) -> PairedRedAblationReport:
    """Produce a paired report only from verified persisted experiment facts."""

    experiment = load_red_ablation_experiment(engine, experiment_id)
    if experiment is None:
        raise ValueError(f"unknown Red ablation experiment: {experiment_id}")
    manifest = load_evaluation_set_manifest(
        engine,
        experiment.contract.evaluation_manifest_hash,
    )
    if manifest is None:
        raise ValueError("Red ablation experiment references missing evaluation manifest")
    observations = load_red_ablation_observations(engine, experiment_id)
    return summarize_paired_red_ablation(
        observations,
        contract=experiment.contract,
        manifest=manifest,
        confidence_level=confidence_level,
    )


def _required_measurement(engine: Engine, campaign_id: str) -> CampaignMeasurementSnapshot:
    measurement = load_campaign_measurement_snapshot(engine, campaign_id)
    if measurement is None:
        raise ValueError(f"campaign lacks measurement provenance: {campaign_id}")
    return measurement


def _verify_experiment_measurements(
    experiment: RedAblationExperimentSnapshot,
    baseline: CampaignMeasurementSnapshot,
    treatment: CampaignMeasurementSnapshot,
) -> None:
    contract = experiment.contract
    if baseline.content_hash != experiment.baseline_measurement_hash:
        raise ValueError("baseline measurement hash does not match persisted campaign")
    if treatment.content_hash != experiment.treatment_measurement_hash:
        raise ValueError("treatment measurement hash does not match persisted campaign")

    _verify_arm_measurement(
        measurement=baseline,
        contract=contract,
        expected_campaign_id=experiment.baseline_campaign_id,
        expected_policy_fingerprint=contract.baseline_policy_fingerprint,
        arm="baseline",
    )
    _verify_arm_measurement(
        measurement=treatment,
        contract=contract,
        expected_campaign_id=experiment.treatment_campaign_id,
        expected_policy_fingerprint=contract.treatment_policy_fingerprint,
        arm="treatment",
    )


def _verify_arm_measurement(
    *,
    measurement: CampaignMeasurementSnapshot,
    contract: PairedRedAblationContract,
    expected_campaign_id: str,
    expected_policy_fingerprint: str,
    arm: str,
) -> None:
    if measurement.campaign_id != expected_campaign_id:
        raise ValueError(f"{arm} measurement campaign mismatch")
    if measurement.protocol.purpose != CampaignPurpose.EVALUATION:
        raise ValueError(f"{arm} campaign is not an EVALUATION campaign")
    if measurement.target_snapshot_id != contract.target_snapshot_id:
        raise ValueError(f"{arm} target snapshot does not match ablation contract")
    if measurement.metric_definition_version != contract.metric_definition_version:
        raise ValueError(f"{arm} metric definition does not match ablation contract")
    if measurement.evaluation_manifest_hash != contract.evaluation_manifest_hash:
        raise ValueError(f"{arm} held-out manifest does not match ablation contract")
    if measurement.attack_policy_fingerprint != expected_policy_fingerprint:
        raise ValueError(f"{arm} Red policy fingerprint does not match ablation contract")
    if measurement.judge_policy_fingerprint is None:
        raise ValueError(f"{arm} measurement lacks explicit Judge fingerprint")
    if measurement.judge_policy_fingerprint != contract.judge_fingerprint:
        raise ValueError(f"{arm} Judge fingerprint does not match ablation contract")
    if measurement.budget_fingerprint is None:
        raise ValueError(f"{arm} measurement lacks explicit budget fingerprint")
    if measurement.budget_fingerprint != contract.budget_fingerprint:
        raise ValueError(f"{arm} budget fingerprint does not match ablation contract")


def _verify_observation_against_persistence(
    session: Session,
    *,
    experiment: RedAblationExperimentSnapshot,
    campaign_id: str,
    observation: PairedRedObservation,
) -> None:
    contract = experiment.contract
    expected_policy = (
        contract.baseline_policy_fingerprint
        if observation.arm == AblationArm.BASELINE
        else contract.treatment_policy_fingerprint
    )
    if observation.policy_fingerprint != expected_policy:
        raise ValueError("Red ablation observation policy fingerprint mismatch")

    execution = session.get(ExecutionRow, observation.execution.execution_id)
    if execution is None:
        raise ValueError(f"unknown persisted execution: {observation.execution.execution_id}")
    attack = session.get(AttackRow, execution.attack_instance_id)
    if attack is None:
        raise ValueError("persisted execution references missing attack")
    if attack.campaign_id != campaign_id:
        raise ValueError("persisted execution belongs to the wrong ablation campaign")
    if attack.case_id != observation.case_id:
        raise ValueError("persisted execution case does not match ablation observation")
    if execution.target_snapshot_id != contract.target_snapshot_id:
        raise ValueError("persisted execution target does not match ablation contract")

    _verify_execution_facts(execution, observation.execution)

    conversation = session.scalar(
        select(ConversationRow).where(
            ConversationRow.execution_id == observation.execution.execution_id
        )
    )
    if conversation is None:
        raise ValueError("paired multi-turn ablation requires a persisted conversation")
    if conversation.session_mode != contract.session_mode:
        raise ValueError("persisted conversation session mode does not match ablation contract")
    if conversation.turn_count != observation.target_interactions:
        raise ValueError("persisted turn count does not match ablation observation")
    if conversation.backtracks != observation.backtracks:
        raise ValueError("persisted backtrack count does not match ablation observation")
    if max(0, conversation.branches - 1) != observation.branches_created:
        raise ValueError("persisted branch count does not match ablation observation")
    if conversation.first_violation_ordinal != observation.first_violation_ordinal:
        raise ValueError("persisted first-violation ordinal does not match observation")
    if conversation.first_violation_depth != observation.first_violation_depth:
        raise ValueError("persisted first-violation depth does not match observation")


def _verify_execution_facts(row: ExecutionRow, execution: ExecutionResult) -> None:
    if row.outcome != execution.outcome.value:
        raise ValueError("persisted execution outcome does not match observation")
    if row.objective_violated != execution.objective_violated:
        raise ValueError("persisted objective violation does not match observation")
    if row.model_compromise != execution.model_compromise:
        raise ValueError("persisted model compromise does not match observation")
    if row.system_compromise != execution.system_compromise:
        raise ValueError("persisted system compromise does not match observation")
    if row.confidence != execution.confidence:
        raise ValueError("persisted confidence does not match observation")
    if row.error_kind != execution.error_kind:
        raise ValueError("persisted error kind does not match observation")


def _observation_from_row(
    session: Session,
    row: RedAblationObservationRow,
) -> PairedRedObservation:
    execution = session.get(ExecutionRow, row.execution_id)
    if execution is None:
        raise ValueError("stored Red ablation observation references missing execution")
    attack = session.get(AttackRow, execution.attack_instance_id)
    target = session.get(TargetSnapshotRow, execution.target_snapshot_id)
    if attack is None or target is None:
        raise ValueError("stored Red ablation observation has broken execution references")

    result = ExecutionResult(
        execution_id=execution.execution_id,
        attack_id=attack.case_id,
        target_id=target.target_id,
        outcome=CompromiseOutcome(execution.outcome),
        objective_violated=execution.objective_violated,
        model_compromise=execution.model_compromise,
        system_compromise=execution.system_compromise,
        confidence=execution.confidence,
        error_kind=execution.error_kind,
    )
    return PairedRedObservation(
        arm=AblationArm(row.arm),
        case_id=row.case_id,
        replicate=row.replicate,
        policy_fingerprint=row.policy_fingerprint,
        pair_seed=row.pair_seed,
        execution=result,
        target_interactions=row.target_interactions,
        backtracks=row.backtracks,
        branches_created=row.branches_created,
        first_violation_ordinal=row.first_violation_ordinal,
        first_violation_depth=row.first_violation_depth,
        planner_calls=row.planner_calls,
        mutator_calls=row.mutator_calls,
        planner_output_tokens=row.planner_output_tokens,
        mutator_output_tokens=row.mutator_output_tokens,
        elapsed_seconds=row.elapsed_seconds,
    )


def _observation_payload(
    *,
    experiment_id: str,
    campaign_id: str,
    observation: PairedRedObservation,
) -> dict[str, object]:
    execution = observation.execution
    return {
        "experiment_id": experiment_id,
        "campaign_id": campaign_id,
        "arm": observation.arm.value,
        "case_id": observation.case_id,
        "replicate": observation.replicate,
        "execution_id": execution.execution_id,
        "pair_seed": observation.pair_seed,
        "policy_fingerprint": observation.policy_fingerprint,
        "outcome": execution.outcome.value,
        "objective_violated": execution.objective_violated,
        "model_compromise": execution.model_compromise,
        "system_compromise": execution.system_compromise,
        "confidence": execution.confidence,
        "error_kind": execution.error_kind,
        "target_interactions": observation.target_interactions,
        "backtracks": observation.backtracks,
        "branches_created": observation.branches_created,
        "first_violation_ordinal": observation.first_violation_ordinal,
        "first_violation_depth": observation.first_violation_depth,
        "planner_calls": observation.planner_calls,
        "mutator_calls": observation.mutator_calls,
        "planner_output_tokens": observation.planner_output_tokens,
        "mutator_output_tokens": observation.mutator_output_tokens,
        "elapsed_seconds": observation.elapsed_seconds,
    }


def _expected_campaign(
    experiment: RedAblationExperimentSnapshot,
    arm: AblationArm,
) -> str:
    return (
        experiment.baseline_campaign_id
        if arm == AblationArm.BASELINE
        else experiment.treatment_campaign_id
    )


def _experiment_content_hash(snapshot: RedAblationExperimentSnapshot) -> str:
    return _canonical_hash(snapshot.model_dump(mode="json", exclude={"content_hash"}))


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
