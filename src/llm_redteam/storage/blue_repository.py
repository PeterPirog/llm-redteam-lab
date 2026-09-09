"""Fail-closed persistence for Blue security controls and attributed evidence."""

from __future__ import annotations

from hashlib import sha256

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..blue import (
    BlueControlAssessment,
    BlueControlDefinition,
    ControlObservation,
    assess_control,
)
from .blue_models import BlueControlRow, ControlObservationRow
from .models import AttackRow, EvidenceRow, ExecutionRow, TargetSnapshotRow


class BlueKnowledgePersistenceMixin:
    """Persist Blue controls while deriving effectiveness from execution evidence."""

    engine: Engine

    def save_blue_control(self, control: BlueControlDefinition) -> str:
        profile_control_id = self.blue_profile_control_id(
            control.target_snapshot_id,
            control.control_id,
        )
        with Session(self.engine) as session, session.begin():
            if session.get(TargetSnapshotRow, control.target_snapshot_id) is None:
                raise ValueError(f"unknown target snapshot: {control.target_snapshot_id}")
            if session.get(BlueControlRow, profile_control_id) is not None:
                raise ValueError(f"blue control already exists: {profile_control_id}")
            session.add(
                BlueControlRow(
                    profile_control_id=profile_control_id,
                    target_snapshot_id=control.target_snapshot_id,
                    control_id=control.control_id,
                    name=control.name,
                    layer=control.layer,
                    description=control.description,
                    declared=control.declared,
                    retired=control.retired,
                    tags=list(control.tags),
                )
            )
        return profile_control_id

    def record_control_observation(self, observation: ControlObservation) -> None:
        """Persist one observation only if its execution context and evidence agree."""

        profile_control_id = self.blue_profile_control_id(
            observation.target_snapshot_id,
            observation.control_id,
        )
        with Session(self.engine) as session, session.begin():
            control = session.get(BlueControlRow, profile_control_id)
            if control is None:
                raise ValueError(f"unknown blue control: {profile_control_id}")
            if session.get(ControlObservationRow, observation.observation_id) is not None:
                raise ValueError(
                    f"control observation already exists: {observation.observation_id}"
                )
            execution = session.get(ExecutionRow, observation.execution_id)
            if execution is None:
                raise ValueError(f"unknown execution: {observation.execution_id}")
            if execution.target_snapshot_id != observation.target_snapshot_id:
                raise ValueError("control observation target snapshot does not match execution")
            attack = session.get(AttackRow, execution.attack_instance_id)
            if attack is None:
                raise RuntimeError(
                    f"broken execution reference to attack: {execution.attack_instance_id}"
                )
            if attack.attack_family != observation.attack_family:
                raise ValueError("control observation attack family does not match execution")

            actual_fingerprint = self.execution_fingerprint(observation.execution_id)
            if observation.experiment_fingerprint != actual_fingerprint:
                raise ValueError("control observation experiment fingerprint mismatch")

            if observation.source.authoritative_for_state:
                valid_refs = self._execution_evidence_refs(session, observation.execution_id)
                unknown = set(observation.evidence_refs).difference(valid_refs)
                if unknown:
                    raise ValueError(
                        "authoritative control observation cites unknown execution evidence"
                    )

            session.add(
                ControlObservationRow(
                    observation_id=observation.observation_id,
                    profile_control_id=profile_control_id,
                    target_snapshot_id=observation.target_snapshot_id,
                    execution_id=observation.execution_id,
                    control_event_id=observation.control_event_id,
                    attack_family=observation.attack_family,
                    experiment_fingerprint=observation.experiment_fingerprint,
                    kind=observation.kind.value,
                    source=observation.source.value,
                    evidence_refs=list(observation.evidence_refs),
                    confidence=observation.confidence,
                )
            )

    def evidence_refs_for_execution(self, execution_id: str) -> tuple[str, ...]:
        """Return stable database-local evidence references for direct control attribution."""

        with Session(self.engine) as session:
            if session.get(ExecutionRow, execution_id) is None:
                raise ValueError(f"unknown execution: {execution_id}")
            return tuple(sorted(self._execution_evidence_refs(session, execution_id)))

    def assess_blue_control(
        self,
        *,
        target_snapshot_id: str,
        control_id: str,
        attack_family: str,
        confidence_level: float = 0.95,
        previous: BlueControlAssessment | None = None,
    ) -> BlueControlAssessment:
        """Load evidence and deterministically derive the current control assessment."""

        profile_control_id = self.blue_profile_control_id(target_snapshot_id, control_id)
        with Session(self.engine) as session:
            row = session.get(BlueControlRow, profile_control_id)
            if row is None:
                raise ValueError(f"unknown blue control: {profile_control_id}")
            definition = BlueControlDefinition(
                control_id=row.control_id,
                target_snapshot_id=row.target_snapshot_id,
                name=row.name,
                layer=row.layer,
                description=row.description,
                declared=row.declared,
                retired=row.retired,
                tags=tuple(row.tags),
            )
            rows = session.scalars(
                select(ControlObservationRow)
                .where(ControlObservationRow.profile_control_id == profile_control_id)
                .where(ControlObservationRow.attack_family == attack_family)
                .order_by(ControlObservationRow.created_at, ControlObservationRow.observation_id)
            ).all()
            observations = tuple(
                ControlObservation(
                    observation_id=item.observation_id,
                    control_id=row.control_id,
                    target_snapshot_id=item.target_snapshot_id,
                    attack_family=item.attack_family,
                    execution_id=item.execution_id,
                    control_event_id=item.control_event_id,
                    experiment_fingerprint=item.experiment_fingerprint,
                    kind=item.kind,
                    source=item.source,
                    evidence_refs=tuple(item.evidence_refs),
                    confidence=item.confidence,
                )
                for item in rows
            )
        return assess_control(
            definition,
            observations,
            attack_family=attack_family,
            confidence_level=confidence_level,
            previous=previous,
        )

    @staticmethod
    def blue_profile_control_id(target_snapshot_id: str, control_id: str) -> str:
        digest = sha256(f"{target_snapshot_id}:{control_id}".encode()).hexdigest()[:24]
        return f"blue-control-{digest}"

    @staticmethod
    def _execution_evidence_refs(session: Session, execution_id: str) -> set[str]:
        rows = session.scalars(
            select(EvidenceRow)
            .where(EvidenceRow.execution_id == execution_id)
            .order_by(EvidenceRow.evidence_id)
        ).all()
        return {f"evidence:{item.evidence_id}" for item in rows}
