"""Transactional persistence API for experiment evidence and genealogy."""

from __future__ import annotations

import json
from hashlib import sha256

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from ..campaigns.multiturn import ConversationRunResult
from ..domain import EvidenceKind, EvidenceRecord, ExecutionResult, TargetIdentity
from ..forensics import ForensicReport
from .ablation_models import RedAblationExperimentRow, RedAblationObservationRow
from .analysis_models import ForensicReportRow
from .analysis_repository import AnalysisPersistenceMixin
from .blue_repository import BlueKnowledgePersistenceMixin
from .calibration_models import JudgeCalibrationObservationRow, JudgeCalibrationRunRow
from .measurement_models import CampaignMeasurementProtocolRow
from .models import (
    AttackRow,
    Base,
    CampaignRow,
    ConversationRow,
    EvidenceRow,
    ExecutionRow,
    TargetSnapshotRow,
    TurnRow,
)


class ExperimentRepository(AnalysisPersistenceMixin, BlueKnowledgePersistenceMixin):
    """Persist normalized experiment facts without storing raw prompts by default."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    @classmethod
    def from_url(cls, url: str, *, echo: bool = False) -> ExperimentRepository:
        return cls(create_engine(url, echo=echo))

    def create_schema(self) -> None:
        # Explicit references keep extension tables registered even when callers
        # import ExperimentRepository directly from storage.repository.
        _ = CampaignMeasurementProtocolRow.__table__
        _ = RedAblationExperimentRow.__table__
        _ = RedAblationObservationRow.__table__
        _ = JudgeCalibrationRunRow.__table__
        _ = JudgeCalibrationObservationRow.__table__
        Base.metadata.create_all(self.engine)

    def save_target(self, target: TargetIdentity) -> str:
        snapshot_id = self.target_snapshot_id(target)
        with Session(self.engine) as session, session.begin():
            if session.get(TargetSnapshotRow, snapshot_id) is None:
                session.add(
                    TargetSnapshotRow(
                        snapshot_id=snapshot_id,
                        target_id=target.id,
                        configuration_hash=target.configuration_hash,
                        target_class=target.target_class.value,
                        target_mode=target.target_mode.value,
                        model=target.model,
                        provider=target.provider,
                        runtime=target.runtime,
                        model_digest=target.model_digest,
                        application=target.application,
                        application_version=target.application_version,
                        system_prompt_hash=target.system_prompt_hash,
                        capabilities=sorted(target.capabilities),
                    )
                )
        return snapshot_id

    def start_campaign(
        self,
        *,
        campaign_id: str,
        target_snapshot_id: str,
        configuration_hash: str,
        metric_definition_version: str = "v1",
    ) -> None:
        with Session(self.engine) as session, session.begin():
            if session.get(TargetSnapshotRow, target_snapshot_id) is None:
                raise ValueError(f"unknown target snapshot: {target_snapshot_id}")
            if session.get(CampaignRow, campaign_id) is not None:
                raise ValueError(f"campaign already exists: {campaign_id}")
            session.add(
                CampaignRow(
                    campaign_id=campaign_id,
                    target_snapshot_id=target_snapshot_id,
                    configuration_hash=configuration_hash,
                    metric_definition_version=metric_definition_version,
                )
            )

    def record_attack(
        self,
        *,
        attack_instance_id: str,
        campaign_id: str,
        case_id: str,
        attack_family: str,
        interaction_mode: str,
        generation: int = 0,
        parent_attack_instance_id: str | None = None,
        hypothesis_id: str | None = None,
        payload_hash: str | None = None,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            if session.get(CampaignRow, campaign_id) is None:
                raise ValueError(f"unknown campaign: {campaign_id}")
            if session.get(AttackRow, attack_instance_id) is not None:
                raise ValueError(f"attack instance already exists: {attack_instance_id}")
            if (
                parent_attack_instance_id is not None
                and session.get(AttackRow, parent_attack_instance_id) is None
            ):
                raise ValueError(f"unknown parent attack: {parent_attack_instance_id}")
            session.add(
                AttackRow(
                    attack_instance_id=attack_instance_id,
                    campaign_id=campaign_id,
                    case_id=case_id,
                    parent_attack_instance_id=parent_attack_instance_id,
                    hypothesis_id=hypothesis_id,
                    attack_family=attack_family,
                    generation=generation,
                    interaction_mode=interaction_mode,
                    payload_hash=payload_hash,
                )
            )

    def save_execution(
        self,
        result: ExecutionResult,
        *,
        attack_instance_id: str,
        target_snapshot_id: str,
    ) -> None:
        with Session(self.engine) as session, session.begin():
            self._add_execution(
                session,
                result,
                attack_instance_id=attack_instance_id,
                target_snapshot_id=target_snapshot_id,
            )
            self._add_evidence(session, result.execution_id, None, result.evidence)

    def save_conversation(
        self,
        result: ConversationRunResult,
        *,
        attack_instance_id: str,
        target_snapshot_id: str,
    ) -> None:
        """Atomically persist execution, conversation tree, turns and evidence."""

        with Session(self.engine) as session, session.begin():
            self._add_execution(
                session,
                result.execution,
                attack_instance_id=attack_instance_id,
                target_snapshot_id=target_snapshot_id,
            )
            session.add(
                ConversationRow(
                    conversation_id=result.conversation_id,
                    execution_id=result.execution.execution_id,
                    session_mode=result.session_mode.value,
                    flow_fingerprint=result.flow_fingerprint,
                    turn_count=len(result.turns),
                    backtracks=result.backtracks,
                    branches=result.branches,
                    first_violation_turn_id=result.first_violation_turn_id,
                    first_violation_ordinal=result.first_violation_ordinal,
                    first_violation_depth=result.first_violation_depth,
                )
            )
            session.flush()

            for turn in result.turns:
                judgment = turn.judgment
                session.add(
                    TurnRow(
                        turn_id=turn.turn_id,
                        conversation_id=result.conversation_id,
                        ordinal=turn.ordinal,
                        depth=turn.depth,
                        branch_id=turn.branch_id,
                        parent_turn_id=turn.parent_turn_id,
                        attacker_message_hash=self.content_hash(turn.attacker_message),
                        target_response_hash=(
                            self.content_hash(turn.target_response)
                            if turn.target_response is not None
                            else None
                        ),
                        outcome=turn.outcome.value,
                        objective_violated=(
                            judgment.objective_violated if judgment is not None else None
                        ),
                        model_compromise=(
                            judgment.model_compromise if judgment is not None else None
                        ),
                        system_compromise=(
                            judgment.system_compromise if judgment is not None else None
                        ),
                        confidence=judgment.confidence if judgment is not None else None,
                        judge_type=judgment.judge_type if judgment is not None else None,
                        error_kind=turn.error_kind,
                    )
                )
            session.flush()

            for turn in result.turns:
                self._add_evidence(
                    session,
                    result.execution.execution_id,
                    turn.turn_id,
                    turn.evidence,
                )
            self._add_evidence(
                session,
                result.execution.execution_id,
                None,
                self._execution_only_evidence(result),
            )

    def save_forensic_report(
        self,
        report: ForensicReport,
        *,
        analysis_version: str = "v1",
    ) -> str:
        """Persist derived root-cause analysis without storing raw evidence content."""

        if not analysis_version:
            raise ValueError("analysis_version must be non-empty")
        report_id = self.forensic_report_id(report.execution_id, analysis_version)
        with Session(self.engine) as session, session.begin():
            if session.get(ExecutionRow, report.execution_id) is None:
                raise ValueError(f"unknown execution: {report.execution_id}")
            if session.get(ForensicReportRow, report_id) is not None:
                raise ValueError(f"forensic report already exists: {report_id}")
            session.add(
                ForensicReportRow(
                    forensic_report_id=report_id,
                    execution_id=report.execution_id,
                    analysis_version=analysis_version,
                    status=report.status.value,
                    reproduction_status=report.reproduction_status.value,
                    attack_family=list(report.attack_family),
                    model_compromise=report.model_compromise,
                    system_compromise=report.system_compromise,
                    failure_layer=report.failure_layer,
                    proximate_cause=report.proximate_cause,
                    enabling_conditions=list(report.enabling_conditions),
                    controls_effective=list(report.controls_effective),
                    controls_bypassed=list(report.controls_bypassed),
                    supporting_evidence_refs=list(report.supporting_evidence_refs),
                    necessary_component_ids=list(report.necessary_component_ids),
                    alternative_explanations=list(report.alternative_explanations),
                    confidence=report.confidence,
                    summary=report.summary,
                    error_kind=report.error_kind,
                )
            )
        return report_id

    def load_execution(self, execution_id: str) -> ExecutionResult | None:
        with Session(self.engine) as session:
            row = session.get(ExecutionRow, execution_id)
            if row is None:
                return None
            evidence_rows = session.scalars(
                select(EvidenceRow)
                .where(EvidenceRow.execution_id == execution_id)
                .order_by(EvidenceRow.evidence_id)
            ).all()
            evidence = tuple(
                EvidenceRecord(
                    kind=EvidenceKind(item.kind),
                    source=item.source,
                    observed_at=item.observed_at,
                    content_hash=item.content_hash,
                    artifact_ref=item.artifact_ref,
                    data=item.data,
                    redacted=item.redacted,
                )
                for item in evidence_rows
            )
            from ..domain import CompromiseOutcome

            return ExecutionResult(
                execution_id=row.execution_id,
                attack_id=self._case_id_for_attack(session, row.attack_instance_id),
                target_id=self._target_id_for_snapshot(session, row.target_snapshot_id),
                outcome=CompromiseOutcome(row.outcome),
                objective_violated=row.objective_violated,
                model_compromise=row.model_compromise,
                system_compromise=row.system_compromise,
                confidence=row.confidence,
                evidence=evidence,
                error_kind=row.error_kind,
            )

    @staticmethod
    def target_snapshot_fingerprint(target: TargetIdentity) -> str:
        """Hash the complete normalized security-target identity deterministically."""

        payload = {
            "id": target.id,
            "target_class": target.target_class.value,
            "target_mode": target.target_mode.value,
            "model": target.model,
            "provider": target.provider,
            "runtime": target.runtime,
            "model_digest": target.model_digest,
            "application": target.application,
            "application_version": target.application_version,
            "system_prompt_hash": target.system_prompt_hash,
            "configuration_hash": target.configuration_hash,
            "capabilities": sorted(target.capabilities),
        }
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return sha256(raw.encode()).hexdigest()

    @staticmethod
    def target_snapshot_id(target: TargetIdentity) -> str:
        digest = ExperimentRepository.target_snapshot_fingerprint(target)
        return f"target-{digest[:24]}"

    @staticmethod
    def forensic_report_id(execution_id: str, analysis_version: str) -> str:
        digest = sha256(f"{execution_id}:{analysis_version}".encode()).hexdigest()[:24]
        return f"forensic-{digest}"

    @staticmethod
    def content_hash(content: str) -> str:
        return sha256(content.encode()).hexdigest()

    @staticmethod
    def _execution_only_evidence(
        result: ConversationRunResult,
    ) -> tuple[EvidenceRecord, ...]:
        """Return execution evidence not already persisted against a conversation turn.

        Execution evidence normally contains the flattened turn evidence. Some trusted
        control-plane facts (for example fixture or isolation teardown proofs) are added
        only after the bounded conversation has finished. Treat evidence as a multiset so
        structurally identical records from different turns are each consumed once rather
        than accidentally collapsing legitimate repeated observations.
        """

        remaining = list(result.execution.evidence)
        for turn in result.turns:
            for record in turn.evidence:
                try:
                    remaining.remove(record)
                except ValueError:
                    continue
        return tuple(remaining)

    @staticmethod
    def _add_execution(
        session: Session,
        result: ExecutionResult,
        *,
        attack_instance_id: str,
        target_snapshot_id: str,
    ) -> None:
        attack = session.get(AttackRow, attack_instance_id)
        if attack is None:
            raise ValueError(f"unknown attack instance: {attack_instance_id}")
        target = session.get(TargetSnapshotRow, target_snapshot_id)
        if target is None:
            raise ValueError(f"unknown target snapshot: {target_snapshot_id}")
        campaign = session.get(CampaignRow, attack.campaign_id)
        if campaign is None:
            raise RuntimeError(f"broken attack reference to campaign: {attack.campaign_id}")
        if campaign.target_snapshot_id != target_snapshot_id:
            raise ValueError(
                "execution target snapshot does not match attack campaign target snapshot"
            )
        if result.attack_id != attack.case_id:
            raise ValueError("execution attack_id does not match attack case_id")
        if result.target_id != target.target_id:
            raise ValueError("execution target_id does not match target snapshot")
        if session.get(ExecutionRow, result.execution_id) is not None:
            raise ValueError(f"execution already exists: {result.execution_id}")
        session.add(
            ExecutionRow(
                execution_id=result.execution_id,
                attack_instance_id=attack_instance_id,
                target_snapshot_id=target_snapshot_id,
                outcome=result.outcome.value,
                objective_violated=result.objective_violated,
                model_compromise=result.model_compromise,
                system_compromise=result.system_compromise,
                confidence=result.confidence,
                error_kind=result.error_kind,
            )
        )
        session.flush()

    @staticmethod
    def _add_evidence(
        session: Session,
        execution_id: str,
        turn_id: str | None,
        evidence: tuple[EvidenceRecord, ...],
    ) -> None:
        for record in evidence:
            session.add(
                EvidenceRow(
                    execution_id=execution_id,
                    turn_id=turn_id,
                    kind=record.kind.value,
                    source=record.source,
                    observed_at=record.observed_at,
                    content_hash=record.content_hash,
                    artifact_ref=record.artifact_ref,
                    data=record.data,
                    redacted=record.redacted,
                )
            )

    @staticmethod
    def _case_id_for_attack(session: Session, attack_instance_id: str) -> str:
        attack = session.get(AttackRow, attack_instance_id)
        if attack is None:
            raise RuntimeError(f"broken execution reference to attack: {attack_instance_id}")
        return attack.case_id

    @staticmethod
    def _target_id_for_snapshot(session: Session, target_snapshot_id: str) -> str:
        target = session.get(TargetSnapshotRow, target_snapshot_id)
        if target is None:
            raise RuntimeError(f"broken execution reference to target: {target_snapshot_id}")
        return target.target_id
