"""Persistence mixin for reproducibility, minimization and counterfactual artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..counterfactuals import CounterfactualResult
from ..minimization import MinimizationResult, VariantAssessment
from ..reproduction import ReproductionResult
from .analysis_models import (
    CounterfactualComponentRow,
    CounterfactualRunRow,
    MinimizationAssessmentRow,
    MinimizationRunRow,
    MinimizedComponentRow,
    ReproductionAttemptRow,
    ReproductionRunRow,
)
from .models import AttackRow, CampaignRow, ConversationRow, ExecutionRow, TargetSnapshotRow


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    execution_id: str
    target_snapshot_id: str
    attack_instance_id: str
    environment_fingerprint: str
    attack_fingerprint: str
    flow_fingerprint: str | None

    @property
    def reproduction_fingerprint(self) -> str:
        raw = "|".join(
            (
                self.environment_fingerprint,
                self.attack_fingerprint,
                self.flow_fingerprint or "single_turn",
            )
        )
        return sha256(raw.encode()).hexdigest()


class AnalysisPersistenceMixin:
    """Add fail-closed storage for derived analysis artifacts."""

    engine: Engine

    def execution_fingerprint(self, execution_id: str) -> str:
        """Return the reproducibility fingerprint for a persisted execution."""

        with Session(self.engine) as session:
            return self._execution_context(session, execution_id).reproduction_fingerprint

    def save_reproduction(
        self,
        result: ReproductionResult,
        *,
        analysis_version: str = "v1",
    ) -> str:
        """Persist reproduction only when every repeat matches the original setup."""

        self._require_version(analysis_version)
        reproduction_id = self._artifact_id(
            "reproduction", result.original_execution_id, analysis_version
        )
        with Session(self.engine) as session, session.begin():
            reference = self._execution_context(session, result.original_execution_id)
            if session.get(ReproductionRunRow, reproduction_id) is not None:
                raise ValueError(f"reproduction already exists: {reproduction_id}")

            for attempt in result.attempts:
                context = self._execution_context(session, attempt.execution_id)
                if context.reproduction_fingerprint != reference.reproduction_fingerprint:
                    raise ValueError(
                        "reproduction attempt does not match original experiment fingerprint: "
                        f"{attempt.execution_id}"
                    )

            rate = result.reproduction_rate
            session.add(
                ReproductionRunRow(
                    reproduction_id=reproduction_id,
                    original_execution_id=result.original_execution_id,
                    target_snapshot_id=reference.target_snapshot_id,
                    attack_instance_id=reference.attack_instance_id,
                    experiment_fingerprint=reference.reproduction_fingerprint,
                    analysis_version=analysis_version,
                    status=result.status.value,
                    requested_attempts=result.requested_attempts,
                    conclusive_attempts=result.conclusive_attempts,
                    successful_reproductions=result.successful_reproductions,
                    unresolved_attempts=result.unresolved_attempts,
                    rate_value=rate.value,
                    rate_ci_low=rate.ci_low,
                    rate_ci_high=rate.ci_high,
                    confidence_level=rate.confidence_level,
                    rate_method=rate.method,
                )
            )
            session.flush()
            for ordinal, attempt in enumerate(result.attempts, start=1):
                session.add(
                    ReproductionAttemptRow(
                        reproduction_attempt_id=f"{reproduction_id}-attempt-{ordinal}",
                        reproduction_id=reproduction_id,
                        execution_id=attempt.execution_id,
                        ordinal=ordinal,
                    )
                )
        return reproduction_id

    def save_minimization(
        self,
        result: MinimizationResult,
        *,
        reference_execution_id: str,
        analysis_version: str = "v1",
    ) -> str:
        """Persist a minimized attack and all candidate-assessment references."""

        self._require_version(analysis_version)
        minimization_id = self._artifact_id(
            "minimization", reference_execution_id, analysis_version
        )
        with Session(self.engine) as session, session.begin():
            reference = self._execution_context(session, reference_execution_id)
            if session.get(MinimizationRunRow, minimization_id) is not None:
                raise ValueError(f"minimization already exists: {minimization_id}")

            self._validate_assessment_environments(
                session,
                result.assessments,
                reference.environment_fingerprint,
            )
            session.add(
                MinimizationRunRow(
                    minimization_id=minimization_id,
                    reference_execution_id=reference_execution_id,
                    target_snapshot_id=reference.target_snapshot_id,
                    attack_instance_id=reference.attack_instance_id,
                    experiment_fingerprint=reference.environment_fingerprint,
                    analysis_version=analysis_version,
                    status=result.status.value,
                    original_component_count=len(result.original.components),
                    minimized_component_count=len(result.minimized.components),
                    removed_component_ids=list(result.removed_component_ids),
                    target_executions=result.target_executions,
                )
            )
            session.flush()

            for ordinal, component in enumerate(result.minimized.components, start=1):
                session.add(
                    MinimizedComponentRow(
                        minimized_component_id=f"{minimization_id}-component-{ordinal}",
                        minimization_id=minimization_id,
                        ordinal=ordinal,
                        component_id=component.component_id,
                        kind=component.kind.value,
                        content_hash=sha256(component.content.encode()).hexdigest(),
                        required=component.required,
                    )
                )

            for ordinal, assessment in enumerate(result.assessments, start=1):
                session.add(
                    MinimizationAssessmentRow(
                        minimization_assessment_id=(
                            f"{minimization_id}-assessment-{ordinal}"
                        ),
                        minimization_id=minimization_id,
                        ordinal=ordinal,
                        component_ids=list(assessment.component_ids),
                        preserved=assessment.preserved,
                        successful_attempts=assessment.successful_attempts,
                        conclusive_failures=assessment.conclusive_failures,
                        unresolved_attempts=assessment.unresolved_attempts,
                        execution_ids=[item.execution_id for item in assessment.executions],
                    )
                )
        return minimization_id

    def save_counterfactuals(
        self,
        result: CounterfactualResult,
        *,
        reference_execution_id: str,
        analysis_version: str = "v1",
    ) -> str:
        """Persist counterfactual interventions after environment compatibility checks."""

        self._require_version(analysis_version)
        counterfactual_id = self._artifact_id(
            "counterfactual", reference_execution_id, analysis_version
        )
        with Session(self.engine) as session, session.begin():
            reference = self._execution_context(session, reference_execution_id)
            if session.get(CounterfactualRunRow, counterfactual_id) is not None:
                raise ValueError(f"counterfactual result already exists: {counterfactual_id}")

            assessments = self._counterfactual_assessments(result)
            self._validate_assessment_environments(
                session,
                assessments,
                reference.environment_fingerprint,
            )
            empty = result.empty_baseline
            session.add(
                CounterfactualRunRow(
                    counterfactual_id=counterfactual_id,
                    reference_execution_id=reference_execution_id,
                    target_snapshot_id=reference.target_snapshot_id,
                    attack_instance_id=reference.attack_instance_id,
                    experiment_fingerprint=reference.environment_fingerprint,
                    analysis_version=analysis_version,
                    attack_id=result.attack_id,
                    evaluated_variants=result.evaluated_variants,
                    target_executions=result.target_executions,
                    truncated_by_budget=result.truncated_by_budget,
                    empty_baseline_preserved=empty.preserved if empty is not None else None,
                    empty_baseline_execution_ids=(
                        [item.execution_id for item in empty.executions]
                        if empty is not None
                        else []
                    ),
                )
            )
            session.flush()

            for item in result.component_results:
                without = item.without_component
                alone = item.component_alone
                digest = sha256(
                    f"{counterfactual_id}:{item.component_id}".encode()
                ).hexdigest()[:16]
                session.add(
                    CounterfactualComponentRow(
                        counterfactual_component_id=f"cf-component-{digest}",
                        counterfactual_id=counterfactual_id,
                        component_id=item.component_id,
                        necessary_under_test=item.necessary_under_test,
                        sufficient_under_test=item.sufficient_under_test,
                        without_component_preserved=(
                            without.preserved if without is not None else None
                        ),
                        component_alone_preserved=(
                            alone.preserved if alone is not None else None
                        ),
                        without_execution_ids=(
                            [execution.execution_id for execution in without.executions]
                            if without is not None
                            else []
                        ),
                        alone_execution_ids=(
                            [execution.execution_id for execution in alone.executions]
                            if alone is not None
                            else []
                        ),
                    )
                )
        return counterfactual_id

    @staticmethod
    def _require_version(analysis_version: str) -> None:
        if not analysis_version:
            raise ValueError("analysis_version must be non-empty")

    @staticmethod
    def _artifact_id(kind: str, execution_id: str, analysis_version: str) -> str:
        digest = sha256(
            f"{kind}:{execution_id}:{analysis_version}".encode()
        ).hexdigest()[:24]
        return f"{kind}-{digest}"

    @staticmethod
    def _counterfactual_assessments(
        result: CounterfactualResult,
    ) -> tuple[VariantAssessment, ...]:
        rows: list[VariantAssessment] = []
        if result.empty_baseline is not None:
            rows.append(result.empty_baseline)
        for item in result.component_results:
            if item.without_component is not None:
                rows.append(item.without_component)
            if item.component_alone is not None:
                rows.append(item.component_alone)
        return tuple(rows)

    def _validate_assessment_environments(
        self,
        session: Session,
        assessments: tuple[VariantAssessment, ...],
        expected_environment_fingerprint: str,
    ) -> None:
        for assessment in assessments:
            for execution in assessment.executions:
                context = self._execution_context(session, execution.execution_id)
                if context.environment_fingerprint != expected_environment_fingerprint:
                    raise ValueError(
                        "analysis execution does not match reference environment: "
                        f"{execution.execution_id}"
                    )

    @staticmethod
    def _execution_context(session: Session, execution_id: str) -> _ExecutionContext:
        execution = session.get(ExecutionRow, execution_id)
        if execution is None:
            raise ValueError(f"unknown execution: {execution_id}")
        attack = session.get(AttackRow, execution.attack_instance_id)
        if attack is None:
            raise RuntimeError(
                f"broken execution reference to attack: {execution.attack_instance_id}"
            )
        campaign = session.get(CampaignRow, attack.campaign_id)
        if campaign is None:
            raise RuntimeError(f"broken attack reference to campaign: {attack.campaign_id}")
        target = session.get(TargetSnapshotRow, execution.target_snapshot_id)
        if target is None:
            raise RuntimeError(
                f"broken execution reference to target: {execution.target_snapshot_id}"
            )
        conversation = session.scalar(
            select(ConversationRow).where(ConversationRow.execution_id == execution_id)
        )
        flow_fingerprint = conversation.flow_fingerprint if conversation is not None else None

        environment_raw = "|".join(
            (
                execution.target_snapshot_id,
                target.configuration_hash,
                campaign.configuration_hash,
                campaign.metric_definition_version,
            )
        )
        environment_fingerprint = sha256(environment_raw.encode()).hexdigest()

        attack_identity = attack.payload_hash or attack.attack_instance_id
        attack_raw = "|".join(
            (
                attack.case_id,
                attack.attack_family,
                attack.interaction_mode,
                attack_identity,
            )
        )
        attack_fingerprint = sha256(attack_raw.encode()).hexdigest()
        return _ExecutionContext(
            execution_id=execution_id,
            target_snapshot_id=execution.target_snapshot_id,
            attack_instance_id=execution.attack_instance_id,
            environment_fingerprint=environment_fingerprint,
            attack_fingerprint=attack_fingerprint,
            flow_fingerprint=flow_fingerprint,
        )
