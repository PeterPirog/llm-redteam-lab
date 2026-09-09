import pytest
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from llm_redteam.counterfactuals import ComponentCounterfactual, CounterfactualResult
from llm_redteam.domain import CompromiseOutcome, ExecutionResult, FindingStatus
from llm_redteam.metrics import wilson_rate
from llm_redteam.minimization import (
    AttackComponent,
    AttackComponentKind,
    AttackVariant,
    MinimizationResult,
    MinimizationStatus,
    VariantAssessment,
)
from llm_redteam.reproduction import ReproductionResult
from llm_redteam.storage.analysis_models import (
    CounterfactualComponentRow,
    CounterfactualRunRow,
    MinimizationRunRow,
    MinimizedComponentRow,
    ReproductionAttemptRow,
    ReproductionRunRow,
)
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

CASE_ID = "ANALYSIS-PERSIST-001"
TARGET_ID = "escalating-vault-target"


def _execution(
    execution_id: str,
    *,
    violated: bool = True,
    target_id: str = TARGET_ID,
) -> ExecutionResult:
    return ExecutionResult(
        execution_id=execution_id,
        attack_id=CASE_ID,
        target_id=target_id,
        outcome=(
            CompromiseOutcome.MODEL_COMPROMISE
            if violated
            else CompromiseOutcome.PASS
        ),
        objective_violated=violated,
        model_compromise=violated,
        system_compromise=False,
        confidence=1.0,
    )


def _setup_repository() -> tuple[ExperimentRepository, str]:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = EscalatingVaultTarget(canary="RT_CANARY_PINEAPPLE_739")
    snapshot_id = repository.save_target(target.identity)
    repository.start_campaign(
        campaign_id="campaign-analysis",
        target_snapshot_id=snapshot_id,
        configuration_hash="campaign-analysis-config",
        metric_definition_version="v1",
    )
    repository.record_attack(
        attack_instance_id="attack-original",
        campaign_id="campaign-analysis",
        case_id=CASE_ID,
        attack_family="multi_turn_escalation",
        interaction_mode="single_turn",
        payload_hash="payload-original",
    )
    return repository, snapshot_id


def _save_execution(
    repository: ExperimentRepository,
    snapshot_id: str,
    execution: ExecutionResult,
    *,
    attack_instance_id: str = "attack-original",
) -> None:
    repository.save_execution(
        execution,
        attack_instance_id=attack_instance_id,
        target_snapshot_id=snapshot_id,
    )


def _record_variant_attack(
    repository: ExperimentRepository,
    *,
    attack_instance_id: str,
    payload_hash: str,
) -> None:
    repository.record_attack(
        attack_instance_id=attack_instance_id,
        campaign_id="campaign-analysis",
        case_id=CASE_ID,
        attack_family="multi_turn_escalation",
        interaction_mode="single_turn",
        payload_hash=payload_hash,
    )


def test_execution_cannot_be_saved_under_snapshot_outside_attack_campaign() -> None:
    repository, _ = _setup_repository()
    other_target = EscalatingVaultTarget(canary="RT_CANARY_DIFFERENT_001")
    other_snapshot = repository.save_target(other_target.identity)

    with pytest.raises(ValueError, match="campaign target snapshot"):
        _save_execution(
            repository,
            other_snapshot,
            _execution("exec-wrong-snapshot"),
        )


def test_execution_case_and_target_identity_are_checked_against_persistence_context() -> None:
    repository, snapshot_id = _setup_repository()
    wrong_case = _execution("exec-wrong-case").model_copy(update={"attack_id": "OTHER"})
    wrong_target = _execution("exec-wrong-target", target_id="other-target")

    with pytest.raises(ValueError, match="attack_id"):
        _save_execution(repository, snapshot_id, wrong_case)
    with pytest.raises(ValueError, match="target_id"):
        _save_execution(repository, snapshot_id, wrong_target)


def test_reproduction_persists_only_compatible_repeat_executions() -> None:
    repository, snapshot_id = _setup_repository()
    original = _execution("exec-original")
    repeat_1 = _execution("exec-repeat-1")
    repeat_2 = _execution("exec-repeat-2")
    for execution in (original, repeat_1, repeat_2):
        _save_execution(repository, snapshot_id, execution)

    result = ReproductionResult(
        original_execution_id=original.execution_id,
        requested_attempts=2,
        conclusive_attempts=2,
        successful_reproductions=2,
        unresolved_attempts=0,
        status=FindingStatus.REPRODUCIBLE,
        reproduction_rate=wilson_rate(2, 2),
        attempts=(repeat_1, repeat_2),
    )

    reproduction_id = repository.save_reproduction(result)

    with Session(repository.engine) as session:
        row = session.get(ReproductionRunRow, reproduction_id)
        assert row is not None
        assert row.status == FindingStatus.REPRODUCIBLE.value
        assert row.experiment_fingerprint == repository.execution_fingerprint(
            original.execution_id
        )
        attempts = session.scalars(
            select(ReproductionAttemptRow)
            .where(ReproductionAttemptRow.reproduction_id == reproduction_id)
            .order_by(ReproductionAttemptRow.ordinal)
        ).all()
        assert [item.execution_id for item in attempts] == [
            repeat_1.execution_id,
            repeat_2.execution_id,
        ]


def test_reproduction_rejects_repeat_from_different_blue_configuration() -> None:
    repository, snapshot_id = _setup_repository()
    original = _execution("exec-original")
    _save_execution(repository, snapshot_id, original)

    other_target = EscalatingVaultTarget(canary="RT_CANARY_DIFFERENT_002")
    other_snapshot = repository.save_target(other_target.identity)
    repository.start_campaign(
        campaign_id="campaign-other",
        target_snapshot_id=other_snapshot,
        configuration_hash="campaign-analysis-config",
        metric_definition_version="v1",
    )
    repository.record_attack(
        attack_instance_id="attack-other",
        campaign_id="campaign-other",
        case_id=CASE_ID,
        attack_family="multi_turn_escalation",
        interaction_mode="single_turn",
        payload_hash="payload-original",
    )
    repeat = _execution("exec-repeat-other")
    repository.save_execution(
        repeat,
        attack_instance_id="attack-other",
        target_snapshot_id=other_snapshot,
    )
    result = ReproductionResult(
        original_execution_id=original.execution_id,
        requested_attempts=1,
        conclusive_attempts=1,
        successful_reproductions=1,
        unresolved_attempts=0,
        status=FindingStatus.REPRODUCIBLE,
        reproduction_rate=wilson_rate(1, 1),
        attempts=(repeat,),
    )

    with pytest.raises(ValueError, match="experiment fingerprint"):
        repository.save_reproduction(result)


def test_minimization_persists_hashed_components_and_candidate_evidence() -> None:
    repository, snapshot_id = _setup_repository()
    reference = _execution("exec-min-reference")
    _save_execution(repository, snapshot_id, reference)
    _record_variant_attack(
        repository,
        attack_instance_id="attack-min-a",
        payload_hash="payload-a",
    )
    candidate_1 = _execution("exec-min-a-1")
    candidate_2 = _execution("exec-min-a-2")
    for execution in (candidate_1, candidate_2):
        _save_execution(
            repository,
            snapshot_id,
            execution,
            attack_instance_id="attack-min-a",
        )

    component_a = AttackComponent(
        component_id="a",
        kind=AttackComponentKind.TEXT_SEGMENT,
        content="synthetic necessary component",
    )
    component_b = AttackComponent(
        component_id="b",
        kind=AttackComponentKind.TEXT_SEGMENT,
        content="synthetic removable component",
    )
    assessment = VariantAssessment(
        component_ids=("a",),
        preserved=True,
        successful_attempts=2,
        conclusive_failures=0,
        unresolved_attempts=0,
        executions=(candidate_1, candidate_2),
    )
    result = MinimizationResult(
        status=MinimizationStatus.COMPLETE,
        original=AttackVariant(
            attack_id=CASE_ID,
            components=(component_a, component_b),
        ),
        minimized=AttackVariant(attack_id=CASE_ID, components=(component_a,)),
        removed_component_ids=("b",),
        target_executions=2,
        assessments=(assessment,),
    )

    minimization_id = repository.save_minimization(
        result,
        reference_execution_id=reference.execution_id,
    )

    with Session(repository.engine) as session:
        row = session.get(MinimizationRunRow, minimization_id)
        assert row is not None
        assert row.minimized_component_count == 1
        component_row = session.scalar(
            select(MinimizedComponentRow).where(
                MinimizedComponentRow.minimization_id == minimization_id
            )
        )
        assert component_row is not None
        assert component_row.component_id == "a"
        assert component_row.content_hash != component_a.content

    columns = {column.name for column in inspect(MinimizedComponentRow).columns}
    assert "content" not in columns
    assert "content_hash" in columns


def test_minimization_rejects_candidate_execution_from_different_environment() -> None:
    repository, snapshot_id = _setup_repository()
    reference = _execution("exec-reference")
    _save_execution(repository, snapshot_id, reference)

    other_target = EscalatingVaultTarget(canary="RT_CANARY_DIFFERENT_003")
    other_snapshot = repository.save_target(other_target.identity)
    repository.start_campaign(
        campaign_id="campaign-other-min",
        target_snapshot_id=other_snapshot,
        configuration_hash="different-campaign-config",
    )
    repository.record_attack(
        attack_instance_id="attack-other-min",
        campaign_id="campaign-other-min",
        case_id=CASE_ID,
        attack_family="multi_turn_escalation",
        interaction_mode="single_turn",
        payload_hash="candidate",
    )
    candidate = _execution("exec-other-min")
    repository.save_execution(
        candidate,
        attack_instance_id="attack-other-min",
        target_snapshot_id=other_snapshot,
    )
    component = AttackComponent(
        component_id="a",
        kind=AttackComponentKind.TEXT_SEGMENT,
        content="synthetic component",
    )
    assessment = VariantAssessment(
        component_ids=("a",),
        preserved=True,
        successful_attempts=1,
        conclusive_failures=0,
        unresolved_attempts=0,
        executions=(candidate,),
    )
    result = MinimizationResult(
        status=MinimizationStatus.COMPLETE,
        original=AttackVariant(attack_id=CASE_ID, components=(component,)),
        minimized=AttackVariant(attack_id=CASE_ID, components=(component,)),
        removed_component_ids=(),
        target_executions=1,
        assessments=(assessment,),
    )

    with pytest.raises(ValueError, match="reference environment"):
        repository.save_minimization(
            result,
            reference_execution_id=reference.execution_id,
        )


def test_counterfactuals_persist_conditional_component_evidence() -> None:
    repository, snapshot_id = _setup_repository()
    reference = _execution("exec-cf-reference")
    _save_execution(repository, snapshot_id, reference)
    _record_variant_attack(
        repository,
        attack_instance_id="attack-cf-without",
        payload_hash="payload-without",
    )
    _record_variant_attack(
        repository,
        attack_instance_id="attack-cf-alone",
        payload_hash="payload-alone",
    )
    without_1 = _execution("exec-cf-without-1")
    without_2 = _execution("exec-cf-without-2")
    alone_1 = _execution("exec-cf-alone-1", violated=False)
    alone_2 = _execution("exec-cf-alone-2", violated=False)
    for execution in (without_1, without_2):
        _save_execution(
            repository,
            snapshot_id,
            execution,
            attack_instance_id="attack-cf-without",
        )
    for execution in (alone_1, alone_2):
        _save_execution(
            repository,
            snapshot_id,
            execution,
            attack_instance_id="attack-cf-alone",
        )

    without = VariantAssessment(
        component_ids=("a",),
        preserved=True,
        successful_attempts=2,
        conclusive_failures=0,
        unresolved_attempts=0,
        executions=(without_1, without_2),
    )
    alone = VariantAssessment(
        component_ids=("b",),
        preserved=False,
        successful_attempts=0,
        conclusive_failures=1,
        unresolved_attempts=0,
        executions=(alone_1,),
    )
    result = CounterfactualResult(
        attack_id=CASE_ID,
        component_results=(
            ComponentCounterfactual(
                component_id="b",
                without_component=without,
                component_alone=alone,
                necessary_under_test=False,
                sufficient_under_test=False,
            ),
        ),
        evaluated_variants=2,
        target_executions=3,
    )

    counterfactual_id = repository.save_counterfactuals(
        result,
        reference_execution_id=reference.execution_id,
    )

    with Session(repository.engine) as session:
        run = session.get(CounterfactualRunRow, counterfactual_id)
        assert run is not None
        assert run.evaluated_variants == 2
        row = session.scalar(
            select(CounterfactualComponentRow).where(
                CounterfactualComponentRow.counterfactual_id == counterfactual_id
            )
        )
        assert row is not None
        assert row.component_id == "b"
        assert row.necessary_under_test is False
        assert row.sufficient_under_test is False
        assert row.without_execution_ids == [
            without_1.execution_id,
            without_2.execution_id,
        ]
