import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from llm_redteam.domain import CompromiseOutcome, ExecutionResult, FindingStatus
from llm_redteam.forensics import ForensicReport, ForensicStatus
from llm_redteam.storage.analysis_models import ForensicReportRow
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget


def _execution() -> ExecutionResult:
    return ExecutionResult(
        execution_id="exec-forensic-storage",
        attack_id="case-forensic-storage",
        target_id="escalating-vault-target",
        outcome=CompromiseOutcome.MODEL_COMPROMISE,
        objective_violated=True,
        model_compromise=True,
        system_compromise=False,
        confidence=1.0,
    )


def _report() -> ForensicReport:
    return ForensicReport(
        status=ForensicStatus.ANALYZED,
        execution_id="exec-forensic-storage",
        attack_id="case-forensic-storage",
        target_id="escalating-vault-target",
        model_compromise=True,
        system_compromise=False,
        reproduction_status=FindingStatus.CONFIRMED,
        failure_layer="instruction_hierarchy",
        proximate_cause="Untrusted synthetic context influenced model behavior.",
        enabling_conditions=("context provenance was not enforced",),
        controls_effective=("tool authorization remained intact",),
        controls_bypassed=("model instruction boundary",),
        supporting_evidence_refs=("ev-123",),
        necessary_component_ids=("turn-1",),
        alternative_explanations=("prompt-specific instability",),
        confidence=0.86,
        summary="Synthetic model compromise was reproducible and evidence-grounded.",
    )


def _repository_with_execution() -> ExperimentRepository:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = EscalatingVaultTarget()
    snapshot_id = repository.save_target(target.identity)
    repository.start_campaign(
        campaign_id="campaign-forensic-storage",
        target_snapshot_id=snapshot_id,
        configuration_hash="campaign-config-hash",
    )
    repository.record_attack(
        attack_instance_id="attack-forensic-storage",
        campaign_id="campaign-forensic-storage",
        case_id="case-forensic-storage",
        attack_family="multi_turn_escalation",
        interaction_mode="multi_turn",
    )
    repository.save_execution(
        _execution(),
        attack_instance_id="attack-forensic-storage",
        target_snapshot_id=snapshot_id,
    )
    return repository


def test_forensic_report_persists_as_versioned_derived_analysis() -> None:
    repository = _repository_with_execution()

    report_id = repository.save_forensic_report(_report(), analysis_version="v1")

    with Session(repository.engine) as session:
        row = session.get(ForensicReportRow, report_id)
        assert row is not None
        assert row.execution_id == "exec-forensic-storage"
        assert row.analysis_version == "v1"
        assert row.status == ForensicStatus.ANALYZED.value
        assert row.model_compromise is True
        assert row.system_compromise is False
        assert row.supporting_evidence_refs == ["ev-123"]
        assert row.necessary_component_ids == ["turn-1"]


def test_forensic_schema_does_not_add_raw_target_or_attacker_prompt_columns() -> None:
    columns = {column.name for column in inspect(ForensicReportRow).columns}

    assert "attacker_message" not in columns
    assert "target_response" not in columns
    assert "raw_prompt" not in columns
    assert "supporting_evidence_refs" in columns


def test_same_execution_and_analysis_version_cannot_be_silently_overwritten() -> None:
    repository = _repository_with_execution()
    repository.save_forensic_report(_report(), analysis_version="v1")

    with pytest.raises(ValueError, match="forensic report already exists"):
        repository.save_forensic_report(_report(), analysis_version="v1")


def test_new_analysis_version_is_preserved_as_separate_report() -> None:
    repository = _repository_with_execution()

    first = repository.save_forensic_report(_report(), analysis_version="v1")
    second = repository.save_forensic_report(_report(), analysis_version="v2")

    assert first != second
    with Session(repository.engine) as session:
        assert session.get(ForensicReportRow, first) is not None
        assert session.get(ForensicReportRow, second) is not None
