from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import (
    CompromiseOutcome,
    EvidenceKind,
    EvidenceRecord,
    ExecutionResult,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from llm_redteam.storage.models import EvidenceRow
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.base import SessionMode


def _evidence(*, source: str, marker: str) -> EvidenceRecord:
    return EvidenceRecord(
        kind=EvidenceKind.METADATA,
        source=source,
        observed_at="runtime",
        content_hash=sha256(marker.encode()).hexdigest(),
        data={"marker": marker},
        redacted=True,
    )


def test_save_conversation_persists_execution_only_evidence_without_turn_duplicates() -> None:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = TargetIdentity(
        id="evidence-target",
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        model="deterministic",
        provider="test",
        runtime="python",
        configuration_hash=sha256(b"evidence-target").hexdigest(),
        capabilities=frozenset({"text"}),
    )
    target_snapshot_id = repository.save_target(target)
    repository.start_campaign(
        campaign_id="campaign-evidence",
        target_snapshot_id=target_snapshot_id,
        configuration_hash=sha256(b"campaign-evidence").hexdigest(),
    )
    repository.record_attack(
        attack_instance_id="attack-evidence",
        campaign_id="campaign-evidence",
        case_id="case-evidence",
        attack_family="persistence_regression",
        interaction_mode="multi_turn",
    )

    repeated_turn_evidence = _evidence(source="turn-source", marker="same-observation")
    teardown_evidence = _evidence(source="trusted-teardown", marker="cleanup-complete")
    turns = (
        ConversationTurn(
            turn_id="turn-1",
            ordinal=1,
            depth=1,
            branch_id="b0",
            attacker_message="first synthetic turn",
            target_response="safe response",
            outcome=CompromiseOutcome.PASS,
            evidence=(repeated_turn_evidence,),
        ),
        ConversationTurn(
            turn_id="turn-2",
            ordinal=2,
            depth=2,
            branch_id="b0",
            parent_turn_id="turn-1",
            attacker_message="second synthetic turn",
            target_response="safe response",
            outcome=CompromiseOutcome.PASS,
            evidence=(repeated_turn_evidence,),
        ),
    )
    execution = ExecutionResult(
        execution_id="exec-evidence",
        attack_id="case-evidence",
        target_id=target.id,
        outcome=CompromiseOutcome.PASS,
        objective_violated=False,
        model_compromise=False,
        system_compromise=False,
        confidence=1.0,
        evidence=(
            repeated_turn_evidence,
            repeated_turn_evidence,
            teardown_evidence,
        ),
    )
    conversation = ConversationRunResult(
        execution=execution,
        conversation_id="conversation-evidence",
        session_mode=SessionMode.REPLAY,
        turns=turns,
        backtracks=0,
        branches=1,
        flow_fingerprint=sha256(b"conversation-flow").hexdigest(),
    )

    repository.save_conversation(
        conversation,
        attack_instance_id="attack-evidence",
        target_snapshot_id=target_snapshot_id,
    )

    with Session(repository.engine) as session:
        rows = session.scalars(
            select(EvidenceRow)
            .where(EvidenceRow.execution_id == execution.execution_id)
            .order_by(EvidenceRow.evidence_id)
        ).all()

    assert len(rows) == 3
    assert [(row.source, row.turn_id) for row in rows] == [
        ("turn-source", "turn-1"),
        ("turn-source", "turn-2"),
        ("trusted-teardown", None),
    ]

    loaded = repository.load_execution(execution.execution_id)
    assert loaded is not None
    assert [record.source for record in loaded.evidence] == [
        "turn-source",
        "turn-source",
        "trusted-teardown",
    ]
