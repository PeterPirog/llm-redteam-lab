import pytest

from llm_redteam.blue import (
    BlueControlDefinition,
    BlueControlState,
    ControlEvidenceSource,
    ControlObservation,
    ControlObservationKind,
)
from llm_redteam.domain import (
    CompromiseOutcome,
    EvidenceKind,
    EvidenceRecord,
    ExecutionResult,
)
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

CASE_ID = "BLUE-KNOWLEDGE-001"
FAMILY = "repository_prompt_injection"
CONTROL_ID = "CTRL-TOOL-AUTHZ"


def _setup() -> tuple[ExperimentRepository, str, str]:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = EscalatingVaultTarget(canary="RT_CANARY_BLUE_KB_001")
    snapshot_id = repository.save_target(target.identity)
    repository.start_campaign(
        campaign_id="campaign-blue-kb",
        target_snapshot_id=snapshot_id,
        configuration_hash="blue-kb-campaign-config",
        metric_definition_version="v1",
    )
    repository.record_attack(
        attack_instance_id="attack-blue-kb",
        campaign_id="campaign-blue-kb",
        case_id=CASE_ID,
        attack_family=FAMILY,
        interaction_mode="single_turn",
        payload_hash="payload-blue-kb",
    )
    execution = ExecutionResult(
        execution_id="exec-blue-kb",
        attack_id=CASE_ID,
        target_id=target.identity.id,
        outcome=CompromiseOutcome.PASS,
        objective_violated=False,
        model_compromise=False,
        system_compromise=False,
        confidence=1.0,
        evidence=(
            EvidenceRecord(
                kind=EvidenceKind.GUARDRAIL,
                source="synthetic_tool_authorizer",
                observed_at="test",
                content_hash="guardrail-block-hash",
                data={"decision": "blocked", "reason": "unauthorized synthetic action"},
                redacted=True,
            ),
        ),
    )
    repository.save_execution(
        execution,
        attack_instance_id="attack-blue-kb",
        target_snapshot_id=snapshot_id,
    )
    repository.save_blue_control(
        BlueControlDefinition(
            control_id=CONTROL_ID,
            target_snapshot_id=snapshot_id,
            name="tool_authorization",
            layer="authorization",
            description="Rejects unauthorized synthetic tool operations.",
        )
    )
    return repository, snapshot_id, execution.execution_id


def _observation(
    repository: ExperimentRepository,
    snapshot_id: str,
    execution_id: str,
    *,
    evidence_refs: tuple[str, ...],
    source: ControlEvidenceSource = ControlEvidenceSource.SYSTEM_STATE,
    attack_family: str = FAMILY,
) -> ControlObservation:
    return ControlObservation(
        observation_id=f"obs-{source.value.lower()}",
        control_id=CONTROL_ID,
        target_snapshot_id=snapshot_id,
        attack_family=attack_family,
        execution_id=execution_id,
        experiment_fingerprint=repository.execution_fingerprint(execution_id),
        kind=ControlObservationKind.BLOCKED_BY_CONTROL,
        source=source,
        evidence_refs=evidence_refs,
        confidence=1.0,
    )


def test_authoritative_observation_round_trip_drives_control_state() -> None:
    repository, snapshot_id, execution_id = _setup()
    refs = repository.evidence_refs_for_execution(execution_id)
    assert refs

    repository.record_control_observation(
        _observation(
            repository,
            snapshot_id,
            execution_id,
            evidence_refs=(refs[0],),
        )
    )
    assessment = repository.assess_blue_control(
        target_snapshot_id=snapshot_id,
        control_id=CONTROL_ID,
        attack_family=FAMILY,
    )

    assert assessment.state == BlueControlState.OBSERVED_EFFECTIVE
    assert assessment.authoritative_trials == 1
    assert assessment.direct_blocks == 1
    assert assessment.block_rate.value == 1.0


def test_authoritative_observation_with_unknown_evidence_reference_fails_closed() -> None:
    repository, snapshot_id, execution_id = _setup()

    with pytest.raises(ValueError, match="unknown execution evidence"):
        repository.record_control_observation(
            _observation(
                repository,
                snapshot_id,
                execution_id,
                evidence_refs=("evidence:999999",),
            )
        )


def test_observation_attack_family_must_match_persisted_execution() -> None:
    repository, snapshot_id, execution_id = _setup()
    refs = repository.evidence_refs_for_execution(execution_id)

    with pytest.raises(ValueError, match="attack family"):
        repository.record_control_observation(
            _observation(
                repository,
                snapshot_id,
                execution_id,
                evidence_refs=(refs[0],),
                attack_family="unrelated_family",
            )
        )


def test_observation_fingerprint_must_match_execution() -> None:
    repository, snapshot_id, execution_id = _setup()
    refs = repository.evidence_refs_for_execution(execution_id)
    observation = _observation(
        repository,
        snapshot_id,
        execution_id,
        evidence_refs=(refs[0],),
    ).model_copy(update={"experiment_fingerprint": "wrong-fingerprint"})

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        repository.record_control_observation(observation)


def test_semantic_forensic_observation_is_persisted_but_not_authoritative() -> None:
    repository, snapshot_id, execution_id = _setup()
    repository.record_control_observation(
        _observation(
            repository,
            snapshot_id,
            execution_id,
            evidence_refs=("forensic:report-v1",),
            source=ControlEvidenceSource.SEMANTIC_FORENSIC,
        )
    )

    assessment = repository.assess_blue_control(
        target_snapshot_id=snapshot_id,
        control_id=CONTROL_ID,
        attack_family=FAMILY,
    )

    assert assessment.state == BlueControlState.DECLARED
    assert assessment.semantic_observations == 1
    assert assessment.authoritative_trials == 0
    assert assessment.block_rate.value is None
