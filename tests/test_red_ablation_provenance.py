from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import inspect

from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import (
    AttackCase,
    AttackTier,
    CompromiseOutcome,
    ExecutionResult,
    GradingSpec,
    PayloadSpec,
    SecurityObjective,
    SourceMode,
    SourceRef,
    TargetClass,
    TargetMode,
)
from llm_redteam.evaluation_protocol import held_out_evaluation_protocol
from llm_redteam.evaluation_sets import build_held_out_evaluation_manifest
from llm_redteam.judges.base import Judgment
from llm_redteam.red.ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedObservation,
)
from llm_redteam.storage import (
    ExperimentRepository,
    build_evaluation_campaign_measurement_snapshot,
    build_red_ablation_experiment_snapshot,
    load_red_ablation_experiment,
    load_red_ablation_observations,
    save_campaign_measurement_snapshot,
    save_evaluation_set_manifest,
    save_red_ablation_experiment,
    save_red_ablation_observation,
    summarize_persisted_red_ablation,
)
from llm_redteam.targets.base import SessionMode
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

BASELINE_POLICY = "a" * 64
TREATMENT_POLICY = "b" * 64
JUDGE_HASH = "c" * 64
BUDGET_HASH = "d" * 64
CORPUS_HASH = "e" * 64
METRIC_VERSION = "metrics-v1"


@dataclass(frozen=True)
class _Fixture:
    repository: ExperimentRepository
    snapshot_id: str
    manifest_hash: str
    contract: PairedRedAblationContract
    experiment_hash: str
    baseline_execution: ExecutionResult
    treatment_execution: ExecutionResult


def _case() -> AttackCase:
    return AttackCase(
        id="case-a",
        name="case-a",
        description="Synthetic persisted ablation fixture.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="ablation-provenance-test"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the protected synthetic objective.",
            forbidden_effect="Protected synthetic objective is fulfilled.",
        ),
        payload=PayloadSpec(text="synthetic-probe"),
        grading=GradingSpec(preferred=["deterministic"], detectors=["synthetic-policy"]),
    )


def _conversation(
    *,
    campaign_label: str,
    target_id: str,
    success: bool,
) -> ConversationRunResult:
    outcome = (
        CompromiseOutcome.MODEL_COMPROMISE if success else CompromiseOutcome.PASS
    )
    execution = ExecutionResult(
        execution_id=f"exec-{campaign_label}",
        attack_id="case-a",
        target_id=target_id,
        outcome=outcome,
        objective_violated=success,
        model_compromise=success,
        system_compromise=False,
        confidence=1.0,
    )
    judgment = Judgment(
        objective_violated=success,
        model_compromise=success,
        system_compromise=False,
        confidence=1.0,
        reason="synthetic deterministic fixture",
        judge_type="deterministic",
    )
    turn = ConversationTurn(
        turn_id=f"turn-{campaign_label}",
        ordinal=1,
        depth=1,
        branch_id="b0",
        attacker_message="Synthetic paired probe.",
        target_response="Synthetic paired response.",
        outcome=outcome,
        judgment=judgment,
    )
    return ConversationRunResult(
        execution=execution,
        conversation_id=f"conv-{campaign_label}",
        session_mode=SessionMode.REPLAY,
        turns=(turn,),
        backtracks=0,
        branches=1,
        first_violation_turn_id=(turn.turn_id if success else None),
        first_violation_ordinal=(1 if success else None),
        first_violation_depth=(1 if success else None),
        flow_fingerprint="flow-persisted-ablation-v1",
    )


def _observation(
    arm: AblationArm,
    execution: ExecutionResult,
) -> PairedRedObservation:
    success = execution.objective_violated is True
    return PairedRedObservation(
        arm=arm,
        case_id="case-a",
        replicate=0,
        policy_fingerprint=(
            BASELINE_POLICY if arm == AblationArm.BASELINE else TREATMENT_POLICY
        ),
        execution=execution,
        target_interactions=1,
        backtracks=0,
        branches_created=0,
        first_violation_ordinal=(1 if success else None),
        first_violation_depth=(1 if success else None),
        planner_calls=1,
        mutator_calls=0,
        planner_output_tokens=10,
        mutator_output_tokens=0,
        elapsed_seconds=0.1,
    )


def _build_fixture() -> _Fixture:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = EscalatingVaultTarget()
    snapshot_id = repository.save_target(target.identity)

    case = _case()
    manifest = build_held_out_evaluation_manifest(
        manifest_id="ablation-provenance-v1",
        discovery_cases=(),
        evaluation_cases=(case,),
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="paired-component-ablation",
    )
    save_evaluation_set_manifest(repository.engine, manifest)

    campaigns = {
        AblationArm.BASELINE: ("campaign-baseline", BASELINE_POLICY, "config-baseline"),
        AblationArm.TREATMENT: ("campaign-treatment", TREATMENT_POLICY, "config-treatment"),
    }
    measurement_hashes: dict[AblationArm, str] = {}
    executions: dict[AblationArm, ExecutionResult] = {}

    for arm, (campaign_id, policy_hash, config_hash) in campaigns.items():
        repository.start_campaign(
            campaign_id=campaign_id,
            target_snapshot_id=snapshot_id,
            configuration_hash=config_hash,
            metric_definition_version=METRIC_VERSION,
        )
        measurement = build_evaluation_campaign_measurement_snapshot(
            campaign_id=campaign_id,
            target_snapshot_id=snapshot_id,
            campaign_configuration_hash=config_hash,
            metric_definition_version=METRIC_VERSION,
            protocol=held_out_evaluation_protocol(),
            attack_policy_fingerprint=policy_hash,
            judge_policy_fingerprint=JUDGE_HASH,
            budget_fingerprint=BUDGET_HASH,
            manifest=manifest,
        )
        measurement_hashes[arm] = save_campaign_measurement_snapshot(
            repository.engine,
            measurement,
        )
        repository.record_attack(
            attack_instance_id=f"attack-{arm.value.lower()}",
            campaign_id=campaign_id,
            case_id=case.id,
            attack_family=case.attack_family[0],
            interaction_mode="multi_turn",
        )
        conversation = _conversation(
            campaign_label=arm.value.lower(),
            target_id=target.identity.id,
            success=arm == AblationArm.TREATMENT,
        )
        repository.save_conversation(
            conversation,
            attack_instance_id=f"attack-{arm.value.lower()}",
            target_snapshot_id=snapshot_id,
        )
        executions[arm] = conversation.execution

    contract = PairedRedAblationContract(
        experiment_id="persisted-ablation-v1",
        target_snapshot_id=snapshot_id,
        judge_fingerprint=JUDGE_HASH,
        budget_fingerprint=BUDGET_HASH,
        evaluation_manifest_hash=manifest.content_hash,
        metric_definition_version=METRIC_VERSION,
        session_mode=SessionMode.REPLAY.value,
        changed_component="mechanism_policy",
        baseline_policy_fingerprint=BASELINE_POLICY,
        treatment_policy_fingerprint=TREATMENT_POLICY,
    )
    experiment = build_red_ablation_experiment_snapshot(
        contract=contract,
        baseline_campaign_id="campaign-baseline",
        treatment_campaign_id="campaign-treatment",
        baseline_measurement_hash=measurement_hashes[AblationArm.BASELINE],
        treatment_measurement_hash=measurement_hashes[AblationArm.TREATMENT],
    )
    experiment_hash = save_red_ablation_experiment(repository.engine, experiment)

    return _Fixture(
        repository=repository,
        snapshot_id=snapshot_id,
        manifest_hash=manifest.content_hash,
        contract=contract,
        experiment_hash=experiment_hash,
        baseline_execution=executions[AblationArm.BASELINE],
        treatment_execution=executions[AblationArm.TREATMENT],
    )


def test_schema_registers_ablation_provenance_tables() -> None:
    fixture = _build_fixture()
    tables = set(inspect(fixture.repository.engine).get_table_names())
    assert "red_ablation_experiments" in tables
    assert "red_ablation_observations" in tables


def test_persisted_ablation_round_trips_and_summarizes_from_database_truth() -> None:
    fixture = _build_fixture()
    baseline = _observation(AblationArm.BASELINE, fixture.baseline_execution)
    treatment = _observation(AblationArm.TREATMENT, fixture.treatment_execution)

    first_hash = save_red_ablation_observation(
        fixture.repository.engine,
        experiment_id=fixture.contract.experiment_id,
        observation=baseline,
    )
    second_hash = save_red_ablation_observation(
        fixture.repository.engine,
        experiment_id=fixture.contract.experiment_id,
        observation=treatment,
    )
    restored_experiment = load_red_ablation_experiment(
        fixture.repository.engine,
        fixture.contract.experiment_id,
    )
    restored = load_red_ablation_observations(
        fixture.repository.engine,
        fixture.contract.experiment_id,
    )
    report = summarize_persisted_red_ablation(
        fixture.repository.engine,
        fixture.contract.experiment_id,
    )

    assert len(first_hash) == 64
    assert len(second_hash) == 64
    assert restored_experiment is not None
    assert restored_experiment.content_hash == fixture.experiment_hash
    assert len(restored) == 2
    assert report.pair_count == 1
    assert report.objective_violation_rate_delta == 1.0
    assert report.model_compromise_rate_delta == 1.0
    assert report.system_compromise_rate_delta == 0.0


def test_observation_cannot_rewrite_persisted_execution_outcome() -> None:
    fixture = _build_fixture()
    forged_execution = fixture.baseline_execution.model_copy(
        update={
            "outcome": CompromiseOutcome.MODEL_COMPROMISE,
            "objective_violated": True,
            "model_compromise": True,
        }
    )
    forged = _observation(AblationArm.BASELINE, forged_execution)

    with pytest.raises(ValueError, match="outcome"):
        save_red_ablation_observation(
            fixture.repository.engine,
            experiment_id=fixture.contract.experiment_id,
            observation=forged,
        )


def test_observation_cannot_move_treatment_execution_into_baseline_arm() -> None:
    fixture = _build_fixture()
    forged = _observation(AblationArm.BASELINE, fixture.treatment_execution)

    with pytest.raises(ValueError, match="wrong ablation campaign"):
        save_red_ablation_observation(
            fixture.repository.engine,
            experiment_id=fixture.contract.experiment_id,
            observation=forged,
        )


def test_ablation_experiment_rejects_changed_judge_against_persisted_campaigns() -> None:
    fixture = _build_fixture()
    restored = load_red_ablation_experiment(
        fixture.repository.engine,
        fixture.contract.experiment_id,
    )
    assert restored is not None

    changed_contract = fixture.contract.model_copy(
        update={
            "experiment_id": "other-experiment",
            "judge_fingerprint": "f" * 64,
        }
    )
    changed = build_red_ablation_experiment_snapshot(
        contract=changed_contract,
        baseline_campaign_id=restored.baseline_campaign_id,
        treatment_campaign_id=restored.treatment_campaign_id,
        baseline_measurement_hash=restored.baseline_measurement_hash,
        treatment_measurement_hash=restored.treatment_measurement_hash,
    )

    with pytest.raises(ValueError, match="Judge fingerprint"):
        save_red_ablation_experiment(fixture.repository.engine, changed)


def test_ablation_experiment_rejects_tampered_content_hash_before_write() -> None:
    fixture = _build_fixture()
    restored = load_red_ablation_experiment(
        fixture.repository.engine,
        fixture.contract.experiment_id,
    )
    assert restored is not None

    tampered = restored.model_copy(
        update={
            "experiment_id": "tampered-experiment",
            "contract": restored.contract.model_copy(
                update={"experiment_id": "tampered-experiment"}
            ),
            "content_hash": "f" * 64,
        }
    )
    with pytest.raises(ValueError, match="content_hash"):
        save_red_ablation_experiment(fixture.repository.engine, tampered)
