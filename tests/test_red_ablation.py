from __future__ import annotations

import pytest

from llm_redteam.budget import BudgetSnapshot
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
from llm_redteam.evaluation_sets import build_held_out_evaluation_manifest
from llm_redteam.red.ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedObservation,
    PairingMode,
    observation_from_run,
    summarize_paired_red_ablation,
)
from llm_redteam.targets.base import SessionMode

BASELINE_POLICY = "a" * 64
TREATMENT_POLICY = "b" * 64
JUDGE_HASH = "c" * 64
BUDGET_HASH = "d" * 64
CORPUS_HASH = "e" * 64


def _case(case_id: str, payload: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description=f"Synthetic paired-ablation fixture {payload}.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="paired-ablation-test"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the protected synthetic objective.",
            forbidden_effect=f"Protected synthetic objective {payload} is fulfilled.",
        ),
        payload=PayloadSpec(text=payload),
        grading=GradingSpec(preferred=["deterministic"], detectors=["synthetic-policy"]),
    )


def _manifest(*case_ids: str):
    cases = tuple(_case(case_id, f"payload-{case_id}") for case_id in case_ids)
    return build_held_out_evaluation_manifest(
        manifest_id="paired-ablation-v1",
        discovery_cases=(),
        evaluation_cases=cases,
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="paired-component-ablation",
    )


def _contract(manifest_hash: str, *, pairing_mode: PairingMode = PairingMode.CASE_REPLICATE):
    return PairedRedAblationContract(
        experiment_id="red-ablation-v1",
        target_snapshot_id="target-snapshot-v1",
        judge_fingerprint=JUDGE_HASH,
        budget_fingerprint=BUDGET_HASH,
        evaluation_manifest_hash=manifest_hash,
        metric_definition_version="metrics-v1",
        session_mode=SessionMode.REPLAY.value,
        changed_component="mechanism_policy",
        baseline_policy_fingerprint=BASELINE_POLICY,
        treatment_policy_fingerprint=TREATMENT_POLICY,
        pairing_mode=pairing_mode,
    )


def _execution(case_id: str, replicate: int, success: bool, *, system: bool = False):
    outcome = CompromiseOutcome.PASS
    if success and system:
        outcome = CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
    elif success:
        outcome = CompromiseOutcome.MODEL_COMPROMISE
    return ExecutionResult(
        execution_id=f"exec-{case_id}-{replicate}-{int(success)}-{int(system)}",
        attack_id=case_id,
        target_id="synthetic-target",
        outcome=outcome,
        objective_violated=success,
        model_compromise=success,
        system_compromise=system,
        confidence=1.0,
    )


def _observation(
    arm: AblationArm,
    case_id: str,
    replicate: int,
    success: bool,
    *,
    target_interactions: int = 3,
    planner_calls: int = 3,
    pair_seed: int | None = None,
    system: bool = False,
) -> PairedRedObservation:
    policy = BASELINE_POLICY if arm == AblationArm.BASELINE else TREATMENT_POLICY
    execution = _execution(case_id, replicate, success, system=system)
    return PairedRedObservation(
        arm=arm,
        case_id=case_id,
        replicate=replicate,
        policy_fingerprint=policy,
        pair_seed=pair_seed,
        execution=execution,
        target_interactions=target_interactions,
        backtracks=0,
        branches_created=0,
        first_violation_ordinal=(target_interactions if success else None),
        first_violation_depth=(target_interactions if success else None),
        planner_calls=planner_calls,
        mutator_calls=0,
        planner_output_tokens=planner_calls * 10,
        mutator_output_tokens=0,
        elapsed_seconds=1.0,
    )


def test_paired_ablation_reports_effectiveness_layers_and_cost_delta() -> None:
    manifest = _manifest("case-a", "case-b")
    contract = _contract(manifest.content_hash)
    observations = (
        _observation(AblationArm.BASELINE, "case-a", 0, False, target_interactions=3),
        _observation(AblationArm.TREATMENT, "case-a", 0, True, target_interactions=2),
        _observation(AblationArm.BASELINE, "case-b", 0, True, system=True),
        _observation(AblationArm.TREATMENT, "case-b", 0, True, system=True),
    )

    report = summarize_paired_red_ablation(
        observations,
        contract=contract,
        manifest=manifest,
    )

    assert report.pair_count == 2
    assert report.objective_violation_rate_delta == 0.5
    assert report.model_compromise_rate_delta == 0.5
    assert report.system_compromise_rate_delta == 0.0
    assert report.treatment_only_objective_successes == 1
    assert report.baseline_only_objective_successes == 0
    assert report.discordant_pairs == 1
    assert report.exact_mcnemar_p_value == 1.0
    assert report.mean_target_interaction_delta == -0.5
    assert report.comparable_red_component_estimate is True


def test_exact_mcnemar_detects_six_consistent_treatment_only_wins() -> None:
    manifest = _manifest("case-a")
    contract = _contract(manifest.content_hash)
    observations: list[PairedRedObservation] = []
    for replicate in range(6):
        observations.extend(
            [
                _observation(AblationArm.BASELINE, "case-a", replicate, False),
                _observation(AblationArm.TREATMENT, "case-a", replicate, True),
            ]
        )

    report = summarize_paired_red_ablation(
        observations,
        contract=contract,
        manifest=manifest,
    )

    assert report.discordant_pairs == 6
    assert report.treatment_only_objective_successes == 6
    assert report.exact_mcnemar_p_value == pytest.approx(0.03125)
    assert report.treatment_win_rate_among_discordant.value == 1.0
    assert report.treatment_win_rate_among_discordant.trials == 6


def test_paired_ablation_rejects_missing_arm_pair() -> None:
    manifest = _manifest("case-a")
    contract = _contract(manifest.content_hash)

    with pytest.raises(ValueError, match="identical case/replicate keys"):
        summarize_paired_red_ablation(
            (
                _observation(AblationArm.BASELINE, "case-a", 0, False),
                _observation(AblationArm.TREATMENT, "case-a", 0, False),
                _observation(AblationArm.BASELINE, "case-a", 1, False),
            ),
            contract=contract,
            manifest=manifest,
        )


def test_paired_ablation_rejects_unbalanced_case_replicates() -> None:
    manifest = _manifest("case-a", "case-b")
    contract = _contract(manifest.content_hash)
    observations: list[PairedRedObservation] = []
    for arm in (AblationArm.BASELINE, AblationArm.TREATMENT):
        observations.extend(
            [
                _observation(arm, "case-a", 0, False),
                _observation(arm, "case-a", 1, False),
                _observation(arm, "case-b", 0, False),
            ]
        )

    with pytest.raises(ValueError, match="balanced replicates"):
        summarize_paired_red_ablation(
            observations,
            contract=contract,
            manifest=manifest,
        )


def test_seed_pairing_requires_equal_seed_in_both_arms() -> None:
    manifest = _manifest("case-a")
    contract = _contract(
        manifest.content_hash,
        pairing_mode=PairingMode.CASE_REPLICATE_SEED,
    )

    with pytest.raises(ValueError, match="seed mismatch"):
        summarize_paired_red_ablation(
            (
                _observation(
                    AblationArm.BASELINE,
                    "case-a",
                    0,
                    False,
                    pair_seed=11,
                ),
                _observation(
                    AblationArm.TREATMENT,
                    "case-a",
                    0,
                    False,
                    pair_seed=12,
                ),
            ),
            contract=contract,
            manifest=manifest,
        )


def test_observation_builder_uses_budget_delta_and_checks_turns() -> None:
    execution = _execution("case-a", 0, True)
    turn = ConversationTurn(
        turn_id="turn-1",
        ordinal=1,
        depth=1,
        branch_id="b0",
        attacker_message="Synthetic probe.",
        target_response="Synthetic response.",
        outcome=CompromiseOutcome.MODEL_COMPROMISE,
    )
    result = ConversationRunResult(
        execution=execution,
        conversation_id="conv-a",
        session_mode=SessionMode.REPLAY,
        turns=(turn,),
        backtracks=0,
        branches=1,
        first_violation_turn_id="turn-1",
        first_violation_ordinal=1,
        first_violation_depth=1,
        flow_fingerprint="flow-v1",
    )
    before = _budget_snapshot(turns=2, planner_calls=4, planner_tokens=40, elapsed=1.0)
    after = _budget_snapshot(turns=3, planner_calls=5, planner_tokens=52, elapsed=1.4)

    observation = observation_from_run(
        arm=AblationArm.BASELINE,
        replicate=0,
        policy_fingerprint=BASELINE_POLICY,
        result=result,
        budget_before=before,
        budget_after=after,
    )

    assert observation.target_interactions == 1
    assert observation.planner_calls == 1
    assert observation.planner_output_tokens == 12
    assert observation.elapsed_seconds == pytest.approx(0.4)

    bad_after = _budget_snapshot(turns=4, planner_calls=5, planner_tokens=52, elapsed=1.4)
    with pytest.raises(ValueError, match="turn delta"):
        observation_from_run(
            arm=AblationArm.BASELINE,
            replicate=0,
            policy_fingerprint=BASELINE_POLICY,
            result=result,
            budget_before=before,
            budget_after=bad_after,
        )


def _budget_snapshot(
    *,
    turns: int,
    planner_calls: int,
    planner_tokens: int,
    elapsed: float,
) -> BudgetSnapshot:
    return BudgetSnapshot(
        attacks=0,
        generations=0,
        turns=turns,
        turns_by_attack=(),
        model_calls=planner_calls,
        model_calls_by_role=(("red_planner", planner_calls),),
        output_tokens=planner_tokens,
        output_tokens_by_role=(("red_planner", planner_tokens),),
        image_generations=0,
        non_progress_attempts=0,
        elapsed_seconds=elapsed,
    )
