import asyncio

import pytest

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
)
from llm_redteam.red.ablation_runner import execute_paired_red_ablation

BASELINE_POLICY = "a" * 64
TREATMENT_POLICY = "b" * 64


def _case() -> AttackCase:
    return AttackCase(
        id="case-a",
        name="case-a",
        description="Synthetic runner fixture.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="paired-runner-test"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the protected synthetic objective.",
            forbidden_effect="Protected synthetic runner objective is fulfilled.",
        ),
        payload=PayloadSpec(text="synthetic-runner"),
        grading=GradingSpec(preferred=["deterministic"], detectors=["synthetic-policy"]),
    )


def _manifest(case: AttackCase):
    return build_held_out_evaluation_manifest(
        manifest_id="runner-v1",
        discovery_cases=(),
        evaluation_cases=(case,),
        corpus_snapshot_hash="c" * 64,
        split_strategy="paired-component-ablation",
    )


def _contract(manifest_hash: str):
    return PairedRedAblationContract(
        experiment_id="runner-exp-v1",
        target_snapshot_id="target-v1",
        judge_fingerprint="d" * 64,
        budget_fingerprint="e" * 64,
        evaluation_manifest_hash=manifest_hash,
        metric_definition_version="metrics-v1",
        session_mode="REPLAY",
        changed_component="mechanism_policy",
        baseline_policy_fingerprint=BASELINE_POLICY,
        treatment_policy_fingerprint=TREATMENT_POLICY,
        pairing_mode=PairingMode.CASE_REPLICATE_SEED,
    )


def _observation(
    arm: AblationArm,
    case: AttackCase,
    replicate: int,
    pair_seed: int | None,
) -> PairedRedObservation:
    success = arm == AblationArm.TREATMENT
    policy = BASELINE_POLICY if arm == AblationArm.BASELINE else TREATMENT_POLICY
    return PairedRedObservation(
        arm=arm,
        case_id=case.id,
        replicate=replicate,
        policy_fingerprint=policy,
        pair_seed=pair_seed,
        execution=ExecutionResult(
            execution_id=f"exec-{arm.value}-{replicate}",
            attack_id=case.id,
            target_id="synthetic-target",
            outcome=(
                CompromiseOutcome.MODEL_COMPROMISE
                if success
                else CompromiseOutcome.PASS
            ),
            objective_violated=success,
            model_compromise=success,
            system_compromise=False,
            confidence=1.0,
        ),
        target_interactions=2,
        backtracks=0,
        branches_created=0,
        first_violation_ordinal=(2 if success else None),
        first_violation_depth=(2 if success else None),
        planner_calls=2,
        mutator_calls=0,
        planner_output_tokens=20,
        mutator_output_tokens=0,
        elapsed_seconds=0.1,
    )


def test_runner_executes_counterbalanced_pairs_and_preserves_shared_seed() -> None:
    case = _case()
    manifest = _manifest(case)
    contract = _contract(manifest.content_hash)
    calls: list[tuple[AblationArm, int, int | None]] = []

    async def run_trial(
        arm: AblationArm,
        supplied_case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> PairedRedObservation:
        calls.append((arm, replicate, pair_seed))
        return _observation(arm, supplied_case, replicate, pair_seed)

    report = asyncio.run(
        execute_paired_red_ablation(
            cases=(case,),
            contract=contract,
            manifest=manifest,
            replicates_per_case=2,
            run_trial=run_trial,
        )
    )

    assert report.pair_count == 2
    assert report.objective_violation_rate_delta == 1.0
    assert len(calls) == 4
    first_pair = calls[:2]
    second_pair = calls[2:]
    assert first_pair[0][0] != first_pair[1][0]
    assert second_pair[0][0] != second_pair[1][0]
    assert first_pair[0][0] != second_pair[0][0]
    assert first_pair[0][2] == first_pair[1][2]
    assert second_pair[0][2] == second_pair[1][2]
    assert first_pair[0][2] != second_pair[0][2]


def test_runner_rejects_executor_that_changes_scheduled_identity() -> None:
    case = _case()
    manifest = _manifest(case)
    contract = _contract(manifest.content_hash)

    async def bad_runner(
        arm: AblationArm,
        supplied_case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> PairedRedObservation:
        observation = _observation(arm, supplied_case, replicate, pair_seed)
        return observation.model_copy(update={"replicate": replicate + 1})

    with pytest.raises(ValueError, match="wrong replicate"):
        asyncio.run(
            execute_paired_red_ablation(
                cases=(case,),
                contract=contract,
                manifest=manifest,
                replicates_per_case=1,
                run_trial=bad_runner,
            )
        )
