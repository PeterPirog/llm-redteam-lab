from llm_redteam.domain import (
    AttackCase,
    AttackTier,
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
    PairingMode,
    build_counterbalanced_pair_plan,
)

BASELINE_POLICY = "a" * 64
TREATMENT_POLICY = "b" * 64


def _case(case_id: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description=f"Counterbalance fixture {case_id}.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="counterbalance-test"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the synthetic protected objective.",
            forbidden_effect=f"Synthetic protected objective {case_id} is fulfilled.",
        ),
        payload=PayloadSpec(text=f"synthetic-{case_id}"),
        grading=GradingSpec(preferred=["deterministic"], detectors=["synthetic-policy"]),
    )


def _manifest():
    return build_held_out_evaluation_manifest(
        manifest_id="counterbalanced-v1",
        discovery_cases=(),
        evaluation_cases=(_case("case-b"), _case("case-a")),
        corpus_snapshot_hash="c" * 64,
        split_strategy="paired-component-ablation",
    )


def _contract(manifest_hash: str, pairing_mode: PairingMode):
    return PairedRedAblationContract(
        experiment_id="counterbalanced-exp-v1",
        target_snapshot_id="target-v1",
        judge_fingerprint="d" * 64,
        budget_fingerprint="e" * 64,
        evaluation_manifest_hash=manifest_hash,
        metric_definition_version="metrics-v1",
        session_mode="REPLAY",
        changed_component="mechanism_policy",
        baseline_policy_fingerprint=BASELINE_POLICY,
        treatment_policy_fingerprint=TREATMENT_POLICY,
        pairing_mode=pairing_mode,
    )


def test_counterbalanced_plan_is_deterministic_and_alternates_first_arm() -> None:
    manifest = _manifest()
    contract = _contract(manifest.content_hash, PairingMode.CASE_REPLICATE)

    first = build_counterbalanced_pair_plan(
        contract=contract,
        manifest=manifest,
        replicates_per_case=2,
    )
    second = build_counterbalanced_pair_plan(
        contract=contract,
        manifest=manifest,
        replicates_per_case=2,
    )

    assert first == second
    assert [(item.case_id, item.replicate) for item in first] == [
        ("case-a", 0),
        ("case-a", 1),
        ("case-b", 0),
        ("case-b", 1),
    ]
    assert all(left.first_arm != right.first_arm for left, right in zip(first, first[1:]))
    assert sum(item.first_arm == AblationArm.BASELINE for item in first) == 2
    assert sum(item.first_arm == AblationArm.TREATMENT for item in first) == 2
    assert all(item.pair_seed is None for item in first)


def test_seed_pairing_plan_assigns_stable_distinct_pair_seeds() -> None:
    manifest = _manifest()
    contract = _contract(manifest.content_hash, PairingMode.CASE_REPLICATE_SEED)

    plan = build_counterbalanced_pair_plan(
        contract=contract,
        manifest=manifest,
        replicates_per_case=2,
    )

    seeds = [item.pair_seed for item in plan]
    assert all(seed is not None for seed in seeds)
    assert len(set(seeds)) == len(seeds)


def test_counterbalanced_plan_rejects_wrong_manifest_and_zero_replicates() -> None:
    manifest = _manifest()
    contract = _contract("f" * 64, PairingMode.CASE_REPLICATE)

    try:
        build_counterbalanced_pair_plan(
            contract=contract,
            manifest=manifest,
            replicates_per_case=1,
        )
    except ValueError as exc:
        assert "manifest" in str(exc)
    else:
        raise AssertionError("manifest mismatch should fail closed")

    valid = _contract(manifest.content_hash, PairingMode.CASE_REPLICATE)
    try:
        build_counterbalanced_pair_plan(
            contract=valid,
            manifest=manifest,
            replicates_per_case=0,
        )
    except ValueError as exc:
        assert "replicates_per_case" in str(exc)
    else:
        raise AssertionError("zero replicates should fail closed")
