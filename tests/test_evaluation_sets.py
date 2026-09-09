import pytest

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
from llm_redteam.evaluation_sets import (
    EvaluationSetExposure,
    build_held_out_evaluation_manifest,
    select_manifest_cases,
)

CORPUS_HASH = "a" * 64


def _case(case_id: str, payload: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description="Synthetic evaluation-set fixture.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test-suite"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the protected synthetic objective.",
            forbidden_effect="Protected synthetic objective is fulfilled.",
        ),
        payload=PayloadSpec(text=payload),
        grading=GradingSpec(preferred=["semantic"], detectors=["synthetic-policy"]),
    )


def test_manifest_builds_disjoint_hash_bound_partitions() -> None:
    discovery = (_case("DISC-001", "discovery-a"), _case("DISC-002", "discovery-b"))
    evaluation = (_case("EVAL-001", "evaluation-a"),)

    manifest = build_held_out_evaluation_manifest(
        manifest_id="heldout-v1",
        discovery_cases=discovery,
        evaluation_cases=evaluation,
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="explicit-versioned-split",
    )

    assert manifest.exposure == EvaluationSetExposure.INTERNAL_HELD_OUT
    assert manifest.red_can_access_evaluation_content is False
    assert manifest.discovery_case_set_hash != manifest.evaluation_case_set_hash
    assert len(manifest.content_hash) == 64
    assert select_manifest_cases(discovery + evaluation, manifest=manifest, evaluation=False) == discovery
    assert select_manifest_cases(discovery + evaluation, manifest=manifest, evaluation=True) == evaluation


def test_manifest_allows_pure_evaluation_without_discovery_cases() -> None:
    evaluation = (_case("EVAL-001", "evaluation-a"),)

    manifest = build_held_out_evaluation_manifest(
        manifest_id="pure-eval-v1",
        discovery_cases=(),
        evaluation_cases=evaluation,
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="frozen-policy-regression",
    )

    assert manifest.discovery_cases == ()
    assert len(manifest.discovery_case_set_hash) == 64
    assert select_manifest_cases(evaluation, manifest=manifest, evaluation=False) == ()


def test_manifest_rejects_empty_evaluation_partition() -> None:
    with pytest.raises(ValueError, match="at least one evaluation case"):
        build_held_out_evaluation_manifest(
            manifest_id="empty-eval",
            discovery_cases=(_case("DISC-001", "discovery"),),
            evaluation_cases=(),
            corpus_snapshot_hash=CORPUS_HASH,
            split_strategy="invalid-empty-evaluation",
        )


def test_manifest_rejects_same_case_id_across_partitions() -> None:
    shared = _case("CASE-001", "same")

    with pytest.raises(ValueError, match="case IDs must be disjoint"):
        build_held_out_evaluation_manifest(
            manifest_id="overlap-id",
            discovery_cases=(shared,),
            evaluation_cases=(shared,),
            corpus_snapshot_hash=CORPUS_HASH,
            split_strategy="invalid-overlap",
        )


def test_manifest_rejects_same_content_hidden_behind_different_ids() -> None:
    discovery = _case("DISC-001", "same-content")
    duplicated = discovery.model_copy(update={"id": "EVAL-001"})

    with pytest.raises(ValueError, match="case content must be disjoint"):
        build_held_out_evaluation_manifest(
            manifest_id="overlap-content",
            discovery_cases=(discovery,),
            evaluation_cases=(duplicated,),
            corpus_snapshot_hash=CORPUS_HASH,
            split_strategy="invalid-content-overlap",
        )


def test_sequestered_manifest_requires_external_source_identity() -> None:
    discovery = (_case("DISC-001", "discovery"),)
    evaluation = (_case("EVAL-001", "evaluation"),)

    with pytest.raises(ValueError, match="sequestered_source_id"):
        build_held_out_evaluation_manifest(
            manifest_id="sequestered-v1",
            discovery_cases=discovery,
            evaluation_cases=evaluation,
            corpus_snapshot_hash=CORPUS_HASH,
            split_strategy="external-sequestered",
            exposure=EvaluationSetExposure.SEQUESTERED,
        )

    manifest = build_held_out_evaluation_manifest(
        manifest_id="sequestered-v1",
        discovery_cases=discovery,
        evaluation_cases=evaluation,
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="external-sequestered",
        exposure=EvaluationSetExposure.SEQUESTERED,
        sequestered_source_id="local-secure-store:eval-v1",
    )
    assert manifest.exposure == EvaluationSetExposure.SEQUESTERED


def test_selection_fails_closed_when_case_content_changes() -> None:
    discovery = (_case("DISC-001", "original"),)
    evaluation = (_case("EVAL-001", "evaluation"),)
    manifest = build_held_out_evaluation_manifest(
        manifest_id="heldout-v1",
        discovery_cases=discovery,
        evaluation_cases=evaluation,
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="explicit-versioned-split",
    )
    mutated = discovery[0].model_copy(update={"description": "Changed after split creation."})

    with pytest.raises(ValueError, match="content hash mismatch"):
        select_manifest_cases((mutated,) + evaluation, manifest=manifest, evaluation=False)
