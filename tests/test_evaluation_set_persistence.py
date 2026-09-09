import pytest
from sqlalchemy.orm import Session

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
from llm_redteam.storage import (
    EvaluationSetManifestRow,
    ExperimentRepository,
    load_evaluation_set_manifest,
    load_evaluation_set_manifest_by_id,
    save_evaluation_set_manifest,
)

CORPUS_HASH = "a" * 64


def _case(case_id: str, payload: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description=f"Persistence fixture for {case_id}.",
        target_classes=[TargetClass.REASONING],
        target_modes=[TargetMode.MODEL],
        attack_family=["context_fusion"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test-suite"),
        security_objective=SecurityObjective(
            invariant="Synthetic invariant is preserved.",
            expected_safe_behavior="Do not fulfill the protected objective.",
            forbidden_effect="Protected objective is fulfilled.",
        ),
        payload=PayloadSpec(text=payload),
        grading=GradingSpec(preferred=["semantic"], detectors=["synthetic-policy"]),
    )


def _manifest(*, manifest_id: str = "heldout-persist-v1", suffix: str = ""):
    return build_held_out_evaluation_manifest(
        manifest_id=manifest_id,
        discovery_cases=(_case("DISC-001", f"discovery{suffix}"),),
        evaluation_cases=(_case("EVAL-001", f"evaluation{suffix}"),),
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="explicit-versioned-split",
    )


def _repository() -> ExperimentRepository:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    return repository


def test_manifest_round_trip_by_hash_and_id() -> None:
    repository = _repository()
    manifest = _manifest()

    saved = save_evaluation_set_manifest(repository.engine, manifest)

    assert saved == manifest.content_hash
    assert load_evaluation_set_manifest(repository.engine, saved) == manifest
    assert load_evaluation_set_manifest_by_id(repository.engine, manifest.manifest_id) == manifest


def test_identical_manifest_resave_is_idempotent() -> None:
    repository = _repository()
    manifest = _manifest()

    first = save_evaluation_set_manifest(repository.engine, manifest)
    second = save_evaluation_set_manifest(repository.engine, manifest)

    assert first == second == manifest.content_hash


def test_manifest_id_is_immutable_after_first_persistence() -> None:
    repository = _repository()
    original = _manifest()
    changed = _manifest(suffix="-changed")
    save_evaluation_set_manifest(repository.engine, original)

    with pytest.raises(ValueError, match="manifest_id is immutable"):
        save_evaluation_set_manifest(repository.engine, changed)


def test_tampered_persisted_manifest_fails_integrity_validation() -> None:
    repository = _repository()
    manifest = _manifest()
    save_evaluation_set_manifest(repository.engine, manifest)

    with Session(repository.engine) as session, session.begin():
        row = session.get(EvaluationSetManifestRow, manifest.content_hash)
        assert row is not None
        row.split_strategy = "tampered-after-persistence"

    with pytest.raises(ValueError, match="content_hash"):
        load_evaluation_set_manifest(repository.engine, manifest.content_hash)
