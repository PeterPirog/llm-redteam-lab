import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.storage.models import TargetSnapshotRow
from llm_redteam.storage.repository import ExperimentRepository


def _target(**updates) -> TargetIdentity:
    target = TargetIdentity(
        id="target-alpha",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="blue:latest",
        provider="ollama",
        runtime="http://localhost:11434",
        model_digest="sha256:" + "a" * 64,
        application="direct-model-api",
        application_version="v1",
        system_prompt_hash="b" * 64,
        configuration_hash="c" * 64,
        capabilities=frozenset({"text", "reasoning"}),
    )
    return target.model_copy(update=updates)


def test_target_snapshot_fingerprint_is_stable_and_full_length() -> None:
    first = _target()
    second = _target(capabilities=frozenset(("reasoning", "text")))

    first_fingerprint = ExperimentRepository.target_snapshot_fingerprint(first)
    second_fingerprint = ExperimentRepository.target_snapshot_fingerprint(second)

    assert len(first_fingerprint) == 64
    assert first_fingerprint == second_fingerprint
    assert ExperimentRepository.target_snapshot_id(first) == (
        f"target-{first_fingerprint[:24]}"
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"id": "target-beta"},
        {"target_class": TargetClass.WRITING},
        {"target_mode": TargetMode.PIPELINE},
        {"model": "blue:v2"},
        {"provider": "openai-compatible"},
        {"runtime": "http://localhost:9999"},
        {"model_digest": "sha256:" + "d" * 64},
        {"application": "openwebui"},
        {"application_version": "v2"},
        {"system_prompt_hash": "e" * 64},
        {"configuration_hash": "f" * 64},
        {"capabilities": frozenset({"text", "reasoning", "tools"})},
    ],
)
def test_any_security_target_identity_change_changes_snapshot(updates: dict) -> None:
    baseline = _target()
    changed = _target(**updates)

    assert ExperimentRepository.target_snapshot_fingerprint(baseline) != (
        ExperimentRepository.target_snapshot_fingerprint(changed)
    )
    assert ExperimentRepository.target_snapshot_id(baseline) != (
        ExperimentRepository.target_snapshot_id(changed)
    )


def test_same_mutable_model_tag_with_different_weights_persists_distinct_snapshots() -> None:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    first = _target(model_digest="sha256:" + "a" * 64)
    second = _target(model_digest="sha256:" + "d" * 64)

    first_id = repository.save_target(first)
    second_id = repository.save_target(second)

    assert first.model == second.model == "blue:latest"
    assert first.configuration_hash == second.configuration_hash
    assert first_id != second_id

    with Session(repository.engine) as session:
        rows = session.scalars(
            select(TargetSnapshotRow).order_by(TargetSnapshotRow.snapshot_id)
        ).all()
        assert len(rows) == 2
        assert {row.model_digest for row in rows} == {
            "sha256:" + "a" * 64,
            "sha256:" + "d" * 64,
        }
