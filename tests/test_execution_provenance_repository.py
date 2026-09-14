import pytest
from sqlalchemy import update

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.storage.execution_provenance_models import CampaignExecutionProvenanceRow
from llm_redteam.storage.execution_provenance_repository import (
    build_execution_provenance_descriptor,
    load_campaign_execution_provenance,
    save_campaign_execution_provenance,
)
from llm_redteam.storage.repository import ExperimentRepository


def _repository() -> ExperimentRepository:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = TargetIdentity(
        id="synthetic-local-target",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="local-model",
        provider="ollama",
        runtime="http://127.0.0.1:11434",
        configuration_hash="a" * 64,
        capabilities=frozenset({"text"}),
    )
    target_snapshot_id = repository.save_target(target)
    repository.start_campaign(
        campaign_id="campaign-1",
        target_snapshot_id=target_snapshot_id,
        configuration_hash="b" * 64,
    )
    return repository


def _descriptor(endpoint_hash: str = "c" * 64):
    return build_execution_provenance_descriptor(
        kind="local_model_admission_v1",
        payload={
            "inventory_sha256": "d" * 64,
            "bindings": [
                {
                    "label": "blue",
                    "model_id": "local-model",
                    "inventory_record_sha256": "e" * 64,
                    "endpoint_sha256": endpoint_hash,
                }
            ],
        },
    )


def test_execution_provenance_round_trips_and_is_idempotent() -> None:
    repository = _repository()
    descriptor = _descriptor()

    first = save_campaign_execution_provenance(
        repository.engine,
        campaign_id="campaign-1",
        descriptor=descriptor,
    )
    second = save_campaign_execution_provenance(
        repository.engine,
        campaign_id="campaign-1",
        descriptor=descriptor,
    )
    loaded = load_campaign_execution_provenance(
        repository.engine,
        campaign_id="campaign-1",
        kind=descriptor.kind,
    )

    assert first == second == descriptor.content_hash
    assert loaded is not None
    assert loaded.descriptor == descriptor


def test_execution_provenance_rejects_mutation_for_same_kind() -> None:
    repository = _repository()
    save_campaign_execution_provenance(
        repository.engine,
        campaign_id="campaign-1",
        descriptor=_descriptor(),
    )

    with pytest.raises(ValueError, match="immutable"):
        save_campaign_execution_provenance(
            repository.engine,
            campaign_id="campaign-1",
            descriptor=_descriptor("f" * 64),
        )


def test_execution_provenance_requires_existing_campaign() -> None:
    repository = _repository()

    with pytest.raises(ValueError, match="unknown campaign"):
        save_campaign_execution_provenance(
            repository.engine,
            campaign_id="missing-campaign",
            descriptor=_descriptor(),
        )


def test_execution_provenance_rechecks_mutated_payload_before_save() -> None:
    repository = _repository()
    descriptor = _descriptor()
    descriptor.payload["inventory_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="content_hash does not match descriptor"):
        save_campaign_execution_provenance(
            repository.engine,
            campaign_id="campaign-1",
            descriptor=descriptor,
        )


def test_execution_provenance_detects_database_tampering() -> None:
    repository = _repository()
    descriptor = _descriptor()
    save_campaign_execution_provenance(
        repository.engine,
        campaign_id="campaign-1",
        descriptor=descriptor,
    )

    with repository.engine.begin() as connection:
        connection.execute(
            update(CampaignExecutionProvenanceRow)
            .where(CampaignExecutionProvenanceRow.campaign_id == "campaign-1")
            .values(provenance={"tampered": True})
        )

    with pytest.raises(ValueError, match="content hash mismatch"):
        load_campaign_execution_provenance(
            repository.engine,
            campaign_id="campaign-1",
            kind=descriptor.kind,
        )
