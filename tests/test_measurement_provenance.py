import pytest
from sqlalchemy import inspect

from llm_redteam.evaluation_protocol import (
    discovery_protocol,
    held_out_evaluation_protocol,
)
from llm_redteam.storage import (
    CampaignMeasurementSnapshot,
    ExperimentRepository,
    build_campaign_measurement_snapshot,
    fingerprint_attack_policy,
    fingerprint_case_set,
    fingerprint_corpus_snapshot,
    load_campaign_measurement_snapshot,
    save_campaign_measurement_snapshot,
)
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget


CAMPAIGN_CONFIG_HASH = "campaign-config-hash-v1"
METRIC_VERSION = "v2"


def _repository() -> tuple[ExperimentRepository, str]:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = EscalatingVaultTarget()
    snapshot_id = repository.save_target(target.identity)
    repository.start_campaign(
        campaign_id="campaign-eval",
        target_snapshot_id=snapshot_id,
        configuration_hash=CAMPAIGN_CONFIG_HASH,
        metric_definition_version=METRIC_VERSION,
    )
    return repository, snapshot_id


def _evaluation_snapshot(snapshot_id: str) -> CampaignMeasurementSnapshot:
    return build_campaign_measurement_snapshot(
        campaign_id="campaign-eval",
        target_snapshot_id=snapshot_id,
        campaign_configuration_hash=CAMPAIGN_CONFIG_HASH,
        metric_definition_version=METRIC_VERSION,
        protocol=held_out_evaluation_protocol(),
        attack_policy_fingerprint=fingerprint_attack_policy(
            {
                "policy": "frozen-red-v1",
                "max_turns": 4,
                "planner": "configured-role",
            }
        ),
        held_out_case_set_hash=fingerprint_case_set(("case-b", "case-a")),
        corpus_snapshot_hash=fingerprint_corpus_snapshot(
            {
                "manifest_version": 1,
                "cases": {
                    "case-a": "content-hash-a",
                    "case-b": "content-hash-b",
                },
            }
        ),
    )


def test_schema_registers_measurement_protocol_table() -> None:
    repository, _ = _repository()
    assert "campaign_measurement_protocols" in inspect(repository.engine).get_table_names()


def test_evaluation_measurement_snapshot_round_trips_and_is_hash_bound() -> None:
    repository, target_snapshot_id = _repository()
    snapshot = _evaluation_snapshot(target_snapshot_id)

    saved_hash = save_campaign_measurement_snapshot(repository.engine, snapshot)
    restored = load_campaign_measurement_snapshot(
        repository.engine,
        snapshot.campaign_id,
    )

    assert saved_hash == snapshot.content_hash
    assert restored == snapshot
    assert restored is not None
    assert restored.target_snapshot_id == target_snapshot_id
    assert restored.metric_definition_version == METRIC_VERSION
    assert restored.protocol.purpose.value == "EVALUATION"


def test_exact_measurement_snapshot_resave_is_idempotent() -> None:
    repository, target_snapshot_id = _repository()
    snapshot = _evaluation_snapshot(target_snapshot_id)

    first = save_campaign_measurement_snapshot(repository.engine, snapshot)
    second = save_campaign_measurement_snapshot(repository.engine, snapshot)

    assert first == second == snapshot.content_hash


def test_campaign_measurement_snapshot_is_immutable_after_first_write() -> None:
    repository, target_snapshot_id = _repository()
    original = _evaluation_snapshot(target_snapshot_id)
    save_campaign_measurement_snapshot(repository.engine, original)
    changed = build_campaign_measurement_snapshot(
        campaign_id=original.campaign_id,
        target_snapshot_id=target_snapshot_id,
        campaign_configuration_hash=CAMPAIGN_CONFIG_HASH,
        metric_definition_version=METRIC_VERSION,
        protocol=discovery_protocol(),
    )

    with pytest.raises(ValueError, match="immutable"):
        save_campaign_measurement_snapshot(repository.engine, changed)


def test_evaluation_requires_all_reproducibility_fingerprints() -> None:
    _, target_snapshot_id = _repository()
    common = {
        "campaign_id": "campaign-eval",
        "target_snapshot_id": target_snapshot_id,
        "campaign_configuration_hash": CAMPAIGN_CONFIG_HASH,
        "metric_definition_version": METRIC_VERSION,
        "protocol": held_out_evaluation_protocol(),
    }
    policy = fingerprint_attack_policy({"policy": "frozen"})
    cases = fingerprint_case_set(("case-a",))
    corpus = fingerprint_corpus_snapshot({"case-a": "hash-a"})

    with pytest.raises(ValueError, match="attack_policy_fingerprint"):
        build_campaign_measurement_snapshot(
            **common,
            held_out_case_set_hash=cases,
            corpus_snapshot_hash=corpus,
        )
    with pytest.raises(ValueError, match="held_out_case_set_hash"):
        build_campaign_measurement_snapshot(
            **common,
            attack_policy_fingerprint=policy,
            corpus_snapshot_hash=corpus,
        )
    with pytest.raises(ValueError, match="corpus_snapshot_hash"):
        build_campaign_measurement_snapshot(
            **common,
            attack_policy_fingerprint=policy,
            held_out_case_set_hash=cases,
        )


def test_discovery_snapshot_can_omit_held_out_fingerprints() -> None:
    repository, target_snapshot_id = _repository()
    snapshot = build_campaign_measurement_snapshot(
        campaign_id="campaign-eval",
        target_snapshot_id=target_snapshot_id,
        campaign_configuration_hash=CAMPAIGN_CONFIG_HASH,
        metric_definition_version=METRIC_VERSION,
        protocol=discovery_protocol(),
    )

    save_campaign_measurement_snapshot(repository.engine, snapshot)
    restored = load_campaign_measurement_snapshot(repository.engine, "campaign-eval")

    assert restored == snapshot
    assert restored is not None
    assert restored.attack_policy_fingerprint is None
    assert restored.held_out_case_set_hash is None
    assert restored.corpus_snapshot_hash is None


def test_measurement_snapshot_must_match_persisted_campaign_identity() -> None:
    repository, target_snapshot_id = _repository()
    valid = _evaluation_snapshot(target_snapshot_id)

    mismatches = (
        valid.model_copy(update={"target_snapshot_id": "wrong-target"}),
        valid.model_copy(update={"campaign_configuration_hash": "wrong-config"}),
        valid.model_copy(update={"metric_definition_version": "wrong-metrics"}),
    )
    messages = ("target_snapshot_id", "configuration hash", "metric definition")
    for snapshot, message in zip(mismatches, messages, strict=True):
        with pytest.raises(ValueError, match=message):
            save_campaign_measurement_snapshot(repository.engine, snapshot)


def test_unknown_campaign_is_rejected() -> None:
    repository, target_snapshot_id = _repository()
    valid = _evaluation_snapshot(target_snapshot_id)
    unknown = valid.model_copy(update={"campaign_id": "missing-campaign"})

    with pytest.raises(ValueError, match="unknown campaign"):
        save_campaign_measurement_snapshot(repository.engine, unknown)


def test_case_set_fingerprint_is_order_independent_and_deduplicated() -> None:
    assert fingerprint_case_set(("case-b", "case-a", "case-a")) == fingerprint_case_set(
        ("case-a", "case-b")
    )
    with pytest.raises(ValueError, match="cannot be empty"):
        fingerprint_case_set(())
    with pytest.raises(ValueError, match="empty case id"):
        fingerprint_case_set(("case-a", ""))
