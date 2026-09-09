import pytest
from sqlalchemy import inspect

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
from llm_redteam.evaluation_protocol import (
    discovery_protocol,
    held_out_evaluation_protocol,
)
from llm_redteam.evaluation_sets import build_held_out_evaluation_manifest
from llm_redteam.storage import (
    CampaignMeasurementSnapshot,
    ExperimentRepository,
    build_campaign_measurement_snapshot,
    build_evaluation_campaign_measurement_snapshot,
    fingerprint_attack_policy,
    fingerprint_case_set,
    fingerprint_corpus_snapshot,
    load_campaign_measurement_snapshot,
    load_evaluation_set_manifest,
    save_campaign_measurement_snapshot,
    save_evaluation_set_manifest,
)
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget

CAMPAIGN_CONFIG_HASH = "campaign-config-hash-v1"
METRIC_VERSION = "v2"
CORPUS_HASH = fingerprint_corpus_snapshot({"corpus": "heldout-test-v1"})


def _case(case_id: str, payload: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description=f"Measurement provenance fixture {case_id}.",
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


def _manifest():
    return build_held_out_evaluation_manifest(
        manifest_id="measurement-heldout-v1",
        discovery_cases=(_case("DISC-001", "discovery"),),
        evaluation_cases=(
            _case("EVAL-001", "evaluation-a"),
            _case("EVAL-002", "evaluation-b"),
        ),
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="explicit-versioned-test-split",
    )


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


def _evaluation_snapshot(
    repository: ExperimentRepository,
    snapshot_id: str,
) -> tuple[CampaignMeasurementSnapshot, object]:
    manifest = _manifest()
    save_evaluation_set_manifest(repository.engine, manifest)
    snapshot = build_evaluation_campaign_measurement_snapshot(
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
        manifest=manifest,
    )
    return snapshot, manifest


def test_schema_registers_measurement_and_evaluation_manifest_tables() -> None:
    repository, _ = _repository()
    tables = inspect(repository.engine).get_table_names()
    assert "campaign_measurement_protocols" in tables
    assert "evaluation_set_manifests" in tables


def test_evaluation_measurement_snapshot_round_trips_and_is_hash_bound() -> None:
    repository, target_snapshot_id = _repository()
    snapshot, manifest = _evaluation_snapshot(repository, target_snapshot_id)

    saved_hash = save_campaign_measurement_snapshot(repository.engine, snapshot)
    restored = load_campaign_measurement_snapshot(
        repository.engine,
        snapshot.campaign_id,
    )
    restored_manifest = load_evaluation_set_manifest(repository.engine, manifest.content_hash)

    assert saved_hash == snapshot.content_hash
    assert restored == snapshot
    assert restored_manifest == manifest
    assert restored is not None
    assert restored.target_snapshot_id == target_snapshot_id
    assert restored.metric_definition_version == METRIC_VERSION
    assert restored.protocol.purpose.value == "EVALUATION"
    assert restored.evaluation_manifest_hash == manifest.content_hash
    assert restored.held_out_case_set_hash == manifest.evaluation_case_set_hash
    assert restored.corpus_snapshot_hash == manifest.corpus_snapshot_hash


def test_exact_measurement_snapshot_resave_is_idempotent() -> None:
    repository, target_snapshot_id = _repository()
    snapshot, _ = _evaluation_snapshot(repository, target_snapshot_id)

    first = save_campaign_measurement_snapshot(repository.engine, snapshot)
    second = save_campaign_measurement_snapshot(repository.engine, snapshot)

    assert first == second == snapshot.content_hash


def test_campaign_measurement_snapshot_is_immutable_after_first_write() -> None:
    repository, target_snapshot_id = _repository()
    original, _ = _evaluation_snapshot(repository, target_snapshot_id)
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


def test_evaluation_requires_manifest_identity_in_generic_snapshot_builder() -> None:
    _, target_snapshot_id = _repository()
    common = {
        "campaign_id": "campaign-eval",
        "target_snapshot_id": target_snapshot_id,
        "campaign_configuration_hash": CAMPAIGN_CONFIG_HASH,
        "metric_definition_version": METRIC_VERSION,
        "protocol": held_out_evaluation_protocol(),
        "attack_policy_fingerprint": fingerprint_attack_policy({"policy": "frozen"}),
        "held_out_case_set_hash": "a" * 64,
        "corpus_snapshot_hash": "b" * 64,
    }

    with pytest.raises(ValueError, match="evaluation_manifest_hash"):
        build_campaign_measurement_snapshot(**common)


def test_evaluation_measurement_rejects_unpersisted_manifest() -> None:
    repository, target_snapshot_id = _repository()
    manifest = _manifest()
    snapshot = build_evaluation_campaign_measurement_snapshot(
        campaign_id="campaign-eval",
        target_snapshot_id=target_snapshot_id,
        campaign_configuration_hash=CAMPAIGN_CONFIG_HASH,
        metric_definition_version=METRIC_VERSION,
        protocol=held_out_evaluation_protocol(),
        attack_policy_fingerprint=fingerprint_attack_policy({"policy": "frozen"}),
        manifest=manifest,
    )

    with pytest.raises(ValueError, match="unpersisted manifest"):
        save_campaign_measurement_snapshot(repository.engine, snapshot)


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
    assert restored.evaluation_manifest_hash is None
    assert restored.evaluation_set_exposure is None


def test_measurement_snapshot_must_match_persisted_campaign_identity() -> None:
    repository, target_snapshot_id = _repository()
    valid, _ = _evaluation_snapshot(repository, target_snapshot_id)

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
    valid, _ = _evaluation_snapshot(repository, target_snapshot_id)
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
