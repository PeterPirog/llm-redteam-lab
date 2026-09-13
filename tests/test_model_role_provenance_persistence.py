import pytest
from sqlalchemy import update

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_role_artifact import QualifiedModelRoleSet, qualify_model_role
from llm_redteam.model_roles import ModelRole, ModelRoleConfig
from llm_redteam.storage import (
    ExperimentRepository,
    ModelRolePolicyScope,
    build_campaign_model_role_provenance,
    load_campaign_model_role_provenance,
    save_campaign_model_role_provenance,
)
from llm_redteam.storage.model_role_models import CampaignModelRoleQualificationRow


def _identity(
    role: ModelRole,
    *,
    model: str,
    digest_char: str,
    attacker_variant_id: str | None = None,
):
    capabilities = ["text", "reasoning"] if role == ModelRole.RED_PLANNER else ["text"]
    config = ModelRoleConfig.model_validate(
        {
            "provider": "ollama",
            "model": model,
            "class": "local",
            "capabilities": capabilities,
            "temperature": 0.2,
            "max_output_tokens": 256,
        }
    )
    artifact = ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + digest_char * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )
    return qualify_model_role(
        role=role,
        config=config,
        artifact=artifact,
        attacker_variant_id=attacker_variant_id,
    )


def _role_set(*, planner_digest: str = "a") -> QualifiedModelRoleSet:
    return QualifiedModelRoleSet(
        identities=(
            _identity(
                ModelRole.RED_PLANNER,
                model="planner:latest",
                digest_char=planner_digest,
            ),
            _identity(
                ModelRole.RED_MUTATOR,
                model="mutator:latest",
                digest_char="b",
            ),
        )
    )


def _repository() -> ExperimentRepository:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    target = TargetIdentity(
        id="target-1",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="blue:latest",
        provider="ollama",
        model_digest="sha256:" + "f" * 64,
        configuration_hash="blue-config-v1",
    )
    snapshot_id = repository.save_target(target)
    repository.start_campaign(
        campaign_id="campaign-1",
        target_snapshot_id=snapshot_id,
        configuration_hash="campaign-config-v1",
        metric_definition_version="v2",
    )
    return repository


def test_model_role_provenance_round_trips_exact_artifact_identity() -> None:
    repository = _repository()
    provenance = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(),
    )

    saved_hash = save_campaign_model_role_provenance(repository.engine, provenance)
    loaded = load_campaign_model_role_provenance(
        repository.engine,
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
    )

    assert loaded is not None
    assert saved_hash == provenance.provenance_sha256 == loaded.provenance_sha256
    assert loaded.role_set == provenance.role_set
    planner = loaded.role_set.identity_for(ModelRole.RED_PLANNER)
    assert planner.model_id == "planner:latest"
    assert planner.artifact_digest == "sha256:" + "a" * 64
    assert planner.provider_id == "ollama"


def test_exact_repeat_is_idempotent_but_weight_change_is_immutable_conflict() -> None:
    repository = _repository()
    first = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(planner_digest="a"),
    )
    changed = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(planner_digest="d"),
    )

    assert save_campaign_model_role_provenance(repository.engine, first) == first.provenance_sha256
    assert save_campaign_model_role_provenance(repository.engine, first) == first.provenance_sha256
    with pytest.raises(ValueError, match="immutable"):
        save_campaign_model_role_provenance(repository.engine, changed)


def test_attack_and_judge_scopes_are_independently_persisted() -> None:
    repository = _repository()
    attack = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(),
    )
    judge_set = QualifiedModelRoleSet(
        identities=(
            _identity(
                ModelRole.JUDGE_SEMANTIC,
                model="judge:latest",
                digest_char="c",
            ),
        )
    )
    judge = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.JUDGE,
        role_set=judge_set,
    )

    save_campaign_model_role_provenance(repository.engine, attack)
    save_campaign_model_role_provenance(repository.engine, judge)

    loaded_attack = load_campaign_model_role_provenance(
        repository.engine,
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
    )
    loaded_judge = load_campaign_model_role_provenance(
        repository.engine,
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.JUDGE,
    )
    assert loaded_attack is not None
    assert loaded_judge is not None
    assert loaded_attack.role_set.route_ids == ("red_mutator", "red_planner")
    assert loaded_judge.role_set.route_ids == ("judge_semantic",)
    assert loaded_attack.provenance_sha256 != loaded_judge.provenance_sha256


def test_unknown_campaign_cannot_receive_model_role_provenance() -> None:
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    repository.create_schema()
    provenance = build_campaign_model_role_provenance(
        campaign_id="missing-campaign",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(),
    )

    with pytest.raises(ValueError, match="unknown campaign"):
        save_campaign_model_role_provenance(repository.engine, provenance)


def test_persisted_hash_tampering_is_detected_on_load() -> None:
    repository = _repository()
    provenance = build_campaign_model_role_provenance(
        campaign_id="campaign-1",
        policy_scope=ModelRolePolicyScope.ATTACK,
        role_set=_role_set(),
    )
    save_campaign_model_role_provenance(repository.engine, provenance)

    with repository.engine.begin() as connection:
        connection.execute(
            update(CampaignModelRoleQualificationRow)
            .where(CampaignModelRoleQualificationRow.campaign_id == "campaign-1")
            .values(artifact_digest="sha256:" + "e" * 64)
        )

    with pytest.raises(ValueError, match="qualification hash"):
        load_campaign_model_role_provenance(
            repository.engine,
            campaign_id="campaign-1",
            policy_scope=ModelRolePolicyScope.ATTACK,
        )
