import pytest

from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_role_artifact import (
    ModelRoleQualificationRequest,
    QualifiedModelRoleSet,
    bind_policy_descriptor_to_model_roles,
    qualify_model_role,
    qualify_model_roles,
)
from llm_redteam.model_roles import ModelRole, ModelRoleConfig, ModelsConfig


def _role_config(
    *,
    model: str = "planner:latest",
    provider: str = "ollama",
    location: str = "local",
    enabled: bool = True,
    capabilities: tuple[str, ...] = ("text", "reasoning"),
    temperature: float = 0.2,
) -> ModelRoleConfig:
    return ModelRoleConfig.model_validate(
        {
            "provider": provider,
            "model": model,
            "class": location,
            "capabilities": list(capabilities),
            "endpoint": "http://localhost:11434/v1/chat/completions",
            "profile": "test",
            "temperature": temperature,
            "max_output_tokens": 256,
            "enabled": enabled,
            "fallback": [],
        }
    )


def _artifact(
    *,
    model: str = "planner:latest",
    provider: str = "ollama",
    digest_char: str = "a",
    local: bool = True,
) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id=provider,
        model_id=model,
        artifact_digest="sha256:" + digest_char * 64,
        artifact_size_bytes=1024,
        local_artifact=local,
        format="gguf",
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def _models(*, attacker_pool: bool = False) -> ModelsConfig:
    payload = {
        "version": 1,
        "policy": {"local_first": True, "allow_cloud_fallback": False},
        "roles": {
            "red_planner": {
                "provider": "ollama",
                "model": "planner:latest",
                "class": "local",
                "endpoint": "http://localhost:11434/v1/chat/completions",
                "capabilities": ["text", "reasoning"],
                "temperature": 0.2,
                "max_output_tokens": 256,
                "fallback": [],
            },
            "red_mutator": {
                "provider": "ollama",
                "model": "mutator:latest",
                "class": "local",
                "endpoint": "http://localhost:11434/v1/chat/completions",
                "capabilities": ["text"],
                "temperature": 0.7,
                "max_output_tokens": 128,
                "fallback": [],
            },
            "judge_semantic": {
                "provider": "ollama",
                "model": "judge:latest",
                "class": "local",
                "endpoint": "http://localhost:11434/v1/chat/completions",
                "capabilities": ["text", "reasoning"],
                "temperature": 0.0,
                "max_output_tokens": 256,
                "fallback": [],
            },
        },
    }
    if attacker_pool:
        payload["red_attacker_pool"] = {
            "enabled": True,
            "variants": [
                {
                    "id": "red-a",
                    "planner": {
                        "provider": "ollama",
                        "model": "variant-planner-a:latest",
                        "class": "local",
                        "capabilities": ["text", "reasoning"],
                        "temperature": 0.2,
                        "max_output_tokens": 256,
                        "fallback": [],
                    },
                    "mutator": {
                        "provider": "ollama",
                        "model": "variant-mutator-a:latest",
                        "class": "local",
                        "capabilities": ["text"],
                        "temperature": 0.7,
                        "max_output_tokens": 128,
                        "fallback": [],
                    },
                },
                {
                    "id": "red-b",
                    "planner": {
                        "provider": "ollama",
                        "model": "variant-planner-b:latest",
                        "class": "local",
                        "capabilities": ["text", "reasoning"],
                        "temperature": 0.3,
                        "max_output_tokens": 256,
                        "fallback": [],
                    },
                    "mutator": {
                        "provider": "ollama",
                        "model": "variant-mutator-b:latest",
                        "class": "local",
                        "capabilities": ["text"],
                        "temperature": 0.8,
                        "max_output_tokens": 128,
                        "fallback": [],
                    },
                },
            ],
        }
    return ModelsConfig.model_validate(payload)


def test_exact_role_and_artifact_are_bound_into_stable_identity() -> None:
    config = _role_config()
    artifact = _artifact()

    identity = qualify_model_role(
        role=ModelRole.RED_PLANNER,
        config=config,
        artifact=artifact,
    )

    assert identity.role == ModelRole.RED_PLANNER
    assert identity.provider_id == "ollama"
    assert identity.model_id == "planner:latest"
    assert identity.role_configuration_fingerprint == config.configuration_fingerprint
    assert identity.artifact_identity_sha256 == artifact.identity_sha256
    assert identity.artifact_digest == artifact.artifact_digest
    assert identity.local_artifact is True
    assert len(identity.qualification_sha256) == 64


def test_mutable_tag_with_new_artifact_changes_qualified_identity() -> None:
    config = _role_config(model="planner:latest")
    first = qualify_model_role(
        role=ModelRole.RED_PLANNER,
        config=config,
        artifact=_artifact(model="planner:latest", digest_char="a"),
    )
    second = qualify_model_role(
        role=ModelRole.RED_PLANNER,
        config=config,
        artifact=_artifact(model="planner:latest", digest_char="b"),
    )

    assert first.role_configuration_fingerprint == second.role_configuration_fingerprint
    assert first.artifact_identity_sha256 != second.artifact_identity_sha256
    assert first.qualification_sha256 != second.qualification_sha256


@pytest.mark.parametrize(
    ("config", "artifact", "message"),
    [
        (
            _role_config(provider="ollama"),
            _artifact(provider="other"),
            "provider",
        ),
        (
            _role_config(model="planner:latest"),
            _artifact(model="other:latest"),
            "model ID",
        ),
        (
            _role_config(location="local"),
            _artifact(local=False),
            "locality",
        ),
        (
            _role_config(location="cloud"),
            _artifact(local=True),
            "locality",
        ),
    ],
)
def test_qualification_rejects_provider_model_or_locality_drift(
    config: ModelRoleConfig,
    artifact: ModelArtifactIdentity,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        qualify_model_role(
            role=ModelRole.RED_PLANNER,
            config=config,
            artifact=artifact,
        )


def test_disabled_role_cannot_be_qualified_as_runtime_identity() -> None:
    with pytest.raises(ValueError, match="disabled"):
        qualify_model_role(
            role=ModelRole.RED_PLANNER,
            config=_role_config(enabled=False),
            artifact=_artifact(),
        )


def test_attacker_variant_is_valid_only_for_red_roles() -> None:
    with pytest.raises(ValueError, match="Red model roles"):
        qualify_model_role(
            role=ModelRole.JUDGE_SEMANTIC,
            config=_role_config(
                model="judge:latest",
                capabilities=("text", "reasoning"),
            ),
            artifact=_artifact(model="judge:latest"),
            attacker_variant_id="red-a",
        )


def test_qualified_role_set_hash_is_order_independent_and_routes_are_unique() -> None:
    planner = qualify_model_role(
        role=ModelRole.RED_PLANNER,
        config=_role_config(),
        artifact=_artifact(),
    )
    mutator = qualify_model_role(
        role=ModelRole.RED_MUTATOR,
        config=_role_config(
            model="mutator:latest",
            capabilities=("text",),
            temperature=0.7,
        ),
        artifact=_artifact(model="mutator:latest", digest_char="b"),
    )

    first = QualifiedModelRoleSet(identities=(planner, mutator))
    second = QualifiedModelRoleSet(identities=(mutator, planner))

    assert first.set_sha256 == second.set_sha256
    assert first.route_ids == ("red_mutator", "red_planner")
    assert first.identity_for(ModelRole.RED_PLANNER) == planner

    with pytest.raises(ValueError, match="unique"):
        QualifiedModelRoleSet(identities=(planner, planner))


def test_models_config_resolution_binds_default_red_and_judge_roles() -> None:
    models = _models()
    artifacts = {
        ("ollama", "planner:latest"): _artifact(model="planner:latest", digest_char="a"),
        ("ollama", "mutator:latest"): _artifact(model="mutator:latest", digest_char="b"),
        ("ollama", "judge:latest"): _artifact(model="judge:latest", digest_char="c"),
    }
    requests = (
        ModelRoleQualificationRequest(
            role=ModelRole.RED_PLANNER,
            required_capabilities=frozenset({"text", "reasoning"}),
        ),
        ModelRoleQualificationRequest(
            role=ModelRole.RED_MUTATOR,
            required_capabilities=frozenset({"text"}),
        ),
        ModelRoleQualificationRequest(
            role=ModelRole.JUDGE_SEMANTIC,
            required_capabilities=frozenset({"text", "reasoning"}),
        ),
    )

    qualified = qualify_model_roles(
        models=models,
        artifacts=artifacts,
        requests=requests,
    )

    assert qualified.route_ids == ("judge_semantic", "red_mutator", "red_planner")
    assert qualified.identity_for(ModelRole.JUDGE_SEMANTIC).artifact_digest.endswith("c" * 64)


def test_variant_route_is_disambiguated_from_default_red_role() -> None:
    models = _models(attacker_pool=True)
    artifacts = {
        ("ollama", "variant-planner-a:latest"): _artifact(
            model="variant-planner-a:latest",
            digest_char="d",
        )
    }

    qualified = qualify_model_roles(
        models=models,
        artifacts=artifacts,
        requests=(
            ModelRoleQualificationRequest(
                role=ModelRole.RED_PLANNER,
                attacker_variant_id="red-a",
                required_capabilities=frozenset({"text", "reasoning"}),
            ),
        ),
    )

    assert qualified.route_ids == ("red-a:red_planner",)
    assert (
        qualified.identity_for(
            ModelRole.RED_PLANNER,
            attacker_variant_id="red-a",
        ).model_id
        == "variant-planner-a:latest"
    )


def test_missing_verified_artifact_fails_closed() -> None:
    models = _models()
    with pytest.raises(ValueError, match="verified model artifact missing"):
        qualify_model_roles(
            models=models,
            artifacts={},
            requests=(
                ModelRoleQualificationRequest(role=ModelRole.RED_PLANNER),
            ),
        )


def test_policy_descriptor_binding_requires_exact_role_set_and_changes_with_weights() -> None:
    config = _role_config()
    first_roles = QualifiedModelRoleSet(
        identities=(
            qualify_model_role(
                role=ModelRole.RED_PLANNER,
                config=config,
                artifact=_artifact(digest_char="a"),
            ),
        )
    )
    second_roles = QualifiedModelRoleSet(
        identities=(
            qualify_model_role(
                role=ModelRole.RED_PLANNER,
                config=config,
                artifact=_artifact(digest_char="b"),
            ),
        )
    )
    base = {"kind": "adaptive", "runtime_version": 1}

    first = bind_policy_descriptor_to_model_roles(
        policy_descriptor=base,
        qualified_roles=first_roles,
        required_route_ids=("red_planner",),
    )
    second = bind_policy_descriptor_to_model_roles(
        policy_descriptor=base,
        qualified_roles=second_roles,
        required_route_ids=("red_planner",),
    )

    assert base == {"kind": "adaptive", "runtime_version": 1}
    assert first["model_role_artifacts"] != second["model_role_artifacts"]

    with pytest.raises(ValueError, match="do not match"):
        bind_policy_descriptor_to_model_roles(
            policy_descriptor=base,
            qualified_roles=first_roles,
            required_route_ids=("red_planner", "red_mutator"),
        )

    with pytest.raises(ValueError, match="already contains"):
        bind_policy_descriptor_to_model_roles(
            policy_descriptor={**base, "model_role_artifacts": {}},
            qualified_roles=first_roles,
            required_route_ids=("red_planner",),
        )
