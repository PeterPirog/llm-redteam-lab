import pytest

from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_role_artifact import (
    QualifiedModelRoleSet,
    bind_policy_descriptor_to_model_roles,
    qualify_model_role,
)
from llm_redteam.model_roles import ModelRole, ModelRoleConfig


def _qualified_planner():
    config = ModelRoleConfig.model_validate(
        {
            "provider": "ollama",
            "model": "planner:latest",
            "class": "local",
            "capabilities": ["text", "reasoning"],
            "temperature": 0.2,
            "max_output_tokens": 128,
        }
    )
    artifact = ModelArtifactIdentity(
        provider_id="ollama",
        model_id="planner:latest",
        artifact_digest="sha256:" + "a" * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
    )
    return qualify_model_role(
        role=ModelRole.RED_PLANNER,
        config=config,
        artifact=artifact,
    )


def test_empty_qualified_role_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        QualifiedModelRoleSet()


def test_policy_binding_rejects_empty_required_routes() -> None:
    roles = QualifiedModelRoleSet(identities=(_qualified_planner(),))
    with pytest.raises(ValueError, match="at least one"):
        bind_policy_descriptor_to_model_roles(
            policy_descriptor={"kind": "adaptive"},
            qualified_roles=roles,
            required_route_ids=(),
        )


def test_policy_binding_rejects_duplicate_required_routes() -> None:
    roles = QualifiedModelRoleSet(identities=(_qualified_planner(),))
    with pytest.raises(ValueError, match="must be unique"):
        bind_policy_descriptor_to_model_roles(
            policy_descriptor={"kind": "adaptive"},
            qualified_roles=roles,
            required_route_ids=("red_planner", "red_planner"),
        )
