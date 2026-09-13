import pytest

from llm_redteam.judges.provenance import (
    build_artifact_qualified_judge_policy_descriptor,
    qualify_judge_model_roles,
)
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.storage import fingerprint_judge_policy


def _models(*, multimodal_enabled: bool = True) -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.2,
                    "max_output_tokens": 256,
                    "fallback": [],
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "temperature": 0.7,
                    "max_output_tokens": 128,
                    "fallback": [],
                },
                "judge_semantic": {
                    "provider": "ollama",
                    "model": "judge-text:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                    "enabled": True,
                    "fallback": [],
                },
                "judge_multimodal": {
                    "provider": "ollama",
                    "model": "judge-vision:latest",
                    "class": "local",
                    "capabilities": ["text", "vision"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                    "enabled": multimodal_enabled,
                    "fallback": [],
                },
            },
        }
    )


def _artifact(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=2048,
        local_artifact=True,
        format="gguf",
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def _artifacts(*, semantic_char: str = "a") -> dict[tuple[str, str], ModelArtifactIdentity]:
    return {
        ("ollama", "judge-text:latest"): _artifact("judge-text:latest", semantic_char),
        ("ollama", "judge-vision:latest"): _artifact("judge-vision:latest", "b"),
    }


def test_semantic_judge_policy_is_bound_to_exact_artifact() -> None:
    base = {"kind": "semantic", "implementation": "SemanticJudge", "version": 1}
    descriptor = build_artifact_qualified_judge_policy_descriptor(
        policy_descriptor=base,
        models=_models(),
        artifacts=_artifacts(),
        semantic=True,
        multimodal=False,
    )

    assert base == {"kind": "semantic", "implementation": "SemanticJudge", "version": 1}
    binding = descriptor["model_role_artifacts"]
    assert binding["roles"][0]["route_id"] == "judge_semantic"
    assert binding["roles"][0]["artifact_digest"] == "sha256:" + "a" * 64


def test_same_judge_config_with_new_weights_changes_judge_policy_fingerprint() -> None:
    base = {"kind": "semantic", "implementation": "SemanticJudge", "version": 1}
    first = build_artifact_qualified_judge_policy_descriptor(
        policy_descriptor=base,
        models=_models(),
        artifacts=_artifacts(semantic_char="a"),
    )
    second = build_artifact_qualified_judge_policy_descriptor(
        policy_descriptor=base,
        models=_models(),
        artifacts=_artifacts(semantic_char="c"),
    )

    assert fingerprint_judge_policy(first) != fingerprint_judge_policy(second)


def test_semantic_and_multimodal_judges_have_exact_two_role_routes() -> None:
    qualified = qualify_judge_model_roles(
        models=_models(),
        artifacts=_artifacts(),
        semantic=True,
        multimodal=True,
    )

    assert qualified.route_ids == ("judge_multimodal", "judge_semantic")


def test_disabled_multimodal_judge_cannot_be_qualified_as_active_runtime_role() -> None:
    with pytest.raises(ValueError, match="not enabled"):
        qualify_judge_model_roles(
            models=_models(multimodal_enabled=False),
            artifacts=_artifacts(),
            semantic=False,
            multimodal=True,
        )


def test_model_free_judge_descriptor_does_not_use_artifact_qualification_helper() -> None:
    with pytest.raises(ValueError, match="model-backed Judge role"):
        build_artifact_qualified_judge_policy_descriptor(
            policy_descriptor={"kind": "deterministic", "version": 1},
            models=_models(),
            artifacts=_artifacts(),
            semantic=False,
            multimodal=False,
        )


def test_missing_semantic_judge_artifact_fails_closed() -> None:
    with pytest.raises(ValueError, match="verified model artifact missing"):
        build_artifact_qualified_judge_policy_descriptor(
            policy_descriptor={"kind": "semantic", "version": 1},
            models=_models(),
            artifacts={},
            semantic=True,
            multimodal=False,
        )
