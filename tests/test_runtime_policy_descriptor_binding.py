import pytest

from llm_redteam.campaigns.model_qualification import (
    qualify_campaign_policy_descriptors,
    validate_qualified_runtime_policy_descriptors,
)
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelRole, ModelsConfig


def _models() -> ModelsConfig:
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
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "temperature": 0.7,
                    "max_output_tokens": 128,
                },
                "judge_semantic": {
                    "provider": "ollama",
                    "model": "judge:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                },
            },
        }
    )


def _artifact(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
    )


def _qualified():
    attack = {
        "kind": "adaptive",
        "runtime_version": 2,
        "red_planner": {"model": "planner:latest", "temperature": 0.2},
        "red_mutator": {"model": "mutator:latest", "temperature": 0.7},
    }
    judge = {"kind": "semantic", "implementation": "SemanticJudge", "version": 1}
    qualified = qualify_campaign_policy_descriptors(
        required_model_roles=(
            ModelRole.RED_PLANNER,
            ModelRole.RED_MUTATOR,
            ModelRole.JUDGE_SEMANTIC,
        ),
        models=_models(),
        artifacts={
            ("ollama", "planner:latest"): _artifact("planner:latest", "a"),
            ("ollama", "mutator:latest"): _artifact("mutator:latest", "b"),
            ("ollama", "judge:latest"): _artifact("judge:latest", "c"),
        },
        attack_policy_descriptor=attack,
        judge_policy_descriptor=judge,
        model_backed_red=True,
    )
    return qualified, attack, judge


def test_actual_runtime_descriptors_match_prepared_qualified_policy() -> None:
    qualified, attack, judge = _qualified()

    validate_qualified_runtime_policy_descriptors(
        qualified=qualified,
        attack_policy_descriptor=attack,
        judge_policy_descriptor=judge,
    )


def test_red_runtime_descriptor_drift_is_rejected() -> None:
    qualified, attack, judge = _qualified()
    changed = dict(attack)
    changed["runtime_version"] = 3

    with pytest.raises(ValueError, match="Red runtime descriptor"):
        validate_qualified_runtime_policy_descriptors(
            qualified=qualified,
            attack_policy_descriptor=changed,
            judge_policy_descriptor=judge,
        )


def test_judge_runtime_descriptor_drift_is_rejected() -> None:
    qualified, attack, judge = _qualified()
    changed = dict(judge)
    changed["version"] = 2

    with pytest.raises(ValueError, match="Judge runtime descriptor"):
        validate_qualified_runtime_policy_descriptors(
            qualified=qualified,
            attack_policy_descriptor=attack,
            judge_policy_descriptor=changed,
        )
