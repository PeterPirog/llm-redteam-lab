import pytest

from llm_redteam.campaign_plan import RedPolicyKind
from llm_redteam.domain import CampaignBudget, TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.red.provenance import (
    build_artifact_qualified_red_policy_descriptor,
    qualify_red_model_roles,
)
from llm_redteam.storage import fingerprint_attack_policy
from llm_redteam.targets.base import SessionMode


def _models(*, attacker_pool: bool = False) -> ModelsConfig:
    payload = {
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


def _artifact(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def _budget() -> CampaignBudget:
    return CampaignBudget(
        max_attacks=2,
        max_generations=1,
        max_turns_per_attack=3,
        max_backtracks_per_attack=0,
        max_branches_per_attack=1,
        max_model_calls=8,
        max_model_calls_by_role={"red_planner": 6, "red_mutator": 2},
        max_total_output_tokens=2048,
        max_output_tokens_by_role={"red_planner": 1024, "red_mutator": 512},
        max_image_generations=0,
        wall_clock_seconds=300,
        max_non_progress_attempts=2,
    )


def _default_artifacts(*, planner_char: str = "a") -> dict[tuple[str, str], ModelArtifactIdentity]:
    return {
        ("ollama", "planner:latest"): _artifact("planner:latest", planner_char),
        ("ollama", "mutator:latest"): _artifact("mutator:latest", "b"),
    }


def _descriptor(
    *,
    artifacts: dict[tuple[str, str], ModelArtifactIdentity],
    models: ModelsConfig | None = None,
    attacker_variant_id: str | None = None,
) -> dict[str, object]:
    return build_artifact_qualified_red_policy_descriptor(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.REPLAY,
        campaign_budget=_budget(),
        models=models or _models(),
        artifacts=artifacts,
        attacker_variant_id=attacker_variant_id,
    )


def test_red_descriptor_contains_exact_planner_and_mutator_artifact_routes() -> None:
    descriptor = _descriptor(artifacts=_default_artifacts())

    artifact_binding = descriptor["model_role_artifacts"]
    assert isinstance(artifact_binding, dict)
    assert artifact_binding["version"] == 1
    roles = artifact_binding["roles"]
    assert isinstance(roles, list)
    assert [row["route_id"] for row in roles] == ["red_mutator", "red_planner"]
    assert {row["artifact_digest"] for row in roles} == {
        "sha256:" + "a" * 64,
        "sha256:" + "b" * 64,
    }


def test_same_red_config_with_new_planner_weights_changes_attack_policy_fingerprint() -> None:
    first = _descriptor(artifacts=_default_artifacts(planner_char="a"))
    second = _descriptor(artifacts=_default_artifacts(planner_char="c"))

    assert first["red_planner"] == second["red_planner"]
    assert first["model_role_artifacts"] != second["model_role_artifacts"]
    assert fingerprint_attack_policy(first) != fingerprint_attack_policy(second)


def test_red_artifact_qualification_fails_before_policy_fingerprint_when_artifact_missing() -> None:
    with pytest.raises(ValueError, match="verified model artifact missing"):
        _descriptor(
            artifacts={
                ("ollama", "planner:latest"): _artifact("planner:latest", "a"),
            }
        )


def test_explicit_attacker_variant_uses_namespaced_artifact_routes() -> None:
    models = _models(attacker_pool=True)
    artifacts = {
        ("ollama", "variant-planner-a:latest"): _artifact(
            "variant-planner-a:latest",
            "d",
        ),
        ("ollama", "variant-mutator-a:latest"): _artifact(
            "variant-mutator-a:latest",
            "e",
        ),
    }

    qualified = qualify_red_model_roles(
        models=models,
        artifacts=artifacts,
        attacker_variant_id="red-a",
    )
    descriptor = _descriptor(
        models=models,
        artifacts=artifacts,
        attacker_variant_id="red-a",
    )

    assert qualified.route_ids == ("red-a:red_mutator", "red-a:red_planner")
    assert descriptor["attacker_variant"]["id"] == "red-a"
    assert descriptor["model_role_artifacts"]["roles"][0]["route_id"].startswith("red-a:")
    assert descriptor["model_role_artifacts"]["roles"][1]["route_id"].startswith("red-a:")
