import pytest

from llm_redteam.campaign_plan import RedPolicyKind
from llm_redteam.domain import CampaignBudget, TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.judges.provenance import build_artifact_qualified_judge_policy_descriptor
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.ollama_artifact_registry import OllamaArtifactRegistry
from llm_redteam.red.provenance import build_artifact_qualified_red_policy_descriptor
from llm_redteam.storage import fingerprint_attack_policy, fingerprint_judge_policy
from llm_redteam.targets.base import SessionMode


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
                    "model": "judge:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                    "fallback": [],
                },
            },
        }
    )


def _registry() -> OllamaArtifactRegistry:
    return OllamaArtifactRegistry.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-local-smoke",
            "require_local": True,
            "artifacts": {
                "planner:latest": {"digest": "sha256:" + "a" * 64},
                "mutator:latest": {"digest": "sha256:" + "b" * 64},
                "judge:latest": {"digest": "sha256:" + "c" * 64},
            },
        }
    )


def _tags(*, remote_planner: bool = False) -> dict[str, object]:
    def record(model: str, char: str) -> dict[str, object]:
        row: dict[str, object] = {
            "name": model,
            "model": model,
            "digest": "sha256:" + char * 64,
            "size": 1024,
            "details": {
                "format": "gguf",
                "family": "synthetic",
                "parameter_size": "9B",
                "quantization_level": "Q4_K_M",
            },
        }
        return row

    planner = record("planner:latest", "a")
    if remote_planner:
        planner["remote_host"] = "https://ollama.com"
    return {
        "models": [
            planner,
            record("mutator:latest", "b"),
            record("judge:latest", "c"),
        ]
    }


def _budget() -> CampaignBudget:
    return CampaignBudget(
        max_attacks=1,
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


def test_synthetic_local_inventory_produces_artifact_bound_red_and_judge_fingerprints() -> None:
    models = _models()
    qualification = _registry().verify_tags_response(
        _tags(),
        required_model_ids=("planner:latest", "mutator:latest", "judge:latest"),
    )

    red_descriptor = build_artifact_qualified_red_policy_descriptor(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.REPLAY,
        campaign_budget=_budget(),
        models=models,
        artifacts=qualification.artifact_map,
    )
    judge_descriptor = build_artifact_qualified_judge_policy_descriptor(
        policy_descriptor={"kind": "semantic", "implementation": "SemanticJudge", "version": 1},
        models=models,
        artifacts=qualification.artifact_map,
        semantic=True,
        multimodal=False,
    )

    attack_fingerprint = fingerprint_attack_policy(red_descriptor)
    judge_fingerprint = fingerprint_judge_policy(judge_descriptor)

    assert len(qualification.qualification_sha256) == 64
    assert len(attack_fingerprint) == 64
    assert len(judge_fingerprint) == 64
    assert red_descriptor["model_role_artifacts"]["set_sha256"]
    assert judge_descriptor["model_role_artifacts"]["set_sha256"]
    assert attack_fingerprint != judge_fingerprint


def test_remote_proxy_is_rejected_before_red_or_judge_policy_can_be_built() -> None:
    with pytest.raises(ValueError, match="local model, not remote proxy"):
        _registry().verify_tags_response(
            _tags(remote_planner=True),
            required_model_ids=("planner:latest", "mutator:latest", "judge:latest"),
        )
