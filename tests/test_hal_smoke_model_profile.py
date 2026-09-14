from pathlib import Path

from llm_redteam.model_roles import ModelRole, load_models_config

ROOT = Path(__file__).resolve().parents[1]


def test_hal_smoke_profile_uses_only_local_zero_fallback_roles() -> None:
    config = load_models_config(ROOT / "config" / "models.hal-smoke.example.yaml")

    assert config.policy.local_first is True
    assert config.policy.allow_cloud_fallback is False
    assert config.role(ModelRole.RED_PLANNER).model == "gpt-oss:latest"
    assert config.role(ModelRole.RED_MUTATOR).model == "mistral:7b-instruct"
    assert config.roles[ModelRole.JUDGE_SEMANTIC].enabled is False
    assert config.roles[ModelRole.JUDGE_MULTIMODAL].enabled is False
    assert config.roles[ModelRole.FORENSIC].enabled is False
    assert config.red_attacker_pool.enabled is False

    for role in (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR):
        selected = config.role(role)
        assert selected.location.value == "local"
        assert selected.provider == "ollama"
        assert selected.fallback == ()
        assert selected.endpoint == "http://127.0.0.1:11434/v1/chat/completions"


def test_hal_smoke_planner_and_mutator_use_distinct_models() -> None:
    config = load_models_config(ROOT / "config" / "models.hal-smoke.example.yaml")

    assert config.role(ModelRole.RED_PLANNER).model != config.role(ModelRole.RED_MUTATOR).model
