from pathlib import Path

from llm_redteam.model_roles import ModelRole, load_models_config

ROOT = Path(__file__).resolve().parents[1]


def test_hal_profile_loads_with_zero_cloud_fallback() -> None:
    config = load_models_config(ROOT / "config" / "models.hal-local.example.yaml")

    assert config.policy.local_first is True
    assert config.policy.allow_cloud_fallback is False
    assert config.role(ModelRole.RED_PLANNER).model == "nemotron-3.5-lightning:latest"
    assert config.role(ModelRole.RED_MUTATOR).model == "gpt-oss:latest"
    assert config.roles[ModelRole.JUDGE_SEMANTIC].model == "gemma4:31b"
    assert config.roles[ModelRole.JUDGE_SEMANTIC].enabled is False
    assert config.roles[ModelRole.JUDGE_MULTIMODAL].model == "muse-glimmer:latest"
    assert config.roles[ModelRole.JUDGE_MULTIMODAL].enabled is False
    assert config.roles[ModelRole.FORENSIC].model == "qwen3.6:latest"
    assert config.roles[ModelRole.FORENSIC].enabled is False
    assert config.red_attacker_pool.enabled is False


def test_hal_smoke_roles_use_direct_local_ollama_endpoint() -> None:
    config = load_models_config(ROOT / "config" / "models.hal-local.example.yaml")

    for role in (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR):
        model = config.role(role)
        assert model.provider == "ollama"
        assert model.location.value == "local"
        assert model.endpoint == "http://127.0.0.1:11434/v1/chat/completions"
        assert model.fallback == ()
