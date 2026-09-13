from pathlib import Path

from llm_redteam.model_roles import ModelLocation, ModelRole, load_models_config

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config" / "models.local-smoke.example.yaml"


def test_local_smoke_profile_is_strictly_local_and_cloud_fallback_is_disabled() -> None:
    config = load_models_config(PROFILE)

    assert config.policy.local_first is True
    assert config.policy.allow_cloud_fallback is False
    assert config.blue.source == "campaign"

    for role_config in config.roles.values():
        assert role_config.location == ModelLocation.LOCAL
        assert role_config.endpoint == "http://localhost:11434/v1/chat/completions"
        assert "cloud" not in role_config.model.lower()
        assert role_config.fallback == ()


def test_local_smoke_profile_keeps_judge_independent_from_default_red_planner() -> None:
    config = load_models_config(PROFILE)

    red = config.role(ModelRole.RED_PLANNER, required_capabilities={"text", "reasoning"})
    judge = config.role(
        ModelRole.JUDGE_SEMANTIC,
        required_capabilities={"text", "reasoning"},
    )

    assert red.model == "gpt-oss:latest"
    assert judge.model == "nemotron-3.5-lightning:latest"
    assert red.model != judge.model
    assert judge.invoke == "only_if_deterministic_inconclusive"


def test_local_smoke_profile_predeclares_but_does_not_enable_multi_attacker_pool() -> None:
    config = load_models_config(PROFILE)

    assert config.red_attacker_pool.enabled is False
    assert config.red_attacker_pool.enabled_variants == ()
    assert tuple(variant.id for variant in config.red_attacker_pool.variants) == (
        "gptoss-mistral",
        "qwen-ornith",
    )

    fingerprints = {
        (
            variant.planner.configuration_fingerprint,
            variant.mutator.configuration_fingerprint,
        )
        for variant in config.red_attacker_pool.variants
    }
    assert len(fingerprints) == 2

    for variant in config.red_attacker_pool.variants:
        assert variant.planner.location == ModelLocation.LOCAL
        assert variant.mutator.location == ModelLocation.LOCAL
        assert "cloud" not in variant.planner.model.lower()
        assert "cloud" not in variant.mutator.model.lower()
        assert variant.planner.fallback == ()
        assert variant.mutator.fallback == ()


def test_multimodal_judge_is_local_but_disabled_until_visual_evidence_is_needed() -> None:
    config = load_models_config(PROFILE)
    vision = config.roles[ModelRole.JUDGE_MULTIMODAL]

    assert vision.model == "llama3.2-vision:latest"
    assert vision.location == ModelLocation.LOCAL
    assert {"text", "vision"}.issubset(vision.capabilities)
    assert vision.enabled is False
    assert vision.invoke == "only_if_visual_evidence_requires_semantics"
