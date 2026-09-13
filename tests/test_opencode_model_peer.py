import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.opencode_model_peer import (
    OpenCodeModelPeerBinding,
    OpenCodeProviderConfigDialect,
)
from llm_redteam.targets.opencode import OpenCodeConfig


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _target(**updates: object) -> OpenCodeConfig:
    values: dict[str, object] = {
        "id": "isolated-opencode",
        "base_url": "http://127.0.0.1:4096",
        "model_provider_id": "ollama",
        "model_id": "qwen-local",
        "workspace_root": "/workspace",
        "application_version": "1.15.13",
    }
    values.update(updates)
    return OpenCodeConfig.model_validate(values)


def test_v1_binding_points_opencode_at_exact_isolated_peer() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
    )

    fragment = binding.provider_config_fragment()
    provider = fragment["provider"]["ollama"]  # type: ignore[index]

    assert binding.endpoint_origin == "http://model-peer:11434"
    assert binding.base_url == "http://model-peer:11434/v1"
    assert provider["npm"] == "@ai-sdk/openai-compatible"
    assert provider["options"] == {"baseURL": "http://model-peer:11434/v1"}
    assert provider["models"] == {"qwen-local": {"name": "qwen-local"}}
    assert len(binding.binding_sha256) == 64


def test_v2_binding_uses_explicit_new_schema_without_version_guessing() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
        dialect=OpenCodeProviderConfigDialect.PROVIDERS_V2,
    )

    fragment = binding.provider_config_fragment()
    provider = fragment["providers"]["ollama"]  # type: ignore[index]

    assert provider["package"] == "@opencode/ai/providers/openai-compatible"
    assert provider["settings"] == {"baseURL": "http://model-peer:11434/v1"}
    assert provider["models"] == {"qwen-local": {}}


def test_binding_rejects_non_origin_or_credentialed_endpoints() -> None:
    for endpoint in (
        "https://model-peer:11434",
        "http://user:model-peer@model-peer:11434",
        "http://model-peer:11434/v1",
        "http://model-peer:11434?x=1",
    ):
        with pytest.raises(ValueError, match="plain HTTP origin"):
            OpenCodeModelPeerBinding(
                provider_id="ollama",
                model_id="qwen-local",
                endpoint_origin=endpoint,
            )


def test_merge_refuses_to_replace_existing_provider_policy() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
    )

    merged = binding.merge_config({"share": "disabled"})
    assert merged["share"] == "disabled"
    assert "provider" in merged

    with pytest.raises(ValueError, match="already defines provider"):
        binding.merge_config({"provider": {"other": {}}})


def test_target_selection_must_match_bound_local_peer() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
    )

    binding.validate_target_config(_target())

    with pytest.raises(ValueError, match="provider"):
        binding.validate_target_config(_target(model_provider_id="other"))
    with pytest.raises(ValueError, match="model"):
        binding.validate_target_config(_target(model_id="other-model"))
    with pytest.raises(ValueError, match="application_version"):
        binding.validate_target_config(_target(application_version=None))


def test_dialect_change_changes_measurement_fingerprint() -> None:
    first = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
        dialect=OpenCodeProviderConfigDialect.PROVIDER_V1,
    )
    second = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
        dialect=OpenCodeProviderConfigDialect.PROVIDERS_V2,
    )

    assert first.binding_sha256 != second.binding_sha256
