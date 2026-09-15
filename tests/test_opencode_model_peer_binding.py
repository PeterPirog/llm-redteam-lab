import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.opencode_model_peer import (
    OpenCodeModelPeerBinding,
    OpenCodeProviderConfigDialect,
)
from llm_redteam.targets.opencode import OpenCodeConfig


def _network(host: str = "model-peer") -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host=host,
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


def test_v1_binding_points_at_exact_isolated_network_peer() -> None:
    network = _network()
    binding = OpenCodeModelPeerBinding.from_network(
        network=network,
        provider_id="ollama",
        model_id="qwen-local",
    )

    fragment = binding.provider_config_fragment()
    provider = fragment["provider"]
    assert isinstance(provider, dict)
    ollama = provider["ollama"]
    assert isinstance(ollama, dict)

    assert binding.model_network_profile_sha256 == network.profile_sha256
    assert binding.endpoint_origin == "http://model-peer:11434"
    assert binding.base_url == "http://model-peer:11434/v1"
    assert ollama["npm"] == "@ai-sdk/openai-compatible"
    assert ollama["options"] == {"baseURL": "http://model-peer:11434/v1"}
    assert ollama["models"] == {"qwen-local": {"name": "qwen-local"}}
    assert len(binding.binding_sha256) == 64


def test_v2_binding_uses_explicit_providers_schema() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
        dialect=OpenCodeProviderConfigDialect.PROVIDERS_V2,
    )

    fragment = binding.provider_config_fragment()
    providers = fragment["providers"]
    assert isinstance(providers, dict)
    ollama = providers["ollama"]
    assert isinstance(ollama, dict)

    assert ollama["package"] == "@opencode/ai/providers/openai-compatible"
    assert ollama["settings"] == {"baseURL": "http://model-peer:11434/v1"}
    assert ollama["models"] == {"qwen-local": {"modelID": "qwen-local"}}


def test_binding_rejects_non_origin_credentialed_or_portless_endpoints() -> None:
    for endpoint in (
        "https://model-peer:11434",
        "http://user:secret@model-peer:11434",
        "http://model-peer:11434/v1",
        "http://model-peer:11434?x=1",
        "http://model-peer",
    ):
        with pytest.raises(ValueError, match="model peer endpoint"):
            OpenCodeModelPeerBinding(
                model_network_profile_sha256="a" * 64,
                provider_id="ollama",
                model_id="qwen-local",
                endpoint_origin=endpoint,
            )


def test_binding_rejects_model_network_drift() -> None:
    binding = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
    )

    binding.validate_network(_network())
    with pytest.raises(ValueError, match="requested model network"):
        binding.validate_network(_network("other-model-peer"))


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


def test_target_selection_must_match_bound_peer() -> None:
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


def test_network_model_and_dialect_are_measurement_identity() -> None:
    first = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
    )
    network_changed = OpenCodeModelPeerBinding.from_network(
        network=_network("model-peer-2"),
        provider_id="ollama",
        model_id="qwen-local",
    )
    model_changed = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="other-model",
    )
    dialect_changed = OpenCodeModelPeerBinding.from_network(
        network=_network(),
        provider_id="ollama",
        model_id="qwen-local",
        dialect=OpenCodeProviderConfigDialect.PROVIDERS_V2,
    )

    assert len({
        first.binding_sha256,
        network_changed.binding_sha256,
        model_changed.binding_sha256,
        dialect_changed.binding_sha256,
    }) == 4
