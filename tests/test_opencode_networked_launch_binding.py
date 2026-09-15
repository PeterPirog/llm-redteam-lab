import json

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)
from llm_redteam.targets.opencode import OpenCodeConfig


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        hostname="127.0.0.1",
        port=4096,
        server_password_env="OPENCODE_SERVER_PASSWORD",
    )


def _binding(host: str = "model-peer") -> OpenCodeModelPeerBinding:
    network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host=host,
        model_endpoint_port=11434,
    )
    return OpenCodeModelPeerBinding.from_network(
        network=network,
        provider_id="ollama",
        model_id="qwen-local",
    )


def _sandbox_policy() -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256="a" * 64,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _attestation(
    sandbox_policy: AgentSandboxPolicy,
    **updates: object,
) -> AgentSandboxAttestation:
    runtime = _runtime()
    values: dict[str, object] = {
        "issuer": "synthetic-networked-opencode",
        "isolation_id": "synthetic-container",
        "runtime_profile_sha256": runtime.profile_sha256,
        "sandbox_policy_sha256": sandbox_policy.policy_sha256,
        "workspace_root_sha256": runtime.workspace_root_sha256,
        "proof_sha256": "b" * 64,
    }
    values.update(updates)
    return AgentSandboxAttestation.model_validate(values)


def _target(**updates: object) -> OpenCodeConfig:
    values: dict[str, object] = {
        "id": "opencode-target",
        "base_url": "http://127.0.0.1:4096",
        "model_provider_id": "ollama",
        "model_id": "qwen-local",
        "workspace_root": "/workspace",
        "application_version": "1.15.13",
        "password_env": "OPENCODE_SERVER_PASSWORD",
    }
    values.update(updates)
    return OpenCodeConfig.model_validate(values)


def test_launch_policy_injects_exact_isolated_model_provider() -> None:
    launch = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding(),
    )

    document = json.loads(launch.public_environment["OPENCODE_CONFIG_CONTENT"])
    provider = document["provider"]["ollama"]

    assert provider["options"]["baseURL"] == "http://model-peer:11434/v1"
    assert provider["models"] == {"qwen-local": {"name": "qwen-local"}}
    assert document["share"] == "disabled"
    assert document["autoupdate"] is False
    assert launch.required_secret_env_names == ("OPENCODE_SERVER_PASSWORD",)
    assert launch.command == (
        "opencode",
        "--pure",
        "serve",
        "--hostname",
        "127.0.0.1",
        "--port",
        "4096",
    )
    assert len(launch.policy_sha256) == 64


def test_launch_policy_validates_target_runtime_and_model_selection() -> None:
    launch = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding(),
    )

    launch.validate_target_config(_target())
    with pytest.raises(ValueError, match="workspace"):
        launch.validate_target_config(_target(workspace_root="/other"))
    with pytest.raises(ValueError, match="password env"):
        launch.validate_target_config(_target(password_env="OTHER_PASSWORD"))
    with pytest.raises(ValueError, match="model"):
        launch.validate_target_config(_target(model_id="other-model"))


def test_attested_plan_contains_model_binding_without_secret_values() -> None:
    sandbox_policy = _sandbox_policy()
    launch = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding(),
    )

    plan = launch.build_attested_plan(
        sandbox_policy=sandbox_policy,
        attestation=_attestation(sandbox_policy),
    )

    assert plan.public_environment == launch.public_environment
    assert plan.required_secret_env_names == ("OPENCODE_SERVER_PASSWORD",)
    assert plan.model_binding_sha256 == launch.model_binding.binding_sha256
    assert plan.networked_launch_policy_sha256 == launch.policy_sha256
    serialized = json.dumps(plan.model_dump(mode="json"), sort_keys=True)
    assert "OPENCODE_SERVER_PASSWORD" in serialized
    assert "password-value" not in serialized


def test_model_binding_is_part_of_stable_target_policy_identity() -> None:
    sandbox_policy = _sandbox_policy()
    attestation = _attestation(sandbox_policy)
    first = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding(),
    ).build_attested_plan(
        sandbox_policy=sandbox_policy,
        attestation=attestation,
    )
    second = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding("model-peer-2"),
    ).build_attested_plan(
        sandbox_policy=sandbox_policy,
        attestation=attestation,
    )

    assert first.target_policy_sha256 != second.target_policy_sha256
    assert first.launch_sha256 != second.launch_sha256


def test_attested_plan_rejects_runtime_or_sandbox_mismatch() -> None:
    sandbox_policy = _sandbox_policy()
    launch = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=_binding(),
    )

    with pytest.raises(ValueError, match="runtime profile"):
        launch.build_attested_plan(
            sandbox_policy=sandbox_policy,
            attestation=_attestation(
                sandbox_policy,
                runtime_profile_sha256="c" * 64,
            ),
        )

    with pytest.raises(ValueError, match="sandbox policy"):
        launch.build_attested_plan(
            sandbox_policy=sandbox_policy,
            attestation=_attestation(
                sandbox_policy,
                sandbox_policy_sha256="d" * 64,
            ),
        )
