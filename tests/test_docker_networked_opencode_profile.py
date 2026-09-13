from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_networked_opencode_profile import (
    DockerNetworkedOpenCodeAgentProfile,
)
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import OpenCodeRuntimeProfile

_IMAGE_REF = "synthetic/opencode@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        server_password_env="OPENCODE_SERVER_PASSWORD",
    )


def _launch_policy() -> OpenCodeNetworkedLaunchPolicy:
    return OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=OpenCodeModelPeerBinding.from_network(
            network=_network(),
            provider_id="ollama",
            model_id="qwen-local",
        ),
    )


def _profile() -> DockerNetworkedOpenCodeAgentProfile:
    return DockerNetworkedOpenCodeAgentProfile.compose(
        sandbox=DockerSandboxProfile(
            image_ref=_IMAGE_REF,
            image_id=_IMAGE_ID,
            container_workspace="/workspace",
            memory_limit_bytes=512 * 1024 * 1024,
            pids_limit=128,
            cpus=2.0,
        ),
        model_network=_network(),
        launch_policy=_launch_policy(),
    )


def test_profile_binds_network_and_application_launch_policy() -> None:
    profile = _profile()
    launch = _launch_policy()

    assert profile.launch_policy_sha256 == launch.policy_sha256
    assert profile.launch_command == launch.command
    assert profile.public_environment == launch.public_environment
    assert profile.required_secret_env_names == ("OPENCODE_SERVER_PASSWORD",)
    assert len(profile.profile_sha256) == 64


def test_docker_command_contains_public_config_and_secret_name_only() -> None:
    profile = _profile()

    command = profile.docker_run_command(
        container_name="agent-peer",
        workspace_host_path="/tmp/rt-workspace",
        network_name="rt-model-net",
        command=profile.launch_command,
        detach=True,
    )

    assert command[:2] == ("docker", "run")
    assert "--network" in command
    assert "rt-model-net" in command
    assert "--env" in command
    assert "OPENCODE_SERVER_PASSWORD" in command
    assert not any("OPENCODE_SERVER_PASSWORD=" in item for item in command)
    assert any(
        item.startswith("OPENCODE_CONFIG_CONTENT=")
        and "http://model-peer:11434/v1" in item
        for item in command
    )
    assert command.index("--env") < command.index(_IMAGE_REF)


def test_profile_rejects_command_drift() -> None:
    profile = _profile()

    try:
        profile.docker_run_command(
            container_name="agent-peer",
            workspace_host_path="/tmp/rt-workspace",
            network_name="rt-model-net",
            command=("opencode", "serve"),
            detach=True,
        )
    except ValueError as exc:
        assert "bound launch policy" in str(exc)
    else:
        raise AssertionError("command drift should be rejected")


def test_profile_rejects_binding_to_another_model_network() -> None:
    other_network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="other-model-peer",
        model_endpoint_port=11434,
    )

    try:
        DockerNetworkedOpenCodeAgentProfile.compose(
            sandbox=DockerSandboxProfile(
                image_ref=_IMAGE_REF,
                image_id=_IMAGE_ID,
            ),
            model_network=other_network,
            launch_policy=_launch_policy(),
        )
    except ValueError as exc:
        assert "requested model network" in str(exc)
    else:
        raise AssertionError("model-network drift should be rejected")
