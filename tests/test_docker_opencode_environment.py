import json
from collections import deque
from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_networked_opencode_profile import (
    DockerNetworkedOpenCodeAgentProfile,
)
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentLease
from llm_redteam.docker_opencode_environment import (
    DockerNetworkedOpenCodeEnvironmentAttestor,
)
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import AgentSandboxAttestation, OpenCodeRuntimeProfile

_CONTAINER_ID = "c" * 64
_OTHER_ID = "d" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected command: {argv}")
        return self.results.popleft()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


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


def _lease() -> DockerNetworkedAgentLease:
    runtime = _runtime()
    sandbox = AgentSandboxAttestation(
        issuer="synthetic",
        isolation_id="docker-networked:" + _digest(_CONTAINER_ID),
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256="1" * 64,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256="2" * 64,
    )
    network = _network()
    network_attestation = DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256="3" * 64,
        network_name_sha256="4" * 64,
        agent_container_id_sha256=_digest(_CONTAINER_ID),
        model_peer_container_id_sha256="5" * 64,
        model_endpoint_origin_sha256=_digest(network.model_endpoint_origin),
        network_inspection_sha256="6" * 64,
        agent_membership_sha256="7" * 64,
        model_membership_sha256="8" * 64,
    )
    return DockerNetworkedAgentLease(
        container_name="agent-peer",
        container_id_sha256=_digest(_CONTAINER_ID),
        launch_command_sha256="9" * 64,
        network_id_sha256="a" * 64,
        sandbox_attestation=sandbox,
        network_attestation=network_attestation,
    )


def _inspect_payload(
    *,
    container_id: str = _CONTAINER_ID,
    command: tuple[str, ...] | None = None,
    environment: list[str] | None = None,
) -> CommandResult:
    profile = _profile()
    env = [
        *(f"{name}={value}" for name, value in profile.public_environment.items()),
        "OPENCODE_SERVER_PASSWORD=synthetic-secret",
        "PATH=/usr/local/bin:/usr/bin",
    ]
    if environment is not None:
        env = environment
    return CommandResult(
        returncode=0,
        stdout=json.dumps(
            [
                {
                    "Id": container_id,
                    "Config": {
                        "Cmd": list(command or profile.launch_command),
                        "Env": env,
                    },
                }
            ]
        ),
    )


def test_observation_proves_command_and_environment_without_secret_value() -> None:
    runner = FakeRunner([_inspect_payload()])
    attestor = DockerNetworkedOpenCodeEnvironmentAttestor(runner)

    observation = attestor.observe(lease=_lease(), profile=_profile())

    assert runner.calls == [("docker", "inspect", "--type", "container", "agent-peer")]
    assert observation.container_id_sha256 == _digest(_CONTAINER_ID)
    assert observation.profile_sha256 == _profile().profile_sha256
    assert observation.command_sha256 == _digest_json(list(_profile().launch_command))
    serialized = json.dumps(observation.model_dump(mode="json"), sort_keys=True)
    assert "synthetic-secret" not in serialized
    assert len(observation.proof_sha256) == 64


def test_observation_rejects_container_name_reuse() -> None:
    runner = FakeRunner([_inspect_payload(container_id=_OTHER_ID)])

    with pytest.raises(RuntimeError, match="no longer owns"):
        DockerNetworkedOpenCodeEnvironmentAttestor(runner).observe(
            lease=_lease(),
            profile=_profile(),
        )


def test_observation_rejects_command_drift() -> None:
    runner = FakeRunner([_inspect_payload(command=("opencode", "serve"))])

    with pytest.raises(RuntimeError, match="command drifted"):
        DockerNetworkedOpenCodeEnvironmentAttestor(runner).observe(
            lease=_lease(),
            profile=_profile(),
        )


def test_observation_rejects_public_environment_drift() -> None:
    profile = _profile()
    environment = [
        *(f"{name}={value}" for name, value in profile.public_environment.items()),
        "OPENCODE_SERVER_PASSWORD=synthetic-secret",
    ]
    for index, item in enumerate(environment):
        if item.startswith("OPENCODE_AUTO_SHARE="):
            environment[index] = "OPENCODE_AUTO_SHARE=true"
    runner = FakeRunner([_inspect_payload(environment=environment)])

    with pytest.raises(RuntimeError, match="public environment mismatch"):
        DockerNetworkedOpenCodeEnvironmentAttestor(runner).observe(
            lease=_lease(),
            profile=profile,
        )


def test_observation_rejects_missing_secret_and_duplicate_environment() -> None:
    profile = _profile()
    public_only = [
        f"{name}={value}" for name, value in profile.public_environment.items()
    ]
    missing_runner = FakeRunner([_inspect_payload(environment=public_only)])
    with pytest.raises(RuntimeError, match="required secret is absent"):
        DockerNetworkedOpenCodeEnvironmentAttestor(missing_runner).observe(
            lease=_lease(),
            profile=profile,
        )

    duplicate_runner = FakeRunner(
        [
            _inspect_payload(
                environment=[
                    *public_only,
                    "OPENCODE_SERVER_PASSWORD=one",
                    "OPENCODE_SERVER_PASSWORD=two",
                ]
            )
        ]
    )
    with pytest.raises(RuntimeError, match="duplicate Docker environment"):
        DockerNetworkedOpenCodeEnvironmentAttestor(duplicate_runner).observe(
            lease=_lease(),
            profile=profile,
        )


def _digest_json(value: object) -> str:
    from llm_redteam.agent_actions import canonical_json_hash

    return canonical_json_hash(value)
