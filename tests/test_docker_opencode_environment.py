import json
from collections import deque
from hashlib import sha256

import pytest

from llm_redteam.agent_actions import canonical_json_hash
from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_networked_opencode_profile import DockerNetworkedOpenCodeAgentProfile
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentLease
from llm_redteam.docker_opencode_environment import DockerNetworkedOpenCodeEnvironmentAttestor
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import AgentSandboxAttestation, OpenCodeRuntimeProfile

_CONTAINER_ID = "c" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64
_NETWORK_ID_SHA256 = "3" * 64


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


def _network(host: str = "model-peer") -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host=host,
        model_endpoint_port=11434,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        server_password_env="OPENCODE_SERVER_PASSWORD",
    )


def _profile(
    network: DockerIsolatedModelNetworkProfile | None = None,
) -> DockerNetworkedOpenCodeAgentProfile:
    selected_network = network or _network()
    launch = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=OpenCodeModelPeerBinding.from_network(
            network=selected_network,
            provider_id="ollama",
            model_id="qwen-local",
        ),
    )
    return DockerNetworkedOpenCodeAgentProfile.compose(
        sandbox=DockerSandboxProfile(
            image_ref=_IMAGE_REF,
            image_id=_IMAGE_ID,
            container_workspace="/workspace",
            memory_limit_bytes=512 * 1024 * 1024,
            pids_limit=128,
            cpus=2.0,
        ),
        model_network=selected_network,
        launch_policy=launch,
    )


def _lease(
    network: DockerIsolatedModelNetworkProfile | None = None,
) -> DockerNetworkedAgentLease:
    selected_network = network or _network()
    container_hash = _digest(_CONTAINER_ID)
    runtime = _runtime()
    sandbox = AgentSandboxAttestation(
        issuer="synthetic",
        isolation_id="docker-networked:" + container_hash,
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256="1" * 64,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256="2" * 64,
    )
    network_attestation = DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network",
        network_profile_sha256=selected_network.profile_sha256,
        network_id_sha256=_NETWORK_ID_SHA256,
        network_name_sha256="4" * 64,
        agent_container_id_sha256=container_hash,
        model_peer_container_id_sha256="5" * 64,
        model_endpoint_origin_sha256=_digest(selected_network.model_endpoint_origin),
        network_inspection_sha256="6" * 64,
        agent_membership_sha256="7" * 64,
        model_membership_sha256="8" * 64,
    )
    return DockerNetworkedAgentLease(
        container_name="agent-peer",
        container_id_sha256=container_hash,
        launch_command_sha256="9" * 64,
        network_id_sha256=_NETWORK_ID_SHA256,
        sandbox_attestation=sandbox,
        network_attestation=network_attestation,
    )


def _inspect(
    *,
    profile: DockerNetworkedOpenCodeAgentProfile | None = None,
    container_id: str = _CONTAINER_ID,
    command: tuple[str, ...] | None = None,
    environment: list[str] | None = None,
) -> CommandResult:
    selected = profile or _profile()
    env = [
        *(f"{name}={value}" for name, value in selected.public_environment.items()),
        "OPENCODE_SERVER_PASSWORD=synthetic-secret-do-not-persist",
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
                        "Cmd": list(command or selected.launch_command),
                        "Env": env,
                    },
                }
            ]
        ),
    )


def test_observation_proves_runtime_state_without_secret_value() -> None:
    profile = _profile()
    runner = FakeRunner([_inspect(profile=profile)])
    observation = DockerNetworkedOpenCodeEnvironmentAttestor(runner).observe(
        lease=_lease(), profile=profile
    )

    assert runner.calls == [("docker", "inspect", "--type", "container", "agent-peer")]
    assert observation.profile_sha256 == profile.profile_sha256
    assert observation.launch_policy_sha256 == profile.launch_policy_sha256
    assert observation.command_sha256 == canonical_json_hash(list(profile.launch_command))
    assert observation.public_environment_sha256 == canonical_json_hash(profile.public_environment)
    serialized = json.dumps(observation.model_dump(mode="json"), sort_keys=True)
    assert "synthetic-secret-do-not-persist" not in serialized
    assert "OPENCODE_SERVER_PASSWORD" not in serialized
    assert len(observation.proof_sha256) == 64


def test_observation_rejects_profile_for_another_network_before_inspect() -> None:
    runner = FakeRunner([])
    with pytest.raises(ValueError, match="model-network attestation"):
        DockerNetworkedOpenCodeEnvironmentAttestor(runner).observe(
            lease=_lease(_network()),
            profile=_profile(_network("other-peer")),
        )
    assert runner.calls == []


def test_observation_rejects_container_name_reuse_and_command_drift() -> None:
    with pytest.raises(RuntimeError, match="no longer owns"):
        DockerNetworkedOpenCodeEnvironmentAttestor(
            FakeRunner([_inspect(container_id="d" * 64)])
        ).observe(lease=_lease(), profile=_profile())

    with pytest.raises(RuntimeError, match="command drifted"):
        DockerNetworkedOpenCodeEnvironmentAttestor(
            FakeRunner([_inspect(command=("opencode", "serve"))])
        ).observe(lease=_lease(), profile=_profile())


def test_observation_rejects_public_environment_drift() -> None:
    profile = _profile()
    environment = [
        *(f"{name}={value}" for name, value in profile.public_environment.items()),
        "OPENCODE_SERVER_PASSWORD=synthetic-secret",
    ]
    environment = [
        "OPENCODE_AUTO_SHARE=true" if item.startswith("OPENCODE_AUTO_SHARE=") else item
        for item in environment
    ]
    with pytest.raises(RuntimeError, match="public environment mismatch"):
        DockerNetworkedOpenCodeEnvironmentAttestor(
            FakeRunner([_inspect(profile=profile, environment=environment)])
        ).observe(lease=_lease(), profile=profile)


def test_observation_rejects_missing_empty_or_duplicate_secret() -> None:
    profile = _profile()
    public_only = [f"{name}={value}" for name, value in profile.public_environment.items()]
    for environment in (
        public_only,
        [*public_only, "OPENCODE_SERVER_PASSWORD="],
    ):
        with pytest.raises(RuntimeError, match="required secret is absent"):
            DockerNetworkedOpenCodeEnvironmentAttestor(
                FakeRunner([_inspect(profile=profile, environment=environment)])
            ).observe(lease=_lease(), profile=profile)

    with pytest.raises(RuntimeError, match="duplicate Docker environment"):
        DockerNetworkedOpenCodeEnvironmentAttestor(
            FakeRunner(
                [
                    _inspect(
                        profile=profile,
                        environment=[
                            *public_only,
                            "OPENCODE_SERVER_PASSWORD=one",
                            "OPENCODE_SERVER_PASSWORD=two",
                        ],
                    )
                ]
            )
        ).observe(lease=_lease(), profile=profile)


def test_unrelated_environment_does_not_change_proof() -> None:
    profile = _profile()
    base = [
        *(f"{name}={value}" for name, value in profile.public_environment.items()),
        "OPENCODE_SERVER_PASSWORD=synthetic-secret",
    ]
    first = DockerNetworkedOpenCodeEnvironmentAttestor(
        FakeRunner([_inspect(profile=profile, environment=[*base, "PATH=/a"])])
    ).observe(lease=_lease(), profile=profile)
    second = DockerNetworkedOpenCodeEnvironmentAttestor(
        FakeRunner([_inspect(profile=profile, environment=[*base, "PATH=/b"])])
    ).observe(lease=_lease(), profile=profile)
    assert first.proof_sha256 == second.proof_sha256
