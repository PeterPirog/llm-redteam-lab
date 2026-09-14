from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_networked_opencode_profile import (
    DockerNetworkedOpenCodeAgentProfile,
)
from llm_redteam.docker_networked_opencode_supervisor import (
    DockerNetworkedOpenCodeSupervisor,
)
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentLease
from llm_redteam.docker_opencode_environment import (
    DockerNetworkedOpenCodeEnvironmentObservation,
)
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.opencode_health import OpenCodeHealthObservation
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_CONTAINER_ID = "c" * 64
_NETWORK_ID = "d" * 64
_MODEL_ID = "e" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(workspace_root="/workspace")


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
        ),
        model_network=_network(),
        launch_policy=_launch_policy(),
    )


def _sandbox_policy() -> AgentSandboxPolicy:
    profile = _profile()
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _network_lease() -> DockerModelNetworkLease:
    return DockerModelNetworkLease(
        network_name="rt-model-net",
        network_id_sha256=_digest(_NETWORK_ID),
        network_profile_sha256=_network().profile_sha256,
        create_command_sha256="1" * 64,
        engine=DockerEngineVersionObservation(
            server_version="28.5.1",
            major=28,
            minor=5,
            patch=1,
            command_sha256="2" * 64,
        ),
    )


def _agent_lease(
    *,
    runtime: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
) -> DockerNetworkedAgentLease:
    attestation = AgentSandboxAttestation(
        issuer="synthetic-networked-agent",
        isolation_id="docker-networked:" + _digest(_CONTAINER_ID),
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256="3" * 64,
    )
    network = _network()
    network_attestation = DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256=_digest(_NETWORK_ID),
        network_name_sha256=_digest("rt-model-net"),
        agent_container_id_sha256=_digest(_CONTAINER_ID),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
        model_endpoint_origin_sha256=_digest(network.model_endpoint_origin),
        network_inspection_sha256="4" * 64,
        agent_membership_sha256="5" * 64,
        model_membership_sha256="6" * 64,
    )
    return DockerNetworkedAgentLease(
        container_name="agent-peer",
        container_id_sha256=_digest(_CONTAINER_ID),
        launch_command_sha256="7" * 64,
        network_id_sha256=_digest(_NETWORK_ID),
        sandbox_attestation=attestation,
        network_attestation=network_attestation,
    )


class FakeAgentSupervisor:
    def __init__(self) -> None:
        self.released = 0
        self.launch_calls = 0

    def launch(self, **kwargs):
        self.launch_calls += 1
        assert kwargs["command"] == _profile().launch_command
        return _agent_lease(
            runtime=kwargs["runtime_profile"],
            sandbox_policy=kwargs["sandbox_policy"],
        )

    def release(self, lease: DockerNetworkedAgentLease) -> None:
        assert lease.container_id_sha256 == _digest(_CONTAINER_ID)
        self.released += 1


class FakeEnvironmentAttestor:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def observe(self, *, lease, profile):
        if self.fail:
            raise RuntimeError("synthetic environment failure")
        return DockerNetworkedOpenCodeEnvironmentObservation(
            container_id_sha256=lease.container_id_sha256,
            profile_sha256=profile.profile_sha256,
            command_sha256="8" * 64,
            public_environment_sha256="9" * 64,
            required_secret_names_sha256="a" * 64,
            redacted_observation_sha256="b" * 64,
        )


class FakeHealthSupervisor:
    def __init__(self, *, wrong_container: bool = False) -> None:
        self.wrong_container = wrong_container

    def probe_opencode_health(self, lease, runtime_profile, *, python_executable="python"):
        assert python_executable == "python"
        return OpenCodeHealthObservation(
            healthy=True,
            application_version="synthetic-opencode",
            runtime_profile_sha256=runtime_profile.profile_sha256,
            sandbox_attestation_sha256=lease.attestation.attestation_sha256,
            container_id_sha256=("f" * 64 if self.wrong_container else lease.container_id_sha256),
            endpoint_sha256="c" * 64,
            response_sha256="d" * 64,
        )


def _supervisor(
    agent: FakeAgentSupervisor,
    *,
    environment: FakeEnvironmentAttestor | None = None,
    health: FakeHealthSupervisor | None = None,
) -> DockerNetworkedOpenCodeSupervisor:
    return DockerNetworkedOpenCodeSupervisor(
        agent_supervisor=agent,  # type: ignore[arg-type]
        environment_attestor=environment or FakeEnvironmentAttestor(),  # type: ignore[arg-type]
        health_supervisor=health or FakeHealthSupervisor(),  # type: ignore[arg-type]
    )


def test_composed_launch_returns_only_after_environment_and_health_agree() -> None:
    agent = FakeAgentSupervisor()
    supervisor = _supervisor(agent)

    lease = supervisor.launch(
        profile=_profile(),
        launch_policy=_launch_policy(),
        model_network_profile=_network(),
        network_lease=_network_lease(),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
        runtime_profile=_runtime(),
        sandbox_policy=_sandbox_policy(),
        workspace_host_path="/tmp/rt-workspace",
        container_name="agent-peer",
    )

    assert agent.launch_calls == 1
    assert agent.released == 0
    assert lease.agent.container_id_sha256 == _digest(_CONTAINER_ID)
    assert lease.environment.container_id_sha256 == lease.health.container_id_sha256
    assert lease.launch_plan.public_environment == _launch_policy().public_environment

    supervisor.release(lease)
    assert agent.released == 1


def test_environment_failure_releases_owned_agent() -> None:
    agent = FakeAgentSupervisor()
    supervisor = _supervisor(agent, environment=FakeEnvironmentAttestor(fail=True))

    with pytest.raises(RuntimeError, match="synthetic environment failure"):
        supervisor.launch(
            profile=_profile(),
            launch_policy=_launch_policy(),
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_sandbox_policy(),
            workspace_host_path="/tmp/rt-workspace",
            container_name="agent-peer",
        )

    assert agent.released == 1


def test_cross_container_health_evidence_is_rejected_and_cleaned_up() -> None:
    agent = FakeAgentSupervisor()
    supervisor = _supervisor(agent, health=FakeHealthSupervisor(wrong_container=True))

    with pytest.raises(RuntimeError, match="different containers"):
        supervisor.launch(
            profile=_profile(),
            launch_policy=_launch_policy(),
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_sandbox_policy(),
            workspace_host_path="/tmp/rt-workspace",
            container_name="agent-peer",
        )

    assert agent.released == 1


def test_profile_launch_policy_drift_is_rejected_before_agent_start() -> None:
    agent = FakeAgentSupervisor()
    supervisor = _supervisor(agent)
    changed_network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer-2",
        model_endpoint_port=11434,
    )
    changed_policy = OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=OpenCodeModelPeerBinding.from_network(
            network=changed_network,
            provider_id="ollama",
            model_id="qwen-local",
        ),
    )

    with pytest.raises(ValueError, match="does not bind"):
        supervisor.launch(
            profile=_profile(),
            launch_policy=changed_policy,
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_sandbox_policy(),
            workspace_host_path="/tmp/rt-workspace",
            container_name="agent-peer",
        )

    assert agent.launch_calls == 0
