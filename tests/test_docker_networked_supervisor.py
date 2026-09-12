import json
from collections import deque
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
from llm_redteam.docker_networked_sandbox import DockerNetworkedAgentProfile
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentSupervisor
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_NETWORK_ID = "f" * 64
_AGENT_ID = "a" * 64
_OTHER_ID = "b" * 64
_MODEL_ID = "c" * 64
_NETWORK_NAME = "rt-model-net"
_AGENT_NAME = "agent-peer"
_WORKSPACE = "/tmp/rt-workspace"
_IMAGE_ID = "sha256:" + "d" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "e" * 64


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


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


class FakeNetworkSupervisor:
    def __init__(self, attestation: DockerIsolatedModelNetworkAttestation) -> None:
        self.attestation = attestation
        self.calls = 0

    def attest_peers(self, **kwargs):
        self.calls += 1
        return self.attestation


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _profile() -> DockerNetworkedAgentProfile:
    base = DockerSandboxProfile(
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
    )
    return DockerNetworkedAgentProfile.compose(
        sandbox=base,
        model_network=_network(),
    )


def _policy() -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=_profile().profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(workspace_root="/workspace")


def _network_lease() -> DockerModelNetworkLease:
    return DockerModelNetworkLease(
        network_name=_NETWORK_NAME,
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


def _network_attestation() -> DockerIsolatedModelNetworkAttestation:
    network = _network()
    return DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256=_digest(_NETWORK_ID),
        network_name_sha256=_digest(_NETWORK_NAME),
        agent_container_id_sha256=_digest(_AGENT_ID),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
        model_endpoint_origin_sha256=_digest(network.model_endpoint_origin),
        network_inspection_sha256="3" * 64,
        agent_membership_sha256="4" * 64,
        model_membership_sha256="5" * 64,
    )


def _network_inspect(network_id: str = _NETWORK_ID) -> CommandResult:
    return CommandResult(stdout=json.dumps([{"Id": network_id}]), returncode=0)


def _agent_payload(container_id: str = _AGENT_ID) -> dict[str, object]:
    return {
        "Id": container_id,
        "Image": _IMAGE_ID,
        "State": {"Running": True},
        "HostConfig": {
            "AutoRemove": True,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": _NETWORK_NAME,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "Memory": 512 * 1024 * 1024,
            "NanoCpus": 2_000_000_000,
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": _WORKSPACE,
                "Destination": "/workspace",
                "RW": True,
            }
        ],
    }


def _agent_inspect(container_id: str = _AGENT_ID) -> CommandResult:
    return CommandResult(stdout=json.dumps([_agent_payload(container_id)]), returncode=0)


def test_launch_checks_network_before_start_and_returns_composed_lease() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_AGENT_ID + "\n", returncode=0),
            _agent_inspect(),
        ]
    )
    network_supervisor = FakeNetworkSupervisor(_network_attestation())
    supervisor = DockerNetworkedAgentSupervisor(
        network_supervisor=network_supervisor,  # type: ignore[arg-type]
        runner=runner,
    )

    lease = supervisor.launch(
        docker_profile=_profile(),
        model_network_profile=_network(),
        network_lease=_network_lease(),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
        runtime_profile=_runtime(),
        sandbox_policy=_policy(),
        workspace_host_path=_WORKSPACE,
        container_name=_AGENT_NAME,
        command=("opencode", "serve"),
    )

    assert runner.calls[0] == ("docker", "network", "inspect", _NETWORK_NAME)
    assert runner.calls[1][:2] == ("docker", "run")
    assert "--publish" not in runner.calls[1]
    assert lease.container_id_sha256 == _digest(_AGENT_ID)
    assert lease.network_id_sha256 == _digest(_NETWORK_ID)
    assert network_supervisor.calls == 1


def test_network_name_reuse_is_rejected_before_agent_launch() -> None:
    runner = FakeRunner([_network_inspect(_OTHER_ID)])
    supervisor = DockerNetworkedAgentSupervisor(
        network_supervisor=FakeNetworkSupervisor(_network_attestation()),  # type: ignore[arg-type]
        runner=runner,
    )

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.launch(
            docker_profile=_profile(),
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_policy(),
            workspace_host_path=_WORKSPACE,
            container_name=_AGENT_NAME,
            command=("opencode", "serve"),
        )

    assert len(runner.calls) == 1


def test_container_name_race_does_not_remove_unowned_container() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_AGENT_ID + "\n", returncode=0),
            _agent_inspect(_OTHER_ID),
            _agent_inspect(_OTHER_ID),
        ]
    )
    supervisor = DockerNetworkedAgentSupervisor(
        network_supervisor=FakeNetworkSupervisor(_network_attestation()),  # type: ignore[arg-type]
        runner=runner,
    )

    with pytest.raises(RuntimeError, match="ownership changed"):
        supervisor.launch(
            docker_profile=_profile(),
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_policy(),
            workspace_host_path=_WORKSPACE,
            container_name=_AGENT_NAME,
            command=("opencode", "serve"),
        )

    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)


def test_failed_run_never_removes_unproven_container_name() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(returncode=1, stderr="synthetic collision"),
        ]
    )
    supervisor = DockerNetworkedAgentSupervisor(
        network_supervisor=FakeNetworkSupervisor(_network_attestation()),  # type: ignore[arg-type]
        runner=runner,
    )

    with pytest.raises(RuntimeError, match="launch failed"):
        supervisor.launch(
            docker_profile=_profile(),
            model_network_profile=_network(),
            network_lease=_network_lease(),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
            runtime_profile=_runtime(),
            sandbox_policy=_policy(),
            workspace_host_path=_WORKSPACE,
            container_name=_AGENT_NAME,
            command=("opencode", "serve"),
        )

    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)
