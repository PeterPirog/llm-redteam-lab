import json
from collections import deque
from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_network_supervisor import DockerModelNetworkSupervisor
from llm_redteam.docker_supervisor import CommandResult

_NETWORK_ID = "d" * 64
_OTHER_NETWORK_ID = "e" * 64
_AGENT_ID = "a" * 64
_MODEL_ID = "b" * 64
_NETWORK_NAME = "rt-model-net"
_AGENT_NAME = "agent-peer"
_MODEL_NAME = "model-peer"


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected Docker command: {argv}")
        return self.results.popleft()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _profile() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host=_MODEL_NAME,
        model_endpoint_port=11434,
    )


def _network_payload(
    *,
    profile: DockerIsolatedModelNetworkProfile | None = None,
    network_id: str = _NETWORK_ID,
    internal: bool = True,
    containers: dict[str, object] | None = None,
) -> dict[str, object]:
    profile = profile or _profile()
    return {
        "Id": network_id,
        "Name": _NETWORK_NAME,
        "Driver": "bridge",
        "Scope": "local",
        "Internal": internal,
        "Ingress": False,
        "EnableIPv6": False,
        "Options": {
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
        },
        "Labels": {
            "llm-redteam.model-network-profile-sha256": profile.profile_sha256,
        },
        "Containers": containers or {},
    }


def _network_inspect_result(**kwargs) -> CommandResult:
    return CommandResult(
        stdout=json.dumps([_network_payload(**kwargs)]),
        returncode=0,
    )


def _members() -> dict[str, object]:
    return {
        _AGENT_ID: {
            "Name": _AGENT_NAME,
            "IPv4Address": "172.31.0.2/24",
            "IPv6Address": "",
        },
        _MODEL_ID: {
            "Name": _MODEL_NAME,
            "IPv4Address": "172.31.0.3/24",
            "IPv6Address": "",
        },
    }


def _container_payload(container_id: str, name: str) -> dict[str, object]:
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "State": {"Running": True},
        "NetworkSettings": {
            "Networks": {
                _NETWORK_NAME: {
                    "NetworkID": _NETWORK_ID,
                }
            }
        },
    }


def _container_inspect_result(container_id: str, name: str) -> CommandResult:
    return CommandResult(
        stdout=json.dumps([_container_payload(container_id, name)]),
        returncode=0,
    )


def _create_results(
    *,
    server_version: str = "28.5.1",
    inspected_network_id: str = _NETWORK_ID,
) -> list[CommandResult]:
    return [
        CommandResult(stdout=server_version + "\n", returncode=0),
        CommandResult(stdout=_NETWORK_ID + "\n", returncode=0),
        _network_inspect_result(network_id=inspected_network_id),
    ]


def _create(supervisor: DockerModelNetworkSupervisor):
    return supervisor.create(profile=_profile(), network_name=_NETWORK_NAME)


def test_create_admits_engine_28_and_binds_exact_network_id() -> None:
    runner = FakeRunner(_create_results(server_version="28.3.3-desktop.1"))
    supervisor = DockerModelNetworkSupervisor(runner)

    lease = _create(supervisor)

    assert runner.calls[0] == (
        "docker",
        "version",
        "--format",
        "{{.Server.Version}}",
    )
    assert runner.calls[1][:3] == ("docker", "network", "create")
    assert runner.calls[2] == ("docker", "network", "inspect", _NETWORK_NAME)
    assert lease.engine.major == 28
    assert lease.engine.minor == 3
    assert lease.engine.patch == 3
    assert lease.network_id_sha256 == _digest(_NETWORK_ID)
    assert lease.network_profile_sha256 == _profile().profile_sha256


def test_old_engine_is_rejected_before_network_creation() -> None:
    runner = FakeRunner([CommandResult(stdout="27.5.1\n", returncode=0)])
    supervisor = DockerModelNetworkSupervisor(runner)

    with pytest.raises(RuntimeError, match="too old"):
        _create(supervisor)

    assert runner.calls == [
        ("docker", "version", "--format", "{{.Server.Version}}")
    ]


def test_failed_network_create_never_removes_unproven_name() -> None:
    runner = FakeRunner(
        [
            CommandResult(stdout="28.5.1\n", returncode=0),
            CommandResult(returncode=1, stderr="synthetic name collision"),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)

    with pytest.raises(RuntimeError, match="creation failed"):
        _create(supervisor)

    assert not any(call[:3] == ("docker", "network", "rm") for call in runner.calls)


def test_network_name_reuse_before_admission_is_not_removed() -> None:
    changed = _network_inspect_result(network_id=_OTHER_NETWORK_ID)
    runner = FakeRunner(
        [
            CommandResult(stdout="28.5.1\n", returncode=0),
            CommandResult(stdout=_NETWORK_ID + "\n", returncode=0),
            changed,
            changed,
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)

    with pytest.raises(RuntimeError, match="ownership changed"):
        _create(supervisor)

    assert not any(call[:3] == ("docker", "network", "rm") for call in runner.calls)


def test_rejected_owned_network_is_cleaned_up_by_exact_id() -> None:
    bad = _network_inspect_result(internal=False)
    runner = FakeRunner(
        [
            CommandResult(stdout="28.5.1\n", returncode=0),
            CommandResult(stdout=_NETWORK_ID + "\n", returncode=0),
            bad,
            bad,
            CommandResult(returncode=0),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)

    with pytest.raises(ValueError, match="internal"):
        _create(supervisor)

    assert runner.calls[-1] == ("docker", "network", "rm", _NETWORK_NAME)


def test_attest_peers_rechecks_network_ownership_and_exact_membership() -> None:
    runner = FakeRunner(
        [
            *_create_results(),
            _network_inspect_result(containers=_members()),
            _container_inspect_result(_AGENT_ID, _AGENT_NAME),
            _container_inspect_result(_MODEL_ID, _MODEL_NAME),
            _network_inspect_result(containers=_members()),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)
    lease = _create(supervisor)

    attestation = supervisor.attest_peers(
        lease=lease,
        profile=_profile(),
        agent_container_name=_AGENT_NAME,
        agent_container_id_sha256=_digest(_AGENT_ID),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
    )

    assert attestation.network_id_sha256 == lease.network_id_sha256
    assert attestation.agent_container_id_sha256 == _digest(_AGENT_ID)
    assert attestation.model_peer_container_id_sha256 == _digest(_MODEL_ID)
    assert runner.calls[-1] == ("docker", "network", "inspect", _NETWORK_NAME)


def test_attestation_refuses_network_name_reuse_before_peer_inspection() -> None:
    runner = FakeRunner(
        [
            *_create_results(),
            _network_inspect_result(network_id=_OTHER_NETWORK_ID, containers=_members()),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)
    lease = _create(supervisor)

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.attest_peers(
            lease=lease,
            profile=_profile(),
            agent_container_name=_AGENT_NAME,
            agent_container_id_sha256=_digest(_AGENT_ID),
            model_peer_container_id_sha256=_digest(_MODEL_ID),
        )

    assert not any(
        call[:3] == ("docker", "inspect", "--type")
        for call in runner.calls[3:]
    )


def test_release_refuses_name_reuse_and_does_not_remove_other_network() -> None:
    runner = FakeRunner(
        [
            *_create_results(),
            _network_inspect_result(network_id=_OTHER_NETWORK_ID),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)
    lease = _create(supervisor)

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.release(lease)

    assert not any(call[:3] == ("docker", "network", "rm") for call in runner.calls)


def test_release_removes_owned_network_and_verifies_absence() -> None:
    runner = FakeRunner(
        [
            *_create_results(),
            _network_inspect_result(),
            CommandResult(returncode=0),
            CommandResult(returncode=1),
        ]
    )
    supervisor = DockerModelNetworkSupervisor(runner)
    lease = _create(supervisor)

    supervisor.release(lease)

    assert ("docker", "network", "rm", _NETWORK_NAME) in runner.calls
    assert runner.calls[-1] == ("docker", "network", "inspect", _NETWORK_NAME)


def test_unparseable_engine_version_fails_closed() -> None:
    runner = FakeRunner([CommandResult(stdout="synthetic-version\n", returncode=0)])
    supervisor = DockerModelNetworkSupervisor(runner)

    with pytest.raises(RuntimeError, match="not parseable"):
        supervisor.probe_engine_version()
