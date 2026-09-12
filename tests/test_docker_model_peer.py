import json
from collections import deque
from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_model_peer import (
    DockerModelPeerProfile,
    DockerModelPeerSupervisor,
)
from llm_redteam.docker_supervisor import CommandResult

_NETWORK_ID = "a" * 64
_CONTAINER_ID = "b" * 64
_OTHER_ID = "c" * 64
_IMAGE_ID = "sha256:" + "d" * 64
_IMAGE_REF = "synthetic/model-peer@sha256:" + "e" * 64
_NETWORK_NAME = "rt-model-net"


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


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _profile(*, gpu_access: bool = False) -> DockerModelPeerProfile:
    return DockerModelPeerProfile(
        provider_id="synthetic-openai-compatible",
        model_id="synthetic-model-v1",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("model-server", "--port", "11434"),
        readiness_command=("model-health", "--json"),
        readiness_required_json={
            "ready": True,
            "model": "synthetic-model-v1",
        },
        memory_limit_bytes=2 * 1024 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
        gpu_access=gpu_access,
    )


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


def _network_inspect(network_id: str = _NETWORK_ID) -> CommandResult:
    return CommandResult(stdout=json.dumps([{"Id": network_id}]), returncode=0)


def _container_payload(
    container_id: str = _CONTAINER_ID,
    *,
    gpu_access: bool = False,
) -> dict[str, object]:
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
            "Memory": 2 * 1024 * 1024 * 1024,
            "NanoCpus": 2_000_000_000,
            "PortBindings": {},
            "DeviceRequests": (
                [
                    {
                        "Driver": "",
                        "Count": -1,
                        "DeviceIDs": None,
                        "Capabilities": [["gpu"]],
                        "Options": {},
                    }
                ]
                if gpu_access
                else []
            ),
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {_NETWORK_NAME: {}}},
    }


def _container_inspect(
    container_id: str = _CONTAINER_ID,
    *,
    gpu_access: bool = False,
) -> CommandResult:
    return CommandResult(
        stdout=json.dumps([_container_payload(container_id, gpu_access=gpu_access)]),
        returncode=0,
    )


def _ready(*, model: str = "synthetic-model-v1") -> CommandResult:
    return CommandResult(
        stdout=json.dumps({"ready": True, "model": model}),
        returncode=0,
    )


def test_profile_launch_has_exact_network_and_no_host_ports_or_mounts() -> None:
    command = _profile().docker_run_command(
        network_profile=_network(),
        network_name=_NETWORK_NAME,
    )

    assert command[:2] == ("docker", "run")
    assert command[command.index("--name") + 1] == "model-peer"
    assert command[command.index("--network") + 1] == _NETWORK_NAME
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--publish" not in command
    assert "-p" not in command
    assert "--mount" not in command


def test_gpu_access_is_explicit_stable_policy() -> None:
    cpu_profile = _profile(gpu_access=False)
    gpu_profile = _profile(gpu_access=True)
    command = gpu_profile.docker_run_command(
        network_profile=_network(),
        network_name=_NETWORK_NAME,
    )

    assert gpu_profile.profile_sha256 != cpu_profile.profile_sha256
    assert command[command.index("--gpus") + 1] == "all"


def test_launch_returns_exact_ready_model_peer_lease_without_inference() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _container_inspect(),
            _network_inspect(),
            _container_inspect(),
            _ready(),
            _container_inspect(),
        ]
    )
    supervisor = DockerModelPeerSupervisor(runner)

    lease = supervisor.launch(
        profile=_profile(),
        network_profile=_network(),
        network_lease=_network_lease(),
    )

    assert runner.calls[0] == ("docker", "network", "inspect", _NETWORK_NAME)
    assert runner.calls[1][:2] == ("docker", "run")
    assert runner.calls[5] == (
        "docker",
        "exec",
        "model-peer",
        "model-health",
        "--json",
    )
    assert lease.container_id_sha256 == _digest(_CONTAINER_ID)
    assert lease.network_id_sha256 == _digest(_NETWORK_ID)
    assert lease.profile_sha256 == _profile().profile_sha256
    assert lease.readiness.ready is True
    assert lease.readiness.model_id == "synthetic-model-v1"


def test_reused_network_name_is_rejected_before_model_peer_launch() -> None:
    runner = FakeRunner([_network_inspect(_OTHER_ID)])
    supervisor = DockerModelPeerSupervisor(runner)

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.launch(
            profile=_profile(),
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert len(runner.calls) == 1


def test_wrong_readiness_model_fails_closed_and_removes_only_owned_peer() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _container_inspect(),
            _network_inspect(),
            _container_inspect(),
            _ready(model="different-model"),
            _container_inspect(),
            _container_inspect(),
            CommandResult(returncode=0),
        ]
    )
    supervisor = DockerModelPeerSupervisor(runner)

    with pytest.raises(RuntimeError, match="readiness requirement failed"):
        supervisor.launch(
            profile=_profile(),
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert runner.calls[-1] == ("docker", "rm", "--force", "model-peer")


def test_name_reuse_during_rejected_readiness_never_removes_replacement() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _container_inspect(),
            _network_inspect(),
            _container_inspect(),
            _ready(model="different-model"),
            _container_inspect(),
            _container_inspect(_OTHER_ID),
        ]
    )
    supervisor = DockerModelPeerSupervisor(runner)

    with pytest.raises(RuntimeError, match="readiness requirement failed"):
        supervisor.launch(
            profile=_profile(),
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)


def test_gpu_inspection_requires_matching_device_request() -> None:
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _container_inspect(gpu_access=True),
            _network_inspect(),
            _container_inspect(gpu_access=True),
            _ready(),
            _container_inspect(gpu_access=True),
        ]
    )

    lease = DockerModelPeerSupervisor(runner).launch(
        profile=_profile(gpu_access=True),
        network_profile=_network(),
        network_lease=_network_lease(),
    )

    assert lease.readiness.ready is True
