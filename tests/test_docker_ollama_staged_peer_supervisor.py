import json
from collections import deque
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_ollama_staged_peer import DockerOllamaStagedPeerProfile
from llm_redteam.docker_ollama_staged_peer_supervisor import (
    DockerOllamaStagedPeerSupervisor,
)
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.ollama_model_staging import (
    OllamaStagedModelStoreIdentity,
    PreparedOllamaModelStore,
)

_CONTAINER_ID = "c" * 64
_NETWORK_ID = "d" * 64
_NETWORK_NAME = "rt-model-net"
_IMAGE_ID = "sha256:" + "a" * 64
_IMAGE_REF = "synthetic/ollama@sha256:" + "b" * 64


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


def _store(tmp_path: Path) -> PreparedOllamaModelStore:
    models = tmp_path / "stage" / "models"
    models.mkdir(parents=True)
    identity = OllamaStagedModelStoreIdentity(
        model_id="qwen-local",
        manifest_digest="sha256:" + "e" * 64,
        manifest_relative_path_sha256="3" * 64,
        staged_tree_sha256="4" * 64,
        referenced_blob_count=2,
        referenced_blob_bytes=1024,
    )
    return PreparedOllamaModelStore(models_path=models, identity=identity)


def _profile(store: PreparedOllamaModelStore) -> DockerOllamaStagedPeerProfile:
    return DockerOllamaStagedPeerProfile(
        provider_id="ollama",
        model_id="qwen-local",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("ollama", "serve"),
        readiness_command=("/usr/local/bin/rt-ollama-probe", "version"),
        readiness_required_json={"provider": "ollama", "ready": True},
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
        staged_store_identity_sha256=store.identity.identity_sha256,
    )


def _network_inspect() -> CommandResult:
    return CommandResult(returncode=0, stdout=json.dumps([{"Id": _NETWORK_ID}]))


def _container_payload(
    store: PreparedOllamaModelStore,
    *,
    read_write: bool = False,
) -> dict[str, object]:
    return {
        "Id": _CONTAINER_ID,
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
            "PortBindings": {},
            "DeviceRequests": [],
        },
        "Config": {"Env": ["OLLAMA_MODELS=/models"]},
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(store.models_path),
                "Destination": "/models",
                "RW": read_write,
            }
        ],
        "NetworkSettings": {
            "Networks": {_NETWORK_NAME: {"NetworkID": _NETWORK_ID}}
        },
    }


def _container_inspect(
    store: PreparedOllamaModelStore,
    *,
    read_write: bool = False,
) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps([_container_payload(store, read_write=read_write)]),
    )


def test_launch_staged_requires_mount_proof_before_readiness(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(returncode=0, stdout=_CONTAINER_ID + "\n"),
            _container_inspect(store),
            _network_inspect(),
            _container_inspect(store),
            CommandResult(returncode=0, stdout='{"provider":"ollama","ready":true}'),
            _container_inspect(store),
        ]
    )

    lease = DockerOllamaStagedPeerSupervisor(runner).launch_staged(
        profile=profile,
        staged_store=store,
        network_profile=_network(),
        network_lease=_network_lease(),
    )

    assert runner.calls[0] == ("docker", "network", "inspect", _NETWORK_NAME)
    assert runner.calls[1][:2] == ("docker", "run")
    assert "--mount" in runner.calls[1]
    exec_index = next(i for i, call in enumerate(runner.calls) if call[:2] == ("docker", "exec"))
    assert exec_index > 2
    assert lease.peer.container_id_sha256 == _digest(_CONTAINER_ID)
    assert lease.peer.readiness.ready is True
    assert lease.staging.staged_store_identity_sha256 == store.identity.identity_sha256
    assert len(lease.proof_sha256) == 64


def test_failed_mount_attestation_cleans_only_owned_container(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(returncode=0, stdout=_CONTAINER_ID + "\n"),
            _container_inspect(store, read_write=True),
            _container_inspect(store, read_write=True),
            CommandResult(returncode=0, stdout=_CONTAINER_ID + "\n"),
        ]
    )

    with pytest.raises(ValueError, match="not_read_only"):
        DockerOllamaStagedPeerSupervisor(runner).launch_staged(
            profile=profile,
            staged_store=store,
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert runner.calls[-1] == ("docker", "rm", "--force", "model-peer")
    assert not any(call[:2] == ("docker", "exec") for call in runner.calls)


def test_store_identity_drift_is_rejected_before_docker_calls(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    changed = PreparedOllamaModelStore(
        models_path=store.models_path,
        identity=store.identity.model_copy(update={"model_id": "other-model"}),
    )
    runner = FakeRunner([])

    with pytest.raises(ValueError, match="does not bind"):
        DockerOllamaStagedPeerSupervisor(runner).launch_staged(
            profile=profile,
            staged_store=changed,
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert runner.calls == []
