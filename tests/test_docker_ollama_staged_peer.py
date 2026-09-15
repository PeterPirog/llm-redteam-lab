from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_ollama_staged_peer import (
    DockerOllamaStagedPeerProfile,
    attest_staged_ollama_peer,
)
from llm_redteam.ollama_model_staging import (
    OllamaStagedModelStoreIdentity,
    PreparedOllamaModelStore,
)

_IMAGE_ID = "sha256:" + "a" * 64
_IMAGE_REF = "synthetic/ollama@sha256:" + "b" * 64
_CONTAINER_ID = "c" * 64
_NETWORK_ID = "d" * 64
_NETWORK_NAME = "rt-model-net"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _store(tmp_path: Path, *, model_id: str = "qwen-local") -> PreparedOllamaModelStore:
    models = tmp_path / "stage" / "models"
    models.mkdir(parents=True, exist_ok=True)
    identity = OllamaStagedModelStoreIdentity(
        model_id=model_id,
        manifest_digest="sha256:" + "e" * 64,
        manifest_relative_path_sha256="1" * 64,
        staged_tree_sha256="2" * 64,
        referenced_blob_count=2,
        referenced_blob_bytes=1024,
    )
    return PreparedOllamaModelStore(models_path=models, identity=identity)


def _profile(store: PreparedOllamaModelStore, *, gpu_access: bool = False):
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
        gpu_access=gpu_access,
        staged_store_identity_sha256=store.identity.identity_sha256,
        container_models_path="/models",
    )


def _payload(
    store: PreparedOllamaModelStore,
    *,
    read_write: bool = False,
    extra_mount: bool = False,
    environment: list[str] | None = None,
    port_bindings: object = None,
    gpu: bool = False,
) -> dict[str, object]:
    mounts: list[dict[str, object]] = [
        {
            "Type": "bind",
            "Source": str(store.models_path),
            "Destination": "/models",
            "RW": read_write,
        }
    ]
    if extra_mount:
        mounts.append(
            {
                "Type": "bind",
                "Source": str(store.models_path.parent),
                "Destination": "/extra",
                "RW": False,
            }
        )
    device_requests = (
        [{"Count": -1, "Capabilities": [["gpu"]]}] if gpu else []
    )
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
            "PortBindings": port_bindings,
            "DeviceRequests": device_requests,
        },
        "Config": {
            "Env": environment or ["OLLAMA_MODELS=/models", "PATH=/usr/bin"],
        },
        "Mounts": mounts,
        "NetworkSettings": {
            "Networks": {_NETWORK_NAME: {"NetworkID": _NETWORK_ID}}
        },
    }


def test_launch_adds_only_exact_read_only_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)

    command = profile.docker_run_command_with_store(
        network_profile=_network(),
        network_name=_NETWORK_NAME,
        staged_store=store,
    )

    assert "--publish" not in command
    assert "-p" not in command
    assert "OLLAMA_MODELS=/models" in command
    mount_value = command[command.index("--mount") + 1]
    assert f"src={store.models_path}" in mount_value
    assert "dst=/models" in mount_value
    assert mount_value.endswith(",readonly")
    assert command.index("--mount") < command.index(_IMAGE_REF)


def test_attestation_accepts_exact_staged_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)

    proof = attest_staged_ollama_peer(
        profile=profile,
        staged_store=store,
        payload=_payload(store),
        expected_network_name=_NETWORK_NAME,
    )

    assert proof.peer_profile_sha256 == profile.profile_sha256
    assert proof.staged_store_identity_sha256 == store.identity.identity_sha256
    assert proof.container_id_sha256 == _digest(_CONTAINER_ID)
    assert len(proof.proof_sha256) == 64


def test_attestation_rejects_mount_and_environment_drift(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)

    for payload, marker in (
        (_payload(store, read_write=True), "not_read_only"),
        (_payload(store, extra_mount=True), "mount_count"),
        (_payload(store, environment=["PATH=/usr/bin"]), "ollama_models_environment"),
        (
            _payload(
                store,
                environment=["OLLAMA_MODELS=/models", "OLLAMA_MODELS=/other"],
            ),
            "ollama_models_environment",
        ),
    ):
        with pytest.raises(ValueError, match=marker):
            attest_staged_ollama_peer(
                profile=profile,
                staged_store=store,
                payload=payload,
                expected_network_name=_NETWORK_NAME,
            )


def test_attestation_rejects_host_port_and_unexpected_gpu(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)

    with pytest.raises(ValueError, match="published_ports"):
        attest_staged_ollama_peer(
            profile=profile,
            staged_store=store,
            payload=_payload(store, port_bindings={"11434/tcp": [{"HostPort": "11434"}]}),
            expected_network_name=_NETWORK_NAME,
        )
    with pytest.raises(ValueError, match="unexpected_device_request"):
        attest_staged_ollama_peer(
            profile=profile,
            staged_store=store,
            payload=_payload(store, gpu=True),
            expected_network_name=_NETWORK_NAME,
        )


def test_gpu_profile_requires_one_gpu_request(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store, gpu_access=True)

    with pytest.raises(ValueError, match="gpu_device_request"):
        attest_staged_ollama_peer(
            profile=profile,
            staged_store=store,
            payload=_payload(store),
            expected_network_name=_NETWORK_NAME,
        )

    proof = attest_staged_ollama_peer(
        profile=profile,
        staged_store=store,
        payload=_payload(store, gpu=True),
        expected_network_name=_NETWORK_NAME,
    )
    assert len(proof.proof_sha256) == 64


def test_profile_rejects_store_identity_and_model_drift(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    other = _store(tmp_path / "other", model_id="other-model")

    with pytest.raises(ValueError, match="does not match"):
        profile.docker_run_command_with_store(
            network_profile=_network(),
            network_name=_NETWORK_NAME,
            staged_store=other,
        )
