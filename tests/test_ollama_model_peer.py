from pathlib import Path

import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_peer import DockerModelPeerProfile
from llm_redteam.model_artifact import ModelPeerArtifactBinding
from llm_redteam.ollama_artifact_bundle import (
    OllamaArtifactBundleContract,
    OllamaArtifactBundleVerification,
    OllamaBundleBlob,
)
from llm_redteam.ollama_model_peer import (
    attest_ollama_model_peer_inspection,
    compose_ollama_model_peer_profile,
)

_IMAGE_REF = "ollama/ollama@sha256:" + "1" * 64
_IMAGE_ID = "sha256:" + "2" * 64
_MANIFEST_HEX = "3" * 64
_ARTIFACT_IDENTITY = "4" * 64
_NETWORK = "rt-model-net"
_CONTAINER_ID = "5" * 64


def _peer(*, provider_id: str = "ollama", gpu_access: bool = True) -> DockerModelPeerProfile:
    return DockerModelPeerProfile(
        provider_id=provider_id,
        model_id="qwen-test:latest",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("ollama", "serve"),
        readiness_command=("ollama", "list", "-f", "json"),
        memory_limit_bytes=8 * 1024 * 1024 * 1024,
        pids_limit=256,
        cpus=4.0,
        gpu_access=gpu_access,
    )


def _binding(peer: DockerModelPeerProfile) -> ModelPeerArtifactBinding:
    return ModelPeerArtifactBinding(
        peer_profile_sha256=peer.profile_sha256,
        provider_id=peer.provider_id,
        model_id=peer.model_id,
        artifact_identity_sha256=_ARTIFACT_IDENTITY,
    )


def _bundle(peer: DockerModelPeerProfile) -> OllamaArtifactBundleContract:
    return OllamaArtifactBundleContract(
        model_id=peer.model_id,
        artifact_identity_sha256=_ARTIFACT_IDENTITY,
        artifact_size_bytes=42,
        manifest_digest="sha256:" + _MANIFEST_HEX,
        manifest_relative_path="registry.ollama.ai/library/qwen-test/latest",
        blobs=(
            OllamaBundleBlob(
                digest="sha256:" + "6" * 64,
                size_bytes=42,
                media_types=("application/vnd.ollama.image.model",),
            ),
        ),
    )


def _verification(bundle: OllamaArtifactBundleContract) -> OllamaArtifactBundleVerification:
    return OllamaArtifactBundleVerification(
        contract_sha256=bundle.bundle_sha256,
        manifest_sha256=_MANIFEST_HEX,
        blob_inventory_sha256="7" * 64,
        blob_count=1,
        total_blob_bytes=42,
    )


def _profile():
    peer = _peer()
    bundle = _bundle(peer)
    return (
        peer,
        bundle,
        compose_ollama_model_peer_profile(
            peer=peer,
            artifact_binding=_binding(peer),
            bundle_contract=bundle,
            bundle_verification=_verification(bundle),
        ),
    )


def _inspection(
    peer: DockerModelPeerProfile,
    *,
    rw: bool = False,
    networks: tuple[str, ...] = (_NETWORK,),
    mounts: int = 1,
) -> dict[str, object]:
    mount_entries = [
        {
            "Type": "bind",
            "Source": "/run/desktop/mnt/host/c/synthetic/bundle",
            "Destination": "/models",
            "RW": rw,
        }
    ]
    if mounts == 2:
        mount_entries.append(
            {
                "Type": "bind",
                "Source": "/tmp/unexpected",
                "Destination": "/extra",
                "RW": False,
            }
        )
    device_requests = (
        [{"Capabilities": [["gpu"]]}] if peer.gpu_access else []
    )
    return {
        "Id": _CONTAINER_ID,
        "Image": _IMAGE_ID,
        "State": {"Running": True},
        "HostConfig": {
            "AutoRemove": True,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": _NETWORK,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": peer.pids_limit,
            "Memory": peer.memory_limit_bytes,
            "NanoCpus": int(peer.cpus * 1_000_000_000),
            "PortBindings": {},
            "DeviceRequests": device_requests,
        },
        "NetworkSettings": {"Networks": {name: {} for name in networks}},
        "Mounts": mount_entries,
        "Config": {"Env": ["OLLAMA_MODELS=/models", "HOME=/root"]},
    }


def test_profile_composes_exact_peer_artifact_and_bundle_identity() -> None:
    peer, bundle, profile = _profile()

    assert profile.peer_profile_sha256 == peer.profile_sha256
    assert profile.artifact_binding_sha256 == _binding(peer).binding_sha256
    assert profile.artifact_identity_sha256 == _ARTIFACT_IDENTITY
    assert profile.bundle_contract_sha256 == bundle.bundle_sha256
    assert profile.profile_sha256


def test_launch_mounts_only_verified_bundle_read_only_and_sets_ollama_models() -> None:
    peer, _, profile = _profile()
    network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )
    bundle_path = Path("C:/synthetic/verified-bundle")

    command = profile.docker_run_command(
        peer=peer,
        network_profile=network,
        network_name=_NETWORK,
        bundle_host_path=bundle_path,
    )

    mount = command[command.index("--mount") + 1]
    assert "target=/models" in mount
    assert mount.endswith(",readonly")
    assert command[command.index("--env") + 1] == "OLLAMA_MODELS=/models"
    assert command[command.index("--network") + 1] == _NETWORK
    assert command[command.index("--gpus") + 1] == "all"
    assert "--publish" not in command
    assert "-p" not in command
    assert command.index("--mount") < command.index(peer.image_ref)


def test_stable_profile_excludes_per_run_bundle_host_path() -> None:
    peer, _, profile = _profile()
    network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )

    first = profile.docker_run_command(
        peer=peer,
        network_profile=network,
        network_name="run-a",
        bundle_host_path=Path("C:/temp/run-a/models"),
    )
    second = profile.docker_run_command(
        peer=peer,
        network_profile=network,
        network_name="run-b",
        bundle_host_path=Path("D:/temp/run-b/models"),
    )

    assert first != second
    assert profile.profile_sha256 == profile.model_copy().profile_sha256


def test_inspection_attests_hardening_single_readonly_mount_and_namespace_translation() -> None:
    peer, _, profile = _profile()
    requested = Path("C:/synthetic/verified-bundle")

    attestation = attest_ollama_model_peer_inspection(
        profile=profile,
        peer=peer,
        payload=_inspection(peer),
        bundle_host_path=requested,
        expected_network_name=_NETWORK,
    )

    assert attestation.profile_sha256 == profile.profile_sha256
    assert attestation.requested_bundle_host_path_sha256
    assert attestation.observed_mount_source_sha256
    assert (
        attestation.requested_bundle_host_path_sha256
        != attestation.observed_mount_source_sha256
    )
    assert attestation.proof_sha256


def test_inspection_rejects_writable_or_extra_model_mounts() -> None:
    peer, _, profile = _profile()

    with pytest.raises(ValueError, match="model_bundle_mount_readonly"):
        attest_ollama_model_peer_inspection(
            profile=profile,
            peer=peer,
            payload=_inspection(peer, rw=True),
            bundle_host_path=Path("C:/synthetic/bundle"),
            expected_network_name=_NETWORK,
        )

    with pytest.raises(ValueError, match="model_bundle_mount_count"):
        attest_ollama_model_peer_inspection(
            profile=profile,
            peer=peer,
            payload=_inspection(peer, mounts=2),
            bundle_host_path=Path("C:/synthetic/bundle"),
            expected_network_name=_NETWORK,
        )


def test_inspection_rejects_dual_homed_model_peer() -> None:
    peer, _, profile = _profile()

    with pytest.raises(ValueError, match="network_membership"):
        attest_ollama_model_peer_inspection(
            profile=profile,
            peer=peer,
            payload=_inspection(peer, networks=(_NETWORK, "bridge")),
            bundle_host_path=Path("C:/synthetic/bundle"),
            expected_network_name=_NETWORK,
        )


def test_composition_rejects_wrong_artifact_or_provider() -> None:
    peer = _peer()
    bundle = _bundle(peer)
    wrong_binding = _binding(peer).model_copy(
        update={"artifact_identity_sha256": "8" * 64}
    )

    with pytest.raises(ValueError, match="selected model artifact"):
        compose_ollama_model_peer_profile(
            peer=peer,
            artifact_binding=wrong_binding,
            bundle_contract=bundle,
            bundle_verification=_verification(bundle),
        )

    non_ollama = _peer(provider_id="other")
    with pytest.raises(ValueError, match="provider_id=ollama"):
        compose_ollama_model_peer_profile(
            peer=non_ollama,
            artifact_binding=_binding(non_ollama),
            bundle_contract=bundle,
            bundle_verification=_verification(bundle),
        )
