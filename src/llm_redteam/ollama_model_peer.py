"""Bind one verified Ollama artifact bundle to a hardened Docker model peer.

This module is an Ollama-specific edge adapter. Core Docker model-peer policy remains
provider-independent. The adapter composes the stable peer policy with one exact model
artifact and one verified minimal Ollama bundle, then builds a launch contract that mounts
only that bundle read-only and points ``OLLAMA_MODELS`` at the container-visible mount.

The bundle's host path is per-run control-plane state and is intentionally excluded from
stable Blue identity. The exact path used for launch is hashed into per-run attestation.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_peer import DockerModelPeerProfile
from .domain import StrictModel
from .model_artifact import ModelPeerArtifactBinding
from .ollama_artifact_bundle import (
    OllamaArtifactBundleContract,
    OllamaArtifactBundleVerification,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OllamaModelPeerProfile(StrictModel):
    """Stable composition of peer policy and one exact verified Ollama artifact."""

    version: int = Field(ge=1, default=1)
    provider_id: str = Field(default="ollama")
    model_id: str = Field(min_length=1, max_length=256)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_contract_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_verification_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    models_mount_path: str = Field(default="/models", min_length=1, max_length=256)
    models_env_name: str = Field(default="OLLAMA_MODELS", min_length=1, max_length=64)

    @model_validator(mode="after")
    def stable_paths_are_safe(self) -> OllamaModelPeerProfile:
        path = PurePosixPath(self.models_mount_path)
        if not path.is_absolute() or ".." in path.parts or "\x00" in self.models_mount_path:
            raise ValueError("Ollama models mount path must be an absolute safe POSIX path")
        if not _identifier_like(self.models_env_name):
            raise ValueError("Ollama models environment name must be identifier-like")
        return self

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def docker_run_command(
        self,
        *,
        peer: DockerModelPeerProfile,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_name: str,
        bundle_host_path: Path,
    ) -> tuple[str, ...]:
        """Build the exact detached Ollama peer launch for one staged bundle."""

        _require_peer_binding(self, peer)
        if not network_name or any(character.isspace() for character in network_name):
            raise ValueError("network_name must be non-empty and contain no whitespace")
        source = str(bundle_host_path.absolute())
        if not source or "\x00" in source or "," in source:
            raise ValueError("bundle host path is unsafe for Docker --mount syntax")
        mount = (
            f"type=bind,source={source},target={self.models_mount_path},readonly"
        )
        gpu_args = ("--gpus", "all") if peer.gpu_access else ()
        return (
            "docker",
            "run",
            "--rm",
            "--detach",
            "--pull",
            "never",
            "--name",
            network_profile.model_endpoint_host,
            "--network",
            network_name,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(peer.pids_limit),
            "--memory",
            str(peer.memory_limit_bytes),
            "--cpus",
            str(peer.cpus),
            *gpu_args,
            "--mount",
            mount,
            "--env",
            f"{self.models_env_name}={self.models_mount_path}",
            peer.image_ref,
            *peer.command,
        )


class OllamaModelPeerAttestation(StrictModel):
    """Hash-only proof that a launched peer matches the Ollama bundle contract."""

    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_contract_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_verification_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_host_path_sha256: str = Field(pattern=_HASH_PATTERN)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    network_name_sha256: str = Field(pattern=_HASH_PATTERN)
    inspection_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def compose_ollama_model_peer_profile(
    *,
    peer: DockerModelPeerProfile,
    artifact_binding: ModelPeerArtifactBinding,
    bundle_contract: OllamaArtifactBundleContract,
    bundle_verification: OllamaArtifactBundleVerification,
) -> OllamaModelPeerProfile:
    """Compose exact artifact and bundle proofs without changing generic peer identity."""

    if peer.provider_id != "ollama":
        raise ValueError("Ollama model-peer profile requires provider_id=ollama")
    if artifact_binding.peer_profile_sha256 != peer.profile_sha256:
        raise ValueError("artifact binding does not bind the supplied model-peer profile")
    if artifact_binding.provider_id != peer.provider_id:
        raise ValueError("artifact binding provider does not match model-peer provider")
    if artifact_binding.model_id != peer.model_id:
        raise ValueError("artifact binding model does not match model-peer model")
    if bundle_contract.provider_id != peer.provider_id:
        raise ValueError("Ollama bundle provider does not match model-peer provider")
    if bundle_contract.model_id != peer.model_id:
        raise ValueError("Ollama bundle model does not match model-peer model")
    if bundle_contract.artifact_identity_sha256 != artifact_binding.artifact_identity_sha256:
        raise ValueError("Ollama bundle does not bind the selected model artifact")
    if bundle_verification.contract_sha256 != bundle_contract.bundle_sha256:
        raise ValueError("Ollama bundle verification does not bind the bundle contract")
    if bundle_verification.manifest_sha256 != bundle_contract.manifest_digest.removeprefix(
        "sha256:"
    ):
        raise ValueError("Ollama bundle verification manifest digest does not match contract")

    return OllamaModelPeerProfile(
        model_id=peer.model_id,
        peer_profile_sha256=peer.profile_sha256,
        artifact_binding_sha256=artifact_binding.binding_sha256,
        artifact_identity_sha256=artifact_binding.artifact_identity_sha256,
        bundle_contract_sha256=bundle_contract.bundle_sha256,
        bundle_verification_proof_sha256=bundle_verification.proof_sha256,
    )


def attest_ollama_model_peer_inspection(
    *,
    profile: OllamaModelPeerProfile,
    peer: DockerModelPeerProfile,
    payload: dict[str, Any],
    bundle_host_path: Path,
    expected_network_name: str,
) -> OllamaModelPeerAttestation:
    """Fail closed unless Docker inspection proves the exact restricted Ollama peer."""

    _require_peer_binding(profile, peer)
    failures: list[str] = []
    container_id = payload.get("Id")
    if not isinstance(container_id, str) or not container_id:
        failures.append("container_id")
        container_id = "invalid"
    if payload.get("Image") != peer.image_id:
        failures.append("image_id")

    state = payload.get("State")
    if not isinstance(state, dict) or state.get("Running") is not True:
        failures.append("running")

    host = payload.get("HostConfig")
    if not isinstance(host, dict):
        failures.append("host_config")
    else:
        if host.get("AutoRemove") is not True:
            failures.append("auto_remove")
        if host.get("Privileged") is True:
            failures.append("privileged")
        if host.get("ReadonlyRootfs") is not True:
            failures.append("readonly_rootfs")
        if host.get("NetworkMode") != expected_network_name:
            failures.append("network_mode")
        if host.get("CapAdd") not in (None, []):
            failures.append("cap_add")
        cap_drop = {str(value).upper() for value in (host.get("CapDrop") or [])}
        if "ALL" not in cap_drop:
            failures.append("cap_drop_all")
        security_opt = {
            str(value).casefold() for value in (host.get("SecurityOpt") or [])
        }
        if "no-new-privileges:true" not in security_opt:
            failures.append("no_new_privileges")
        if host.get("PidsLimit") != peer.pids_limit:
            failures.append("pids_limit")
        if host.get("Memory") != peer.memory_limit_bytes:
            failures.append("memory_limit")
        if host.get("NanoCpus") != int(peer.cpus * 1_000_000_000):
            failures.append("cpu_limit")
        if host.get("PortBindings") not in (None, {}):
            failures.append("published_ports")
        device_requests = host.get("DeviceRequests") or []
        if peer.gpu_access:
            if len(device_requests) != 1 or not _gpu_request(device_requests[0]):
                failures.append("gpu_device_request")
        elif device_requests:
            failures.append("unexpected_device_request")

    networks = payload.get("NetworkSettings")
    network_map = networks.get("Networks") if isinstance(networks, dict) else None
    if not isinstance(network_map, dict) or set(network_map) != {expected_network_name}:
        failures.append("network_membership")

    mounts = payload.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        failures.append("model_bundle_mount_count")
    else:
        mount = mounts[0]
        if not isinstance(mount, dict):
            failures.append("model_bundle_mount_shape")
        else:
            if mount.get("Type") != "bind":
                failures.append("model_bundle_mount_type")
            if mount.get("Destination") != profile.models_mount_path:
                failures.append("model_bundle_mount_destination")
            if mount.get("RW") is not False:
                failures.append("model_bundle_mount_readonly")

    config = payload.get("Config")
    env = config.get("Env") if isinstance(config, dict) else None
    expected_env = f"{profile.models_env_name}={profile.models_mount_path}"
    if not isinstance(env, list) or expected_env not in env:
        failures.append("ollama_models_environment")

    if failures:
        raise ValueError(
            "Docker Ollama model-peer inspection failed closed: "
            + ", ".join(sorted(set(failures)))
        )

    source_hash = sha256(str(bundle_host_path.absolute()).encode()).hexdigest()
    return OllamaModelPeerAttestation(
        profile_sha256=profile.profile_sha256,
        peer_profile_sha256=peer.profile_sha256,
        artifact_binding_sha256=profile.artifact_binding_sha256,
        bundle_contract_sha256=profile.bundle_contract_sha256,
        bundle_verification_proof_sha256=profile.bundle_verification_proof_sha256,
        bundle_host_path_sha256=source_hash,
        container_id_sha256=sha256(container_id.encode()).hexdigest(),
        network_name_sha256=sha256(expected_network_name.encode()).hexdigest(),
        inspection_sha256=canonical_json_hash(payload),
    )


def _require_peer_binding(
    profile: OllamaModelPeerProfile,
    peer: DockerModelPeerProfile,
) -> None:
    if peer.provider_id != "ollama":
        raise ValueError("Ollama model-peer adapter requires provider_id=ollama")
    if peer.model_id != profile.model_id:
        raise ValueError("Ollama model-peer model ID does not match composed profile")
    if peer.profile_sha256 != profile.peer_profile_sha256:
        raise ValueError("Ollama model-peer base policy does not match composed profile")


def _identifier_like(value: str) -> bool:
    return bool(value) and (value[0].isalpha() or value[0] == "_") and all(
        character.isalnum() or character == "_" for character in value
    )


def _gpu_request(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    capabilities = value.get("Capabilities")
    if not isinstance(capabilities, list):
        return False
    flattened = {
        str(capability).casefold()
        for group in capabilities
        if isinstance(group, list)
        for capability in group
    }
    return "gpu" in flattened
