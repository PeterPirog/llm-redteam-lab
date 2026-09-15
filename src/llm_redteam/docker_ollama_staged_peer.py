"""Ollama model-peer policy with one exact read-only staged model store.

The generic model-peer profile intentionally exposes no host mounts. This specialization
permits exactly one laboratory-owned, content-addressed Ollama store and binds both the
launch command and post-launch attestation to its stable stage identity.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_peer import DockerModelPeerProfile
from .docker_sandbox import DockerContainerInspection, _normalize_host_path
from .domain import StrictModel
from .ollama_model_staging import PreparedOllamaModelStore

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerOllamaStagedPeerProfile(DockerModelPeerProfile):
    """Stable Ollama peer policy bound to one exact staged-store identity."""

    staged_store_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    container_models_path: str = Field(default="/models", min_length=1)

    @model_validator(mode="after")
    def staged_peer_contract_is_valid(self) -> DockerOllamaStagedPeerProfile:
        if self.provider_id != "ollama":
            raise ValueError("staged Ollama peer requires provider_id=ollama")
        path = PurePosixPath(self.container_models_path)
        if not path.is_absolute() or str(path) == "/":
            raise ValueError(
                "container_models_path must be an absolute non-root POSIX path"
            )
        if ".." in path.parts:
            raise ValueError("container_models_path cannot contain parent traversal")
        return self

    def docker_run_command_with_store(
        self,
        *,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_name: str,
        staged_store: PreparedOllamaModelStore,
    ) -> tuple[str, ...]:
        """Build the hardened peer launch with exactly one read-only model-store bind."""

        _require_matching_store(self, staged_store)
        host_path = _normalize_host_path(str(staged_store.models_path))
        if "," in host_path:
            raise ValueError("staged Ollama store path cannot contain comma")

        base = super().docker_run_command(
            network_profile=network_profile,
            network_name=network_name,
        )
        try:
            image_index = base.index(self.image_ref)
        except ValueError as exc:  # pragma: no cover - inherited invariant
            raise RuntimeError("Docker model-peer command lost its image reference") from exc

        mount = (
            f"type=bind,src={host_path},dst={self.container_models_path},readonly"
        )
        additions = (
            "--env",
            f"OLLAMA_MODELS={self.container_models_path}",
            "--mount",
            mount,
        )
        return (*base[:image_index], *additions, *base[image_index:])


class DockerOllamaStagedPeerAttestation(StrictModel):
    """Hash-safe proof of the one-store mount exception and peer confinement."""

    version: int = Field(ge=1, default=1)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    staged_store_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    mount_source_sha256: str = Field(pattern=_HASH_PATTERN)
    inspection_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def attest_staged_ollama_peer(
    *,
    profile: DockerOllamaStagedPeerProfile,
    staged_store: PreparedOllamaModelStore,
    payload: dict[str, Any],
    expected_network_name: str,
) -> DockerOllamaStagedPeerAttestation:
    """Fail closed unless runtime evidence matches the exact staged-peer policy."""

    _require_matching_store(profile, staged_store)
    inspection = DockerContainerInspection.from_docker_inspect(payload)
    failures: list[str] = []

    if inspection.image_id != profile.image_id:
        failures.append("image_id")
    if not inspection.running:
        failures.append("running")
    if not inspection.auto_remove:
        failures.append("auto_remove")
    if inspection.privileged:
        failures.append("privileged")
    if not inspection.readonly_rootfs:
        failures.append("readonly_rootfs")
    if inspection.network_mode != expected_network_name:
        failures.append("network_mode")
    if inspection.cap_add:
        failures.append("cap_add")
    if "ALL" not in {value.upper() for value in inspection.cap_drop}:
        failures.append("cap_drop_all")
    if "no-new-privileges:true" not in {
        value.casefold() for value in inspection.security_opt
    }:
        failures.append("no_new_privileges")
    if inspection.pids_limit <= 0 or inspection.pids_limit > profile.pids_limit:
        failures.append("pids_limit")
    if (
        inspection.memory_limit_bytes <= 0
        or inspection.memory_limit_bytes > profile.memory_limit_bytes
    ):
        failures.append("memory_limit")
    requested_nano_cpus = int(profile.cpus * 1_000_000_000)
    if inspection.nano_cpus <= 0 or inspection.nano_cpus > requested_nano_cpus:
        failures.append("cpu_limit")

    normalized_store = _normalize_host_path(str(staged_store.models_path))
    expected_source = sha256(normalized_store.encode()).hexdigest()
    if len(inspection.mounts) != 1:
        failures.append("mount_count")
    else:
        mount = inspection.mounts[0]
        if mount.mount_type != "bind":
            failures.append("model_store_mount_type")
        if mount.source_sha256 != expected_source:
            failures.append("model_store_mount_source")
        if mount.destination != profile.container_models_path:
            failures.append("model_store_mount_destination")
        if mount.read_write:
            failures.append("model_store_mount_not_read_only")

    host = payload.get("HostConfig")
    if not isinstance(host, dict):
        failures.append("host_config")
    else:
        if host.get("PortBindings") not in (None, {}):
            failures.append("published_ports")
        device_requests = host.get("DeviceRequests") or []
        if profile.gpu_access:
            if len(device_requests) != 1 or not _is_gpu_device_request(
                device_requests[0]
            ):
                failures.append("gpu_device_request")
        elif device_requests:
            failures.append("unexpected_device_request")

    network_settings = payload.get("NetworkSettings")
    networks = (
        network_settings.get("Networks")
        if isinstance(network_settings, dict)
        else None
    )
    if not isinstance(networks, dict) or set(networks) != {expected_network_name}:
        failures.append("network_membership")

    config = payload.get("Config")
    environment = config.get("Env") if isinstance(config, dict) else None
    if not isinstance(environment, list) or not all(
        isinstance(value, str) for value in environment
    ):
        failures.append("environment")
    else:
        expected_env = f"OLLAMA_MODELS={profile.container_models_path}"
        ollama_models_entries = [
            value for value in environment if value.startswith("OLLAMA_MODELS=")
        ]
        if ollama_models_entries != [expected_env]:
            failures.append("ollama_models_environment")

    if failures:
        raise ValueError(
            "staged Ollama model-peer inspection failed closed: "
            + ", ".join(sorted(set(failures)))
        )

    return DockerOllamaStagedPeerAttestation(
        peer_profile_sha256=profile.profile_sha256,
        staged_store_identity_sha256=staged_store.identity.identity_sha256,
        container_id_sha256=inspection.container_id_sha256,
        mount_source_sha256=expected_source,
        inspection_sha256=inspection.proof_sha256,
    )


def _require_matching_store(
    profile: DockerOllamaStagedPeerProfile,
    staged_store: PreparedOllamaModelStore,
) -> None:
    if staged_store.identity.identity_sha256 != profile.staged_store_identity_sha256:
        raise ValueError("staged Ollama store does not match model-peer profile")
    if staged_store.identity.model_id != profile.model_id:
        raise ValueError("staged Ollama store model does not match model-peer profile")


def _is_gpu_device_request(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    capabilities = value.get("Capabilities")
    if not isinstance(capabilities, list):
        return False
    flattened = {
        str(item).casefold()
        for group in capabilities
        if isinstance(group, list)
        for item in group
    }
    return "gpu" in flattened and value.get("Count") == -1
