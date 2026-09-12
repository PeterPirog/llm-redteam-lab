"""Deterministic Docker isolation contract and independent inspection verifier.

This module does not execute Docker. It builds an offline launch contract and verifies
trusted `docker inspect` evidence before issuing an `AgentSandboxAttestation`. The first
profile is deliberately strict: no container network, one disposable read-write workspace
bind, read-only root filesystem, no added Linux capabilities and bounded resources.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_IMAGE_REF_PATTERN = r"^.+@sha256:[0-9a-f]{64}$"
_IMAGE_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_CONTAINER_WORKSPACE = "/workspace"


class DockerSandboxProfile(StrictModel):
    """Stable security-relevant Docker policy for an offline coding-agent container."""

    version: int = Field(ge=1, default=1)
    image_ref: str = Field(pattern=_IMAGE_REF_PATTERN)
    image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    container_workspace: str = Field(default=_CONTAINER_WORKSPACE, min_length=1)
    memory_limit_bytes: int = Field(ge=64 * 1024 * 1024)
    pids_limit: int = Field(ge=16)
    cpus: float = Field(gt=0.0)

    @model_validator(mode="after")
    def container_paths_are_absolute(self) -> DockerSandboxProfile:
        workspace = PurePosixPath(self.container_workspace)
        if not workspace.is_absolute() or str(workspace) == "/":
            raise ValueError("container_workspace must be an absolute non-root POSIX path")
        return self

    @property
    def image_manifest_digest(self) -> str:
        return self.image_ref.rsplit("@sha256:", 1)[1]

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def docker_run_command(
        self,
        *,
        container_name: str,
        workspace_host_path: str,
        command: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Build a fail-closed Docker CLI launch command without executing it."""

        if not container_name or any(character.isspace() for character in container_name):
            raise ValueError("container_name must be non-empty and contain no whitespace")
        _normalize_host_path(workspace_host_path)
        if not command:
            raise ValueError("container command must be non-empty")
        return (
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            str(self.memory_limit_bytes),
            "--cpus",
            str(self.cpus),
            "--mount",
            (
                f"type=bind,src={workspace_host_path},"
                f"dst={self.container_workspace},rw"
            ),
            "--workdir",
            self.container_workspace,
            self.image_ref,
            *command,
        )


class DockerMountInspection(StrictModel):
    """Normalized mount evidence derived from Docker inspect."""

    mount_type: str = Field(min_length=1)
    source_sha256: str = Field(pattern=_HASH_PATTERN)
    destination: str = Field(min_length=1)
    read_write: bool


class DockerContainerInspection(StrictModel):
    """Security-relevant normalized subset of a Docker inspect record."""

    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    running: bool
    auto_remove: bool
    privileged: bool
    readonly_rootfs: bool
    network_mode: str = Field(min_length=1)
    cap_add: tuple[str, ...] = ()
    cap_drop: tuple[str, ...] = ()
    security_opt: tuple[str, ...] = ()
    pids_limit: int
    memory_limit_bytes: int
    nano_cpus: int
    mounts: tuple[DockerMountInspection, ...] = ()

    @classmethod
    def from_docker_inspect(cls, payload: dict[str, Any]) -> DockerContainerInspection:
        """Normalize one real Docker inspect object without retaining host paths."""

        container_id = _required_str(payload, "Id")
        image_id = _required_str(payload, "Image")
        state = _required_dict(payload, "State")
        host_config = _required_dict(payload, "HostConfig")
        mounts_raw = payload.get("Mounts")
        if not isinstance(mounts_raw, list):
            raise ValueError("Docker inspect Mounts must be a list")

        mounts: list[DockerMountInspection] = []
        for raw in mounts_raw:
            if not isinstance(raw, dict):
                raise ValueError("Docker inspect mount entry must be an object")
            source = _normalize_host_path(_required_str(raw, "Source"))
            mounts.append(
                DockerMountInspection(
                    mount_type=_required_str(raw, "Type"),
                    source_sha256=sha256(source.encode()).hexdigest(),
                    destination=_required_str(raw, "Destination"),
                    read_write=_required_bool(raw, "RW"),
                )
            )

        cap_add = _string_tuple(host_config.get("CapAdd"))
        cap_drop = _string_tuple(host_config.get("CapDrop"))
        security_opt = _string_tuple(host_config.get("SecurityOpt"))
        return cls(
            container_id_sha256=sha256(container_id.encode()).hexdigest(),
            image_id=image_id,
            running=_required_bool(state, "Running"),
            auto_remove=_required_bool(host_config, "AutoRemove"),
            privileged=_required_bool(host_config, "Privileged"),
            readonly_rootfs=_required_bool(host_config, "ReadonlyRootfs"),
            network_mode=_required_str(host_config, "NetworkMode"),
            cap_add=tuple(sorted(cap_add)),
            cap_drop=tuple(sorted(cap_drop)),
            security_opt=tuple(sorted(security_opt)),
            pids_limit=_required_int(host_config, "PidsLimit"),
            memory_limit_bytes=_required_int(host_config, "Memory"),
            nano_cpus=_required_int(host_config, "NanoCpus"),
            mounts=tuple(sorted(mounts, key=lambda item: item.destination)),
        )

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def attest_offline_docker_sandbox(
    *,
    docker_profile: DockerSandboxProfile,
    runtime_profile: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
    inspection: DockerContainerInspection,
    workspace_host_path: str,
    issuer: str = "llm-redteam-docker-inspect-v1",
) -> AgentSandboxAttestation:
    """Verify Docker evidence and issue a hash-only sandbox attestation."""

    if sandbox_policy.enforcement_kind != SandboxEnforcementKind.DOCKER:
        raise ValueError("Docker attestation requires enforcement_kind=docker")
    if not sandbox_policy.disposable_workspace:
        raise ValueError("Docker attestation requires disposable_workspace")
    if not sandbox_policy.external_network_denied:
        raise ValueError("Docker attestation requires external_network_denied")
    if sandbox_policy.allowed_network_endpoints:
        raise ValueError("offline Docker profile cannot allow network endpoints")
    if not sandbox_policy.git_publication_denied:
        raise ValueError("Docker attestation requires git_publication_denied")

    failures: list[str] = []
    if inspection.image_id != docker_profile.image_id:
        failures.append("image_id")
    if not inspection.running:
        failures.append("running")
    if not inspection.auto_remove:
        failures.append("auto_remove")
    if inspection.privileged:
        failures.append("privileged")
    if not inspection.readonly_rootfs:
        failures.append("readonly_rootfs")
    if inspection.network_mode != "none":
        failures.append("network_mode")
    if inspection.cap_add:
        failures.append("cap_add")
    if "ALL" not in {cap.upper() for cap in inspection.cap_drop}:
        failures.append("cap_drop_all")
    if not any(
        option.casefold() == "no-new-privileges:true" for option in inspection.security_opt
    ):
        failures.append("no_new_privileges")
    if inspection.pids_limit <= 0 or inspection.pids_limit > docker_profile.pids_limit:
        failures.append("pids_limit")
    if (
        inspection.memory_limit_bytes <= 0
        or inspection.memory_limit_bytes > docker_profile.memory_limit_bytes
    ):
        failures.append("memory_limit")
    requested_nano_cpus = int(docker_profile.cpus * 1_000_000_000)
    if inspection.nano_cpus <= 0 or inspection.nano_cpus > requested_nano_cpus:
        failures.append("cpu_limit")

    expected_source = sha256(_normalize_host_path(workspace_host_path).encode()).hexdigest()
    if len(inspection.mounts) != 1:
        failures.append("mount_count")
    else:
        mount = inspection.mounts[0]
        if mount.mount_type != "bind":
            failures.append("workspace_mount_type")
        if mount.source_sha256 != expected_source:
            failures.append("workspace_mount_source")
        if mount.destination != docker_profile.container_workspace:
            failures.append("workspace_mount_destination")
        if not mount.read_write:
            failures.append("workspace_mount_rw")

    if failures:
        raise ValueError("Docker sandbox inspection failed closed: " + ", ".join(failures))

    return AgentSandboxAttestation(
        issuer=issuer,
        isolation_id=f"docker:{inspection.container_id_sha256}",
        runtime_profile_sha256=runtime_profile.profile_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        workspace_root_sha256=runtime_profile.workspace_root_sha256,
        proof_sha256=inspection.proof_sha256,
    )


def _normalize_host_path(value: str) -> str:
    raw = value.strip()
    if not raw or "\x00" in raw:
        raise ValueError("host path must be non-empty and contain no NUL")
    windows = (
        (len(raw) >= 2 and raw[1] == ":")
        or raw.startswith("\\\\")
        or raw.startswith("//")
        or "\\" in raw
    )
    path = PureWindowsPath(raw) if windows else PurePosixPath(raw)
    if not path.is_absolute():
        raise ValueError("host path must be absolute")
    normalized = str(path).replace("\\", "/")
    return normalized.casefold() if windows else normalized


def _required_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Docker inspect {key} must be an object")
    return value


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Docker inspect {key} must be a non-empty string")
    return value


def _required_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Docker inspect {key} must be a boolean")
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Docker inspect {key} must be an integer")
    return value


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Docker inspect capability/security option field must be a string list")
    return tuple(value)
