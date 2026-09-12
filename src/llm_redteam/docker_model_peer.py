"""Provider-independent Docker model-peer lifecycle for isolated AGENT campaigns.

The model peer is infrastructure, not a Judge and not a trusted source of security
verdicts.  This module owns a tightly constrained container lifecycle and records a
non-inference readiness observation before the peer can be used by an AGENT trial.

Provider-specific details are configuration: image, command and readiness command are
fingerprinted data rather than business-logic branches for Ollama or any other server.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_IMAGE_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_DIGEST_IMAGE_PATTERN = r"^.+@sha256:[0-9a-f]{64}$"


class DockerModelPeerProfile(StrictModel):
    """Stable provider-independent policy for one local model-service peer."""

    version: int = Field(ge=1, default=1)
    provider_id: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    image_ref: str = Field(pattern=_DIGEST_IMAGE_PATTERN)
    image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    command: tuple[str, ...] = Field(min_length=1)
    readiness_command: tuple[str, ...] = Field(min_length=1)
    readiness_required_json: dict[str, str | int | float | bool] = Field(
        default_factory=dict
    )
    memory_limit_bytes: int = Field(gt=0, default=16 * 1024 * 1024 * 1024)
    pids_limit: int = Field(gt=0, default=512)
    cpus: float = Field(gt=0.0, default=8.0)
    gpu_access: bool = False

    @model_validator(mode="after")
    def commands_are_argument_vectors(self) -> DockerModelPeerProfile:
        for command in (self.command, self.readiness_command):
            if any(not item or "\x00" in item for item in command):
                raise ValueError("model peer commands require non-empty NUL-free arguments")
        return self

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def docker_run_command(
        self,
        *,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_name: str,
    ) -> tuple[str, ...]:
        """Build a detached peer launch with no host ports, mounts or extra networks."""

        if not network_name or any(character.isspace() for character in network_name):
            raise ValueError("network_name must be non-empty and contain no whitespace")
        gpu_args = ("--gpus", "all") if self.gpu_access else ()
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
            str(self.pids_limit),
            "--memory",
            str(self.memory_limit_bytes),
            "--cpus",
            str(self.cpus),
            *gpu_args,
            self.image_ref,
            *self.command,
        )


class DockerModelPeerReadinessObservation(StrictModel):
    """Hash-safe non-inference readiness evidence from the exact owned peer."""

    provider_id: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    response_sha256: str = Field(pattern=_HASH_PATTERN)
    ready: bool

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerModelPeerLease(StrictModel):
    """Per-run exact ownership and readiness token for the model peer."""

    container_name: str = Field(min_length=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_command_sha256: str = Field(pattern=_HASH_PATTERN)
    readiness: DockerModelPeerReadinessObservation


class DockerModelPeerSupervisor:
    """Launch, attest readiness and release one model peer fail closed."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 30.0,
        readiness_timeout_seconds: float = 120.0,
        stop_timeout_seconds: int = 5,
    ) -> None:
        if command_timeout_seconds <= 0 or readiness_timeout_seconds <= 0:
            raise ValueError("Docker model-peer timeouts must be positive")
        if stop_timeout_seconds < 0:
            raise ValueError("stop_timeout_seconds cannot be negative")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds
        self._readiness_timeout_seconds = readiness_timeout_seconds
        self._stop_timeout_seconds = stop_timeout_seconds

    def launch(
        self,
        *,
        profile: DockerModelPeerProfile,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
    ) -> DockerModelPeerLease:
        """Launch only on the still-owned network, then prove confinement and readiness."""

        if network_lease.network_profile_sha256 != network_profile.profile_sha256:
            raise ValueError("model-network lease does not bind the requested profile")
        self._require_owned_network(network_lease)
        launch_command = profile.docker_run_command(
            network_profile=network_profile,
            network_name=network_lease.network_name,
        )
        result = self._runner.run(
            launch_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-peer launch failed")
        container_id = _parse_full_id(result.stdout, kind="model-peer container")
        name = network_profile.model_endpoint_host

        try:
            raw = self._inspect_container(name)
            inspected_id = _required_id(raw, kind="container")
            if inspected_id != container_id:
                raise RuntimeError("Docker model-peer ownership changed before attestation")
            _verify_model_peer_inspection(
                profile=profile,
                payload=raw,
                expected_network_name=network_lease.network_name,
            )
            self._require_owned_network(network_lease)
            readiness = self._probe_readiness(
                profile=profile,
                container_name=name,
                container_id=container_id,
            )
        except Exception:
            self._remove_if_owned(name, container_id)
            raise

        return DockerModelPeerLease(
            container_name=name,
            container_id_sha256=sha256(container_id.encode()).hexdigest(),
            profile_sha256=profile.profile_sha256,
            network_id_sha256=network_lease.network_id_sha256,
            launch_command_sha256=canonical_json_hash(list(launch_command)),
            readiness=readiness,
        )

    def release(self, lease: DockerModelPeerLease) -> None:
        """Remove only the model peer still owned by the supplied exact-ID lease."""

        self._require_owned_container(lease)
        stopped = self._runner.run(
            (
                "docker",
                "stop",
                "--time",
                str(self._stop_timeout_seconds),
                lease.container_name,
            ),
            timeout_seconds=self._command_timeout_seconds,
        )
        if stopped.returncode != 0:
            removed = self._runner.run(
                ("docker", "rm", "--force", lease.container_name),
                timeout_seconds=self._command_timeout_seconds,
            )
            if removed.returncode != 0:
                raise RuntimeError("Docker model-peer teardown failed")
        post = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if post.returncode != 0:
            return
        try:
            remaining = _parse_single_record(post.stdout)
            remaining_id = _required_id(remaining, kind="container")
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model-peer removal could not be verified") from exc
        if sha256(remaining_id.encode()).hexdigest() == lease.container_id_sha256:
            raise RuntimeError("Docker model peer still exists after teardown")
        raise RuntimeError("Docker model-peer name was reused during teardown")

    def _probe_readiness(
        self,
        *,
        profile: DockerModelPeerProfile,
        container_name: str,
        container_id: str,
    ) -> DockerModelPeerReadinessObservation:
        self._require_raw_container_id(container_name, container_id)
        result = self._runner.run(
            ("docker", "exec", container_name, *profile.readiness_command),
            timeout_seconds=self._readiness_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-peer readiness command failed")
        self._require_raw_container_id(container_name, container_id)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Docker model-peer readiness output is not JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Docker model-peer readiness output must be a JSON object")
        for key, expected in profile.readiness_required_json.items():
            if payload.get(key) != expected:
                raise RuntimeError(
                    f"Docker model-peer readiness requirement failed for key {key!r}"
                )
        return DockerModelPeerReadinessObservation(
            provider_id=profile.provider_id,
            model_id=profile.model_id,
            profile_sha256=profile.profile_sha256,
            container_id_sha256=sha256(container_id.encode()).hexdigest(),
            response_sha256=canonical_json_hash(payload),
            ready=True,
        )

    def _require_owned_network(self, lease: DockerModelNetworkLease) -> None:
        result = self._runner.run(
            ("docker", "network", "inspect", lease.network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-network lease is no longer inspectable")
        try:
            record = _parse_single_record(result.stdout)
            network_id = _required_id(record, kind="network")
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model-network ownership proof is invalid") from exc
        if sha256(network_id.encode()).hexdigest() != lease.network_id_sha256:
            raise RuntimeError("Docker model-network lease no longer owns the network")

    def _inspect_container(self, container_name: str) -> dict[str, Any]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-peer inspection failed")
        try:
            return _parse_single_record(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model-peer inspection payload is invalid") from exc

    def _require_owned_container(self, lease: DockerModelPeerLease) -> None:
        raw = self._inspect_container(lease.container_name)
        container_id = _required_id(raw, kind="container")
        if sha256(container_id.encode()).hexdigest() != lease.container_id_sha256:
            raise RuntimeError("Docker model-peer lease no longer owns the container")

    def _require_raw_container_id(self, container_name: str, expected_id: str) -> None:
        raw = self._inspect_container(container_name)
        if _required_id(raw, kind="container") != expected_id:
            raise RuntimeError("Docker model-peer ownership changed during readiness probe")

    def _remove_if_owned(self, container_name: str, expected_id: str) -> None:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            return
        try:
            current = _required_id(_parse_single_record(result.stdout), kind="container")
        except (ValueError, json.JSONDecodeError):
            return
        if current != expected_id:
            return
        removal = self._runner.run(
            ("docker", "rm", "--force", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if removal.returncode != 0:
            raise RuntimeError("Docker model-peer cleanup failed after rejected attestation")


def _verify_model_peer_inspection(
    *,
    profile: DockerModelPeerProfile,
    payload: dict[str, Any],
    expected_network_name: str,
) -> None:
    failures: list[str] = []
    host = payload.get("HostConfig")
    state = payload.get("State")
    mounts = payload.get("Mounts")
    networks = (payload.get("NetworkSettings") or {}).get("Networks") if isinstance(
        payload.get("NetworkSettings"), dict
    ) else None
    if payload.get("Image") != profile.image_id:
        failures.append("image_id")
    if not isinstance(state, dict) or state.get("Running") is not True:
        failures.append("running")
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
        cap_add = host.get("CapAdd") or []
        cap_drop = host.get("CapDrop") or []
        if cap_add:
            failures.append("cap_add")
        if "ALL" not in {str(value).upper() for value in cap_drop}:
            failures.append("cap_drop_all")
        security_opt = host.get("SecurityOpt") or []
        if "no-new-privileges:true" not in {str(value).casefold() for value in security_opt}:
            failures.append("no_new_privileges")
        if not _bounded_positive_int(host.get("PidsLimit"), profile.pids_limit):
            failures.append("pids_limit")
        if not _bounded_positive_int(host.get("Memory"), profile.memory_limit_bytes):
            failures.append("memory_limit")
        nano_cpu_limit = int(profile.cpus * 1_000_000_000)
        if not _bounded_positive_int(host.get("NanoCpus"), nano_cpu_limit):
            failures.append("cpu_limit")
        if host.get("PortBindings") not in (None, {}):
            failures.append("published_ports")
        device_requests = host.get("DeviceRequests") or []
        if profile.gpu_access:
            if len(device_requests) != 1 or not _is_gpu_device_request(device_requests[0]):
                failures.append("gpu_device_request")
        elif device_requests:
            failures.append("unexpected_device_request")
    if mounts not in (None, []):
        failures.append("host_mounts")
    if not isinstance(networks, dict) or set(networks) != {expected_network_name}:
        failures.append("network_membership")
    if failures:
        raise ValueError(
            "Docker model-peer inspection failed closed: "
            + ", ".join(sorted(set(failures)))
        )


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


def _bounded_positive_int(value: object, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= maximum


def _parse_full_id(stdout: str, *, kind: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"Docker {kind} launch returned invalid ID output")
    value = lines[0]
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError(f"Docker {kind} launch returned an invalid full ID")
    return value


def _parse_single_record(stdout: str) -> dict[str, Any]:
    payload = json.loads(stdout)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ValueError("Docker inspect must contain exactly one object")
    return payload[0]


def _required_id(payload: dict[str, Any], *, kind: str) -> str:
    value = payload.get("Id")
    if not isinstance(value, str) or not value:
        raise ValueError(f"Docker {kind} inspect Id must be a non-empty string")
    return value
