"""Trusted lifecycle supervisor for a network-attached AGENT container.

The supervisor composes three independent proofs before returning a usable lease:

1. the pre-created model-network lease still owns the exact Docker network;
2. the launched AGENT container still owns the exact Docker container name;
3. independent network and sandbox attestations describe the same AGENT container.

No shell is used. Failed or raced resources are cleaned up only after exact ownership
has been re-established from Docker inspection.
"""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from .docker_model_network_supervisor import (
    DockerModelNetworkLease,
    DockerModelNetworkSupervisor,
)
from .docker_networked_sandbox import (
    DockerNetworkedAgentProfile,
    attest_networked_docker_sandbox,
)
from .docker_sandbox import DockerContainerInspection
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel
from .opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerNetworkedAgentLease(StrictModel):
    """Runtime ownership token for one independently attested AGENT container."""

    container_name: str = Field(min_length=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_command_sha256: str = Field(pattern=_HASH_PATTERN)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_attestation: AgentSandboxAttestation
    network_attestation: DockerIsolatedModelNetworkAttestation


class DockerNetworkedAgentSupervisor:
    """Launch and release a confined AGENT on one already-owned model network."""

    def __init__(
        self,
        *,
        network_supervisor: DockerModelNetworkSupervisor,
        runner: DockerCommandRunner | None = None,
        command_timeout_seconds: float = 15.0,
        stop_timeout_seconds: int = 5,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if stop_timeout_seconds < 0:
            raise ValueError("stop_timeout_seconds cannot be negative")
        self._network_supervisor = network_supervisor
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds
        self._stop_timeout_seconds = stop_timeout_seconds

    def launch(
        self,
        *,
        docker_profile: DockerNetworkedAgentProfile,
        model_network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
        model_peer_container_id_sha256: str,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        workspace_host_path: str,
        container_name: str,
        command: tuple[str, ...],
    ) -> DockerNetworkedAgentLease:
        """Launch only onto the still-owned network and return a doubly attested lease."""

        if network_lease.network_profile_sha256 != model_network_profile.profile_sha256:
            raise ValueError("network lease does not bind the requested model-network profile")
        if docker_profile.model_network_profile_sha256 != model_network_profile.profile_sha256:
            raise ValueError("AGENT profile does not bind the requested model-network profile")

        self._require_owned_network(network_lease)
        launch_command = docker_profile.docker_run_command(
            container_name=container_name,
            workspace_host_path=workspace_host_path,
            network_name=network_lease.network_name,
            command=command,
            detach=True,
        )
        launch_result = self._runner.run(
            launch_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if launch_result.returncode != 0:
            # A failed run can indicate a pre-existing unrelated container name.
            # Never remove by name before ownership has been established.
            raise RuntimeError("networked Docker AGENT launch failed")

        launched_id = _parse_container_id(launch_result.stdout)
        try:
            raw = self._inspect_container_raw(container_name)
            inspected_id = _raw_container_id(raw)
            if inspected_id != launched_id:
                raise RuntimeError("networked Docker AGENT ownership changed before attestation")
            inspection = DockerContainerInspection.from_docker_inspect(raw)
            network_attestation = self._network_supervisor.attest_peers(
                lease=network_lease,
                profile=model_network_profile,
                agent_container_name=container_name,
                agent_container_id_sha256=sha256(launched_id.encode()).hexdigest(),
                model_peer_container_id_sha256=model_peer_container_id_sha256,
            )
            sandbox_attestation = attest_networked_docker_sandbox(
                docker_profile=docker_profile,
                model_network_profile=model_network_profile,
                runtime_profile=runtime_profile,
                sandbox_policy=sandbox_policy,
                inspection=inspection,
                network_attestation=network_attestation,
                workspace_host_path=workspace_host_path,
                network_name=network_lease.network_name,
            )
        except Exception:
            self._remove_if_owned(container_name, launched_id)
            raise

        return DockerNetworkedAgentLease(
            container_name=container_name,
            container_id_sha256=sha256(launched_id.encode()).hexdigest(),
            launch_command_sha256=canonical_json_hash(list(launch_command)),
            network_id_sha256=network_lease.network_id_sha256,
            sandbox_attestation=sandbox_attestation,
            network_attestation=network_attestation,
        )

    def release(self, lease: DockerNetworkedAgentLease) -> None:
        """Stop only the AGENT container still owned by the supplied lease."""

        self._require_owned_container(lease)
        stop_result = self._runner.run(
            (
                "docker",
                "stop",
                "--time",
                str(self._stop_timeout_seconds),
                lease.container_name,
            ),
            timeout_seconds=self._command_timeout_seconds,
        )
        if stop_result.returncode != 0:
            remove_result = self._runner.run(
                ("docker", "rm", "--force", lease.container_name),
                timeout_seconds=self._command_timeout_seconds,
            )
            if remove_result.returncode != 0:
                raise RuntimeError("networked Docker AGENT teardown failed")

        post = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if post.returncode != 0:
            return
        try:
            record = _parse_single_inspect_record(post.stdout)
            remaining_id = _raw_container_id(record)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("networked Docker AGENT removal could not be verified") from exc
        remaining_hash = sha256(remaining_id.encode()).hexdigest()
        if remaining_hash == lease.container_id_sha256:
            raise RuntimeError("networked Docker AGENT still exists after teardown")
        raise RuntimeError("networked Docker AGENT name was reused during teardown")

    def _require_owned_network(self, lease: DockerModelNetworkLease) -> None:
        result = self._runner.run(
            ("docker", "network", "inspect", lease.network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("model-network lease is no longer inspectable")
        try:
            record = _parse_single_inspect_record(result.stdout)
            network_id = _required_id(record, kind="network")
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("model-network ownership proof is invalid") from exc
        if sha256(network_id.encode()).hexdigest() != lease.network_id_sha256:
            raise RuntimeError("model-network lease no longer owns the named network")

    def _require_owned_container(self, lease: DockerNetworkedAgentLease) -> None:
        raw = self._inspect_container_raw(lease.container_name)
        current_id = _raw_container_id(raw)
        if sha256(current_id.encode()).hexdigest() != lease.container_id_sha256:
            raise RuntimeError("networked Docker AGENT lease no longer owns the container")

    def _inspect_container_raw(self, container_name: str) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("networked Docker AGENT inspection failed")
        try:
            return _parse_single_inspect_record(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("networked Docker AGENT inspection payload is invalid") from exc

    def _remove_if_owned(self, container_name: str, expected_id: str) -> None:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            return
        try:
            record = _parse_single_inspect_record(result.stdout)
            current_id = _raw_container_id(record)
        except (ValueError, json.JSONDecodeError):
            return
        if current_id != expected_id:
            return
        removal = self._runner.run(
            ("docker", "rm", "--force", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if removal.returncode != 0:
            raise RuntimeError("networked Docker AGENT cleanup failed after rejection")


def _parse_container_id(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("networked Docker AGENT launch returned invalid container ID output")
    container_id = lines[0]
    if len(container_id) != 64 or any(
        character not in "0123456789abcdef" for character in container_id
    ):
        raise RuntimeError("networked Docker AGENT launch returned an invalid container ID")
    return container_id


def _parse_single_inspect_record(stdout: str) -> dict[str, object]:
    payload = json.loads(stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("Docker inspect must return exactly one record")
    record = payload[0]
    if not isinstance(record, dict):
        raise ValueError("Docker inspect record must be an object")
    return record


def _required_id(record: dict[str, object], *, kind: str) -> str:
    value = record.get("Id")
    if not isinstance(value, str) or not value:
        raise ValueError(f"Docker {kind} inspect Id must be a non-empty string")
    return value


def _raw_container_id(record: dict[str, object]) -> str:
    value = _required_id(record, kind="container")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("Docker container inspect Id must be a full lowercase ID")
    return value
