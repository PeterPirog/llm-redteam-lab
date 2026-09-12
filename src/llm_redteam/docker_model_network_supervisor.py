"""Trusted lifecycle supervisor for isolated Docker model networks.

The supervisor owns Docker Engine admission, network creation, exact network-ID
ownership, peer inspection and name-reuse-safe teardown.  It never trusts agent/model
output as containment evidence and does not start model inference itself.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import (
    DockerContainerNetworkMembershipInspection,
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
    DockerModelNetworkInspection,
    attest_isolated_model_network,
)
from .docker_supervisor import (
    CommandResult,
    DockerCommandRunner,
    SubprocessDockerCommandRunner,
)
from .domain import StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_VERSION_PREFIX = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


class DockerEngineVersionObservation(StrictModel):
    """Trusted Docker server-version evidence captured before network creation."""

    server_version: str = Field(min_length=1)
    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    patch: int = Field(ge=0)
    command_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerModelNetworkLease(StrictModel):
    """Runtime-only ownership token for one isolated model network."""

    network_name: str = Field(min_length=1)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    network_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    create_command_sha256: str = Field(pattern=_HASH_PATTERN)
    engine: DockerEngineVersionObservation


class DockerModelNetworkSupervisor:
    """Create, attest and release one isolated model network fail closed."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 15.0,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds

    def probe_engine_version(self) -> DockerEngineVersionObservation:
        """Read the Docker server version without invoking a shell."""

        command = (
            "docker",
            "version",
            "--format",
            "{{.Server.Version}}",
        )
        result = self._runner.run(
            command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker server version probe failed")
        version = _single_nonempty_line(
            result.stdout,
            error="Docker server version probe returned invalid output",
        )
        match = _VERSION_PREFIX.match(version)
        if match is None:
            raise RuntimeError("Docker server version is not parseable")
        major, minor, patch = (int(part) for part in match.groups())
        return DockerEngineVersionObservation(
            server_version=version,
            major=major,
            minor=minor,
            patch=patch,
            command_sha256=canonical_json_hash(list(command)),
        )

    def create(
        self,
        *,
        profile: DockerIsolatedModelNetworkProfile,
        network_name: str,
    ) -> DockerModelNetworkLease:
        """Create and own an empty isolated bridge only after independent inspection."""

        engine = self.probe_engine_version()
        if engine.major < profile.minimum_engine_major:
            raise RuntimeError(
                "Docker server is too old for the isolated model-network profile"
            )

        create_command = profile.docker_network_create_command(network_name=network_name)
        result = self._runner.run(
            create_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            # Failure may mean the name already belongs to an unrelated network.
            # Never remove by name before ownership has been established.
            raise RuntimeError("Docker model network creation failed")
        created_id = _parse_network_id(result.stdout)

        try:
            raw = self._inspect_raw(network_name)
            inspected_id = _raw_network_id(raw)
            if inspected_id != created_id:
                raise RuntimeError("Docker model network ownership changed before attestation")
            inspection = DockerModelNetworkInspection.from_docker_network_inspect(raw)
            _verify_empty_network_base(profile=profile, inspection=inspection, network_name=network_name)
        except Exception:
            self._remove_if_owned(network_name, created_id)
            raise

        return DockerModelNetworkLease(
            network_name=network_name,
            network_id_sha256=sha256(created_id.encode()).hexdigest(),
            network_profile_sha256=profile.profile_sha256,
            create_command_sha256=canonical_json_hash(list(create_command)),
            engine=engine,
        )

    def attest_peers(
        self,
        *,
        lease: DockerModelNetworkLease,
        profile: DockerIsolatedModelNetworkProfile,
        agent_container_name: str,
        agent_container_id_sha256: str,
        model_peer_container_id_sha256: str,
    ) -> DockerIsolatedModelNetworkAttestation:
        """Attest exact agent/model membership after both peers have been attached."""

        if lease.network_profile_sha256 != profile.profile_sha256:
            raise ValueError("model network lease does not bind the requested profile")
        if lease.engine.major < profile.minimum_engine_major:
            raise ValueError("model network lease was admitted by an insufficient Docker engine")

        self._require_owned_network(lease)
        agent_raw = self._inspect_container_raw(agent_container_name)
        model_raw = self._inspect_container_raw(profile.model_endpoint_host)
        agent = DockerContainerNetworkMembershipInspection.from_docker_inspect(agent_raw)
        model = DockerContainerNetworkMembershipInspection.from_docker_inspect(model_raw)
        final_raw = self._require_owned_network(lease)
        inspection = DockerModelNetworkInspection.from_docker_network_inspect(final_raw)

        return attest_isolated_model_network(
            profile=profile,
            inspection=inspection,
            agent_membership=agent,
            model_membership=model,
            network_name=lease.network_name,
            agent_container_id_sha256=agent_container_id_sha256,
            model_peer_container_id_sha256=model_peer_container_id_sha256,
        )

    def release(self, lease: DockerModelNetworkLease) -> None:
        """Remove only the network whose current ID is still owned by this lease."""

        self._require_owned_network(lease)
        result = self._runner.run(
            ("docker", "network", "rm", lease.network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model network teardown failed")

        post = self._runner.run(
            ("docker", "network", "inspect", lease.network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if post.returncode != 0:
            return
        try:
            records = _parse_inspect_records(post.stdout)
            remaining_id = _raw_network_id(records[0])
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model network removal could not be verified") from exc
        remaining_hash = sha256(remaining_id.encode()).hexdigest()
        if remaining_hash == lease.network_id_sha256:
            raise RuntimeError("Docker model network still exists after teardown")
        raise RuntimeError("Docker model network name was reused during teardown")

    def _require_owned_network(self, lease: DockerModelNetworkLease) -> dict[str, object]:
        raw = self._inspect_raw(lease.network_name)
        current_id = _raw_network_id(raw)
        if sha256(current_id.encode()).hexdigest() != lease.network_id_sha256:
            raise RuntimeError("Docker model network lease no longer owns the named network")
        return raw

    def _inspect_raw(self, network_name: str) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "network", "inspect", network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model network inspection failed")
        try:
            records = _parse_inspect_records(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model network inspection payload is invalid") from exc
        return records[0]

    def _inspect_container_raw(self, container_name: str) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-network peer inspection failed")
        try:
            records = _parse_inspect_records(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker peer inspection payload is invalid") from exc
        return records[0]

    def _remove_if_owned(self, network_name: str, expected_id: str) -> None:
        result = self._runner.run(
            ("docker", "network", "inspect", network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            return
        try:
            records = _parse_inspect_records(result.stdout)
            current_id = _raw_network_id(records[0])
        except (ValueError, json.JSONDecodeError):
            return
        if current_id != expected_id:
            return
        remove = self._runner.run(
            ("docker", "network", "rm", network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if remove.returncode != 0:
            raise RuntimeError("Docker model network cleanup failed after rejected attestation")


def _verify_empty_network_base(
    *,
    profile: DockerIsolatedModelNetworkProfile,
    inspection: DockerModelNetworkInspection,
    network_name: str,
) -> None:
    failures: list[str] = []
    if inspection.network_name_sha256 != sha256(network_name.encode()).hexdigest():
        failures.append("network_name")
    if inspection.driver != profile.driver:
        failures.append("driver")
    if inspection.scope != "local":
        failures.append("scope")
    if not inspection.internal:
        failures.append("internal")
    if inspection.ingress:
        failures.append("ingress")
    if inspection.enable_ipv6:
        failures.append("ipv6_enabled")
    if inspection.gateway_mode_ipv4 != "isolated":
        failures.append("gateway_mode_ipv4")
    if inspection.gateway_mode_ipv6 not in {None, "isolated"}:
        failures.append("gateway_mode_ipv6")
    if inspection.profile_label_sha256 != profile.profile_sha256:
        failures.append("profile_label")
    if inspection.members:
        failures.append("network_not_empty_at_admission")
    if failures:
        raise ValueError(
            "Docker model network admission failed closed: "
            + ", ".join(sorted(set(failures)))
        )


def _parse_network_id(stdout: str) -> str:
    network_id = _single_nonempty_line(
        stdout,
        error="Docker model network creation did not return exactly one network ID",
    )
    if len(network_id) != 64 or any(
        character not in "0123456789abcdef" for character in network_id
    ):
        raise RuntimeError("Docker model network creation returned an invalid network ID")
    return network_id


def _single_nonempty_line(stdout: str, *, error: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(error)
    return lines[0]


def _parse_inspect_records(stdout: str) -> list[dict[str, object]]:
    payload = json.loads(stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("Docker inspect must return exactly one record")
    record = payload[0]
    if not isinstance(record, dict):
        raise ValueError("Docker inspect record must be an object")
    return record


def _raw_network_id(payload: dict[str, object]) -> str:
    value = payload.get("Id")
    if not isinstance(value, str) or not value:
        raise ValueError("Docker network inspect Id must be a non-empty string")
    return value
