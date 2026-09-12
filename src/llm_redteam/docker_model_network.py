"""Independent attestation for a model-only Docker network.

The contract is intentionally narrower than general container networking.  It proves
that an AGENT container and one predeclared local-model container are the only peers on
an IPv4-only internal bridge whose gateway mode is ``isolated``.  Both containers must
be attached to that network and to no other Docker network.

This module does not execute Docker or model inference.  A trusted supervisor supplies
``docker network inspect`` and ``docker inspect`` payloads and receives a hash-only
attestation after all invariants are verified fail closed.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Literal

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_DOCKER_NAME_PATTERN = r"^[a-z0-9][a-z0-9_.-]{0,127}$"
_GATEWAY_MODE_IPV4 = "com.docker.network.bridge.gateway_mode_ipv4"
_GATEWAY_MODE_IPV6 = "com.docker.network.bridge.gateway_mode_ipv6"
_PROFILE_LABEL = "llm-redteam.model-network-profile-sha256"


class DockerIsolatedModelNetworkProfile(StrictModel):
    """Stable high-assurance policy for one agent-to-model-only Docker network."""

    version: int = Field(ge=1, default=1)
    driver: Literal["bridge"] = "bridge"
    model_endpoint_host: str = Field(pattern=_DOCKER_NAME_PATTERN)
    model_endpoint_port: int = Field(ge=1, le=65535)
    minimum_engine_major: int = Field(ge=28, default=28)

    @model_validator(mode="after")
    def endpoint_host_is_canonical(self) -> DockerIsolatedModelNetworkProfile:
        if self.model_endpoint_host != self.model_endpoint_host.casefold():
            raise ValueError("model_endpoint_host must be lowercase")
        return self

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(
            {
                **self.model_dump(mode="json"),
                "internal": True,
                "gateway_mode_ipv4": "isolated",
                "ipv6_enabled": False,
                "member_policy": "exact-agent-plus-model-v1",
                "container_membership": "single-network-only-v1",
            }
        )

    @property
    def model_endpoint_origin(self) -> str:
        return f"http://{self.model_endpoint_host}:{self.model_endpoint_port}"

    def docker_network_create_command(self, *, network_name: str) -> tuple[str, ...]:
        """Build the trusted network-create command without executing it."""

        _validate_docker_name(network_name, field_name="network_name")
        return (
            "docker",
            "network",
            "create",
            "--driver",
            self.driver,
            "--internal",
            "--opt",
            f"{_GATEWAY_MODE_IPV4}=isolated",
            "--label",
            f"{_PROFILE_LABEL}={self.profile_sha256}",
            network_name,
        )


class DockerNetworkMemberInspection(StrictModel):
    """Hash-only peer evidence normalized from ``docker network inspect``."""

    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    name_sha256: str = Field(pattern=_HASH_PATTERN)
    has_ipv4_address: bool
    has_ipv6_address: bool


class DockerModelNetworkInspection(StrictModel):
    """Security-relevant subset of one Docker network inspection record."""

    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    network_name_sha256: str = Field(pattern=_HASH_PATTERN)
    driver: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    internal: bool
    ingress: bool
    enable_ipv6: bool
    gateway_mode_ipv4: str | None = None
    gateway_mode_ipv6: str | None = None
    profile_label_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    members: tuple[DockerNetworkMemberInspection, ...] = ()

    @classmethod
    def from_docker_network_inspect(
        cls,
        payload: dict[str, Any],
    ) -> DockerModelNetworkInspection:
        """Normalize one real network-inspect object without retaining raw identities."""

        network_id = _required_str(payload, "Id")
        network_name = _required_str(payload, "Name")
        options = _optional_dict(payload, "Options")
        labels = _optional_dict(payload, "Labels")
        containers = _optional_dict(payload, "Containers")

        members: list[DockerNetworkMemberInspection] = []
        for container_id, raw in containers.items():
            if not isinstance(container_id, str) or not container_id:
                raise ValueError("Docker network member ID must be a non-empty string")
            if not isinstance(raw, dict):
                raise ValueError("Docker network member must be an object")
            name = _required_str(raw, "Name")
            ipv4 = _optional_str(raw, "IPv4Address")
            ipv6 = _optional_str(raw, "IPv6Address")
            members.append(
                DockerNetworkMemberInspection(
                    container_id_sha256=_digest(container_id),
                    name_sha256=_digest(name),
                    has_ipv4_address=bool(ipv4),
                    has_ipv6_address=bool(ipv6),
                )
            )

        profile_label = labels.get(_PROFILE_LABEL)
        if profile_label is not None and not isinstance(profile_label, str):
            raise ValueError("Docker network profile label must be a string")

        return cls(
            network_id_sha256=_digest(network_id),
            network_name_sha256=_digest(network_name),
            driver=_required_str(payload, "Driver"),
            scope=_required_str(payload, "Scope"),
            internal=_required_bool(payload, "Internal"),
            ingress=_required_bool(payload, "Ingress"),
            enable_ipv6=_required_bool(payload, "EnableIPv6"),
            gateway_mode_ipv4=_mapping_optional_str(options, _GATEWAY_MODE_IPV4),
            gateway_mode_ipv6=_mapping_optional_str(options, _GATEWAY_MODE_IPV6),
            profile_label_sha256=profile_label,
            members=tuple(sorted(members, key=lambda item: item.container_id_sha256)),
        )

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerContainerNetworkMembershipInspection(StrictModel):
    """Container-side proof that a peer has no second Docker network attachment."""

    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    container_name_sha256: str = Field(pattern=_HASH_PATTERN)
    running: bool
    network_id_sha256s: tuple[str, ...] = ()

    @classmethod
    def from_docker_inspect(
        cls,
        payload: dict[str, Any],
    ) -> DockerContainerNetworkMembershipInspection:
        container_id = _required_str(payload, "Id")
        name = _required_str(payload, "Name").removeprefix("/")
        state = _required_dict(payload, "State")
        network_settings = _required_dict(payload, "NetworkSettings")
        networks = _required_dict(network_settings, "Networks")

        network_ids: list[str] = []
        for raw in networks.values():
            if not isinstance(raw, dict):
                raise ValueError("Docker container network membership must be an object")
            network_id = _required_str(raw, "NetworkID")
            network_ids.append(_digest(network_id))

        return cls(
            container_id_sha256=_digest(container_id),
            container_name_sha256=_digest(name),
            running=_required_bool(state, "Running"),
            network_id_sha256s=tuple(sorted(network_ids)),
        )

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerIsolatedModelNetworkAttestation(StrictModel):
    """Hash-only trusted proof of the exact agent/model network boundary."""

    version: int = Field(ge=1, default=1)
    issuer: str = Field(min_length=1)
    network_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    network_name_sha256: str = Field(pattern=_HASH_PATTERN)
    agent_container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    model_peer_container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    model_endpoint_origin_sha256: str = Field(pattern=_HASH_PATTERN)
    network_inspection_sha256: str = Field(pattern=_HASH_PATTERN)
    agent_membership_sha256: str = Field(pattern=_HASH_PATTERN)
    model_membership_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def attestation_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def attest_isolated_model_network(
    *,
    profile: DockerIsolatedModelNetworkProfile,
    inspection: DockerModelNetworkInspection,
    agent_membership: DockerContainerNetworkMembershipInspection,
    model_membership: DockerContainerNetworkMembershipInspection,
    network_name: str,
    agent_container_id_sha256: str,
    model_peer_container_id_sha256: str,
    issuer: str = "llm-redteam-docker-model-network-v1",
) -> DockerIsolatedModelNetworkAttestation:
    """Verify the exact two-peer isolated network and issue trusted evidence."""

    _validate_docker_name(network_name, field_name="network_name")
    _require_hash(agent_container_id_sha256, field_name="agent_container_id_sha256")
    _require_hash(model_peer_container_id_sha256, field_name="model_peer_container_id_sha256")
    if agent_container_id_sha256 == model_peer_container_id_sha256:
        raise ValueError("agent and model peer must be distinct containers")

    failures: list[str] = []
    if inspection.network_name_sha256 != _digest(network_name):
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

    expected_member_ids = {
        agent_container_id_sha256,
        model_peer_container_id_sha256,
    }
    inspected_members = {
        member.container_id_sha256: member for member in inspection.members
    }
    if set(inspected_members) != expected_member_ids:
        failures.append("exact_member_set")
    else:
        if any(not member.has_ipv4_address for member in inspected_members.values()):
            failures.append("member_ipv4")
        if any(member.has_ipv6_address for member in inspected_members.values()):
            failures.append("member_ipv6")
        model_network_member = inspected_members[model_peer_container_id_sha256]
        if model_network_member.name_sha256 != _digest(profile.model_endpoint_host):
            failures.append("model_peer_network_name")

    for label, membership, expected_container_id in (
        ("agent", agent_membership, agent_container_id_sha256),
        ("model", model_membership, model_peer_container_id_sha256),
    ):
        if membership.container_id_sha256 != expected_container_id:
            failures.append(f"{label}_container_id")
        if not membership.running:
            failures.append(f"{label}_running")
        if membership.network_id_sha256s != (inspection.network_id_sha256,):
            failures.append(f"{label}_single_network")

    if model_membership.container_name_sha256 != _digest(profile.model_endpoint_host):
        failures.append("model_peer_container_name")

    if failures:
        raise ValueError(
            "Docker isolated model network inspection failed closed: "
            + ", ".join(sorted(set(failures)))
        )

    return DockerIsolatedModelNetworkAttestation(
        issuer=issuer,
        network_profile_sha256=profile.profile_sha256,
        network_id_sha256=inspection.network_id_sha256,
        network_name_sha256=inspection.network_name_sha256,
        agent_container_id_sha256=agent_container_id_sha256,
        model_peer_container_id_sha256=model_peer_container_id_sha256,
        model_endpoint_origin_sha256=_digest(profile.model_endpoint_origin),
        network_inspection_sha256=inspection.proof_sha256,
        agent_membership_sha256=agent_membership.proof_sha256,
        model_membership_sha256=model_membership.proof_sha256,
    )


def _validate_docker_name(value: str, *, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must be non-empty")
    import re

    if re.fullmatch(_DOCKER_NAME_PATTERN, value) is None:
        raise ValueError(f"{field_name} must be a lowercase Docker-compatible name")


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _require_hash(value: str, *, field_name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")


def _required_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Docker inspection {key} must be an object")
    return value


def _optional_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Docker inspection {key} must be an object or null")
    return value


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Docker inspection {key} must be a non-empty string")
    return value


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Docker inspection {key} must be a string or null")
    return value


def _mapping_optional_str(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"Docker inspection option {key} must be a non-empty string")
    return value


def _required_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Docker inspection {key} must be a boolean")
    return value
