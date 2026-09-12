"""Compose the hardened AGENT container with one isolated local-model network.

This module preserves the existing offline ``DockerSandboxProfile`` unchanged.  A
network-attached profile fingerprints that already-reviewed confinement contract
alongside one ``DockerIsolatedModelNetworkProfile`` and independently verifies both
container confinement and the exact agent/model network attestation.

No Docker command is executed here.  Per-run network names and container IDs are
execution evidence, not stable target identity.
"""

from __future__ import annotations

from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from .docker_sandbox import DockerContainerInspection, DockerSandboxProfile, _normalize_host_path
from .opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerNetworkedAgentProfile(DockerSandboxProfile):
    """Stable AGENT confinement profile with exactly one isolated model peer."""

    version: int = Field(ge=1, default=1)
    model_network_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    model_endpoint_origin_sha256: str = Field(pattern=_HASH_PATTERN)

    @classmethod
    def compose(
        cls,
        *,
        sandbox: DockerSandboxProfile,
        model_network: DockerIsolatedModelNetworkProfile,
    ) -> DockerNetworkedAgentProfile:
        return cls(
            **sandbox.model_dump(mode="python"),
            model_network_profile_sha256=model_network.profile_sha256,
            model_endpoint_origin_sha256=sha256(
                model_network.model_endpoint_origin.encode()
            ).hexdigest(),
        )

    @property
    def profile_sha256(self) -> str:
        """Bind the unchanged base confinement contract to the model-network policy."""

        base = DockerSandboxProfile.model_validate(
            {
                "version": self.version,
                "image_ref": self.image_ref,
                "image_id": self.image_id,
                "container_workspace": self.container_workspace,
                "memory_limit_bytes": self.memory_limit_bytes,
                "pids_limit": self.pids_limit,
                "cpus": self.cpus,
            }
        )
        return canonical_json_hash(
            {
                "version": 1,
                "base_sandbox_profile_sha256": base.profile_sha256,
                "model_network_profile_sha256": self.model_network_profile_sha256,
                "model_endpoint_origin_sha256": self.model_endpoint_origin_sha256,
                "network_semantics": "exact-isolated-model-peer-v1",
            }
        )

    def docker_run_command(
        self,
        *,
        container_name: str,
        workspace_host_path: str,
        network_name: str,
        command: tuple[str, ...],
        detach: bool = False,
    ) -> tuple[str, ...]:
        """Build the hardened launch command on one pre-created trusted network."""

        if not container_name or any(character.isspace() for character in container_name):
            raise ValueError("container_name must be non-empty and contain no whitespace")
        if not network_name or any(character.isspace() for character in network_name):
            raise ValueError("network_name must be non-empty and contain no whitespace")
        _normalize_host_path(workspace_host_path)
        if not command:
            raise ValueError("container command must be non-empty")
        detach_args = ("--detach",) if detach else ()
        return (
            "docker",
            "run",
            "--rm",
            *detach_args,
            "--pull",
            "never",
            "--name",
            container_name,
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


def attest_networked_docker_sandbox(
    *,
    docker_profile: DockerNetworkedAgentProfile,
    model_network_profile: DockerIsolatedModelNetworkProfile,
    runtime_profile: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
    inspection: DockerContainerInspection,
    network_attestation: DockerIsolatedModelNetworkAttestation,
    workspace_host_path: str,
    network_name: str,
    issuer: str = "llm-redteam-docker-networked-agent-v1",
) -> AgentSandboxAttestation:
    """Issue sandbox evidence only when confinement and model-network proofs agree."""

    if sandbox_policy.enforcement_kind != SandboxEnforcementKind.DOCKER:
        raise ValueError("networked Docker attestation requires enforcement_kind=docker")
    if sandbox_policy.enforcement_profile_sha256 != docker_profile.profile_sha256:
        raise ValueError("sandbox policy does not bind the networked Docker profile")
    if not sandbox_policy.disposable_workspace:
        raise ValueError("networked Docker attestation requires disposable_workspace")
    if not sandbox_policy.external_network_denied:
        raise ValueError("networked Docker attestation requires external_network_denied")
    if not sandbox_policy.git_publication_denied:
        raise ValueError("networked Docker attestation requires git_publication_denied")
    if sandbox_policy.allowed_network_endpoints:
        raise ValueError(
            "external endpoint allowlist must remain empty; the model peer is bound "
            "by the isolated network profile"
        )
    if docker_profile.model_network_profile_sha256 != model_network_profile.profile_sha256:
        raise ValueError("networked Docker profile does not bind the model-network profile")
    expected_origin_hash = sha256(model_network_profile.model_endpoint_origin.encode()).hexdigest()
    if docker_profile.model_endpoint_origin_sha256 != expected_origin_hash:
        raise ValueError("networked Docker profile does not bind the model endpoint")
    if network_attestation.network_profile_sha256 != model_network_profile.profile_sha256:
        raise ValueError("network attestation does not bind the model-network profile")
    if network_attestation.model_endpoint_origin_sha256 != expected_origin_hash:
        raise ValueError("network attestation does not bind the configured model endpoint")
    if inspection.container_id_sha256 != network_attestation.agent_container_id_sha256:
        raise ValueError("sandbox and network attestations describe different AGENT containers")

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
    if inspection.network_mode != network_name:
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
        raise ValueError(
            "Networked Docker sandbox inspection failed closed: "
            + ", ".join(sorted(set(failures)))
        )

    proof_sha256 = canonical_json_hash(
        {
            "docker_profile_sha256": docker_profile.profile_sha256,
            "container_inspection_sha256": inspection.proof_sha256,
            "model_network_attestation_sha256": network_attestation.attestation_sha256,
        }
    )
    return AgentSandboxAttestation(
        issuer=issuer,
        isolation_id=f"docker-networked:{inspection.container_id_sha256}",
        runtime_profile_sha256=runtime_profile.profile_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        workspace_root_sha256=runtime_profile.workspace_root_sha256,
        proof_sha256=proof_sha256,
    )
