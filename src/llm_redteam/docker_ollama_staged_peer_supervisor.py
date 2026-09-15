"""Lifecycle supervisor for one exact read-only staged Ollama model peer."""

from __future__ import annotations

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_model_peer import DockerModelPeerLease, DockerModelPeerSupervisor
from .docker_ollama_staged_peer import (
    DockerOllamaStagedPeerAttestation,
    DockerOllamaStagedPeerProfile,
    attest_staged_ollama_peer,
)
from .domain import StrictModel
from .ollama_model_staging import PreparedOllamaModelStore

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerOllamaStagedPeerLease(StrictModel):
    """Owned peer lease augmented with exact staged-store runtime proof."""

    peer: DockerModelPeerLease
    staging: DockerOllamaStagedPeerAttestation
    staged_store_identity_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOllamaStagedPeerSupervisor(DockerModelPeerSupervisor):
    """Launch only after exact staged-store delivery and readiness are proven."""

    def launch_staged(
        self,
        *,
        profile: DockerOllamaStagedPeerProfile,
        staged_store: PreparedOllamaModelStore,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
    ) -> DockerOllamaStagedPeerLease:
        if network_lease.network_profile_sha256 != network_profile.profile_sha256:
            raise ValueError("model-network lease does not bind the requested profile")
        if staged_store.identity.identity_sha256 != profile.staged_store_identity_sha256:
            raise ValueError("staged model store does not bind the requested peer profile")
        if staged_store.identity.model_id != profile.model_id:
            raise ValueError("staged model store model does not match requested peer profile")

        self._require_owned_network(network_lease)
        launch_command = profile.docker_run_command_with_store(
            network_profile=network_profile,
            network_name=network_lease.network_name,
            staged_store=staged_store,
        )
        result = self._runner.run(
            launch_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("staged Ollama model-peer launch failed")

        container_id = _parse_full_container_id(result.stdout)
        name = network_profile.model_endpoint_host
        try:
            raw = self._inspect_container(name)
            inspected_id = raw.get("Id")
            if inspected_id != container_id:
                raise RuntimeError("staged Ollama peer ownership changed before attestation")
            staging = attest_staged_ollama_peer(
                profile=profile,
                staged_store=staged_store,
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

        peer = DockerModelPeerLease(
            container_name=name,
            container_id_sha256=staging.container_id_sha256,
            profile_sha256=profile.profile_sha256,
            network_id_sha256=network_lease.network_id_sha256,
            launch_command_sha256=canonical_json_hash(list(launch_command)),
            readiness=readiness,
        )
        return DockerOllamaStagedPeerLease(
            peer=peer,
            staging=staging,
            staged_store_identity_sha256=staged_store.identity.identity_sha256,
        )

    def release_staged(self, lease: DockerOllamaStagedPeerLease) -> None:
        """Release only the exact container still owned by the embedded peer lease."""

        self.release(lease.peer)


def _parse_full_container_id(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("staged Ollama launch returned invalid container ID output")
    value = lines[0]
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("staged Ollama launch returned an invalid full container ID")
    return value
