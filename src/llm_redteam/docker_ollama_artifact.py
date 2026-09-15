"""Exact Ollama artifact verification inside one owned Docker model peer.

The verifier performs no inference. It invokes a fixed laboratory-owned probe interface
inside the exact model-peer container, verifies ownership before and after the probe, and
binds the resulting provider artifact identity to the peer profile and lease.
"""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_peer import DockerModelPeerLease, DockerModelPeerProfile
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel
from .model_artifact import (
    ModelArtifactObservation,
    ModelPeerArtifactBinding,
    bind_model_peer_artifact,
)
from .ollama_artifact import OllamaArtifactContract

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_PROBE_EXECUTABLE = "/usr/local/bin/rt-ollama-probe"
_PROBE_CONTRACT_ID = "rt-ollama-probe-v1"


class OllamaDockerArtifactProbeProfile(StrictModel):
    """Stable binding to the fixed laboratory Ollama inventory probe contract."""

    version: int = Field(ge=1, default=1)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def inventory_command(self) -> tuple[str, ...]:
        return (_PROBE_EXECUTABLE, "tags")

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "peer_profile_sha256": self.peer_profile_sha256,
                "probe_contract_id": _PROBE_CONTRACT_ID,
                "inventory_command": list(self.inventory_command),
            }
        )


class DockerOllamaArtifactVerification(StrictModel):
    """Hash-safe proof that one owned Ollama peer exposes one exact local artifact."""

    version: int = Field(ge=1, default=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    peer_readiness_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_command_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact: ModelArtifactObservation
    binding: ModelPeerArtifactBinding

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOllamaArtifactVerifier:
    """Verify exact Ollama content without trusting a mutable model tag or container name."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 30.0,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds

    def verify(
        self,
        *,
        peer_profile: DockerModelPeerProfile,
        peer_lease: DockerModelPeerLease,
        contract: OllamaArtifactContract,
        probe_profile: OllamaDockerArtifactProbeProfile,
    ) -> DockerOllamaArtifactVerification:
        """Fail closed on peer, readiness, ownership, probe or exact manifest drift."""

        _validate_static_binding(
            peer_profile=peer_profile,
            peer_lease=peer_lease,
            contract=contract,
            probe_profile=probe_profile,
        )
        self._require_owned_container(peer_lease)
        result = self._runner.run(
            ("docker", "exec", peer_lease.container_name, *probe_profile.inventory_command),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Ollama artifact inventory probe failed")
        self._require_owned_container(peer_lease)

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama artifact inventory output is not valid JSON") from exc
        observation = contract.verify_tags_response(payload)
        if not observation.identity.local_artifact:
            raise ValueError("owned Ollama peer did not expose a local model artifact")

        binding = bind_model_peer_artifact(
            peer_profile_sha256=peer_profile.profile_sha256,
            peer_provider_id=peer_profile.provider_id,
            peer_model_id=peer_profile.model_id,
            artifact=observation.identity,
        )
        return DockerOllamaArtifactVerification(
            container_id_sha256=peer_lease.container_id_sha256,
            network_id_sha256=peer_lease.network_id_sha256,
            peer_profile_sha256=peer_profile.profile_sha256,
            peer_readiness_proof_sha256=peer_lease.readiness.proof_sha256,
            probe_profile_sha256=probe_profile.profile_sha256,
            probe_command_sha256=canonical_json_hash(list(probe_profile.inventory_command)),
            artifact=observation,
            binding=binding,
        )

    def _require_owned_container(self, lease: DockerModelPeerLease) -> None:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Ollama model-peer container is no longer inspectable")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama model-peer inspection is not valid JSON") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise RuntimeError("Ollama model-peer inspect must return exactly one record")
        container_id = payload[0].get("Id")
        if not isinstance(container_id, str):
            raise RuntimeError("Ollama model-peer inspect Id must be a string")
        if len(container_id) != 64 or any(
            character not in "0123456789abcdef" for character in container_id
        ):
            raise RuntimeError("Ollama model-peer inspect Id must be a full lowercase ID")
        if sha256(container_id.encode()).hexdigest() != lease.container_id_sha256:
            raise RuntimeError("Ollama model-peer lease no longer owns the container")


def _validate_static_binding(
    *,
    peer_profile: DockerModelPeerProfile,
    peer_lease: DockerModelPeerLease,
    contract: OllamaArtifactContract,
    probe_profile: OllamaDockerArtifactProbeProfile,
) -> None:
    if peer_profile.provider_id != "ollama":
        raise ValueError("Ollama artifact verification requires provider_id=ollama")
    if not contract.require_local:
        raise ValueError("Docker Ollama artifact verification requires a local-only contract")
    if peer_profile.model_id != contract.model_id:
        raise ValueError("Ollama artifact contract model does not match model-peer profile")
    if peer_lease.profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("model-peer lease does not bind the requested peer profile")
    if probe_profile.peer_profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("artifact probe profile does not bind the requested model peer")

    readiness = peer_lease.readiness
    if not readiness.ready:
        raise ValueError("model-peer lease is not readiness-qualified")
    if readiness.profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("model-peer readiness does not bind the requested peer profile")
    if readiness.provider_id != peer_profile.provider_id:
        raise ValueError("model-peer readiness provider does not match peer profile")
    if readiness.model_id != peer_profile.model_id:
        raise ValueError("model-peer readiness model does not match peer profile")
    if readiness.container_id_sha256 != peer_lease.container_id_sha256:
        raise ValueError("model-peer readiness does not bind the leased container")
