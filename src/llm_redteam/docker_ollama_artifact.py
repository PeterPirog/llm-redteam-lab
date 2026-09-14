"""Trusted Ollama artifact verification inside an owned Docker model peer.

The model name is not treated as artifact identity. A predeclared, provider-specific
inventory command runs through `docker exec` against the exact owned model-peer
container, returns an Ollama `/api/tags`-compatible JSON object, and is evaluated by the
existing `OllamaArtifactContract`. No inference request is performed.
"""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field, model_validator

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


class OllamaDockerArtifactProbeProfile(StrictModel):
    """Stable non-inference command contract for an Ollama model-peer image."""

    version: int = Field(ge=1, default=1)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    inventory_command: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def command_is_argument_vector(self) -> "OllamaDockerArtifactProbeProfile":
        if any(not item or "\x00" in item for item in self.inventory_command):
            raise ValueError("artifact inventory command requires non-empty NUL-free arguments")
        return self

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOllamaArtifactVerification(StrictModel):
    """Hash-safe proof that one owned Ollama peer exposes the declared model artifact."""

    version: int = Field(ge=1, default=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    probe_command_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact: ModelArtifactObservation
    binding: ModelPeerArtifactBinding

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOllamaArtifactVerifier:
    """Verify exact Ollama model content without trusting mutable model tags alone."""

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
        """Fail closed on ownership, profile, provider, model or manifest drift."""

        if peer_profile.provider_id != "ollama":
            raise ValueError("Ollama artifact verification requires provider_id=ollama")
        if peer_profile.model_id != contract.model_id:
            raise ValueError("Ollama artifact contract model does not match model-peer profile")
        if peer_lease.profile_sha256 != peer_profile.profile_sha256:
            raise ValueError("model-peer lease does not bind the requested peer profile")
        if probe_profile.peer_profile_sha256 != peer_profile.profile_sha256:
            raise ValueError("artifact probe profile does not bind the requested model peer")

        self._require_owned_container(peer_lease)
        result = self._runner.run(
            ("docker", "exec", peer_lease.container_name, *probe_profile.inventory_command),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Ollama artifact inventory command failed")
        self._require_owned_container(peer_lease)

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Ollama artifact inventory output is not valid JSON") from exc

        observation = contract.verify_tags_response(payload)
        binding = bind_model_peer_artifact(
            peer_profile_sha256=peer_profile.profile_sha256,
            peer_provider_id=peer_profile.provider_id,
            peer_model_id=peer_profile.model_id,
            artifact=observation.identity,
        )
        return DockerOllamaArtifactVerification(
            container_id_sha256=peer_lease.container_id_sha256,
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
