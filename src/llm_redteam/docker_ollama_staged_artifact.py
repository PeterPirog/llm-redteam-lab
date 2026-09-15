"""Compose staged-store, owned peer and exact Ollama artifact evidence."""

from __future__ import annotations

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_ollama_artifact import (
    DockerOllamaArtifactVerification,
    DockerOllamaArtifactVerifier,
    OllamaDockerArtifactProbeProfile,
)
from .docker_ollama_staged_peer import DockerOllamaStagedPeerProfile
from .docker_ollama_staged_peer_supervisor import DockerOllamaStagedPeerLease
from .docker_supervisor import DockerCommandRunner
from .domain import StrictModel
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import PreparedOllamaModelStore

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerOllamaStagedArtifactBinding(StrictModel):
    """Stable proof that one exact staged store became one exact runtime artifact."""

    version: int = Field(ge=1, default=1)
    staged_store_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    staged_peer_lease_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    staging_attestation_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_verification_proof_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOllamaStagedArtifactVerifier:
    """Verify one complete staged-store -> peer -> exact-artifact evidence chain."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 30.0,
    ) -> None:
        self._artifact_verifier = DockerOllamaArtifactVerifier(
            runner,
            command_timeout_seconds=command_timeout_seconds,
        )

    def verify(
        self,
        *,
        peer_profile: DockerOllamaStagedPeerProfile,
        peer_lease: DockerOllamaStagedPeerLease,
        staged_store: PreparedOllamaModelStore,
        contract: OllamaArtifactContract,
        probe_profile: OllamaDockerArtifactProbeProfile,
    ) -> DockerOllamaStagedArtifactBinding:
        """Fail closed unless every static and runtime identity agrees exactly."""

        _validate_staged_chain(
            peer_profile=peer_profile,
            peer_lease=peer_lease,
            staged_store=staged_store,
            contract=contract,
            probe_profile=probe_profile,
        )
        artifact_verification = self._artifact_verifier.verify(
            peer_profile=peer_profile,
            peer_lease=peer_lease.peer,
            contract=contract,
            probe_profile=probe_profile,
        )
        _validate_runtime_artifact(
            staged_store=staged_store,
            peer_lease=peer_lease,
            verification=artifact_verification,
        )
        return DockerOllamaStagedArtifactBinding(
            staged_store_identity_sha256=staged_store.identity.identity_sha256,
            staged_peer_lease_proof_sha256=peer_lease.proof_sha256,
            staging_attestation_proof_sha256=peer_lease.staging.proof_sha256,
            peer_profile_sha256=peer_profile.profile_sha256,
            container_id_sha256=peer_lease.peer.container_id_sha256,
            artifact_identity_sha256=(
                artifact_verification.artifact.identity.identity_sha256
            ),
            artifact_verification_proof_sha256=artifact_verification.proof_sha256,
        )


def _validate_staged_chain(
    *,
    peer_profile: DockerOllamaStagedPeerProfile,
    peer_lease: DockerOllamaStagedPeerLease,
    staged_store: PreparedOllamaModelStore,
    contract: OllamaArtifactContract,
    probe_profile: OllamaDockerArtifactProbeProfile,
) -> None:
    store_identity = staged_store.identity
    if peer_profile.staged_store_identity_sha256 != store_identity.identity_sha256:
        raise ValueError("peer profile does not bind the staged store")
    if peer_lease.staged_store_identity_sha256 != store_identity.identity_sha256:
        raise ValueError("staged peer lease does not bind the staged store")
    if peer_lease.staging.staged_store_identity_sha256 != store_identity.identity_sha256:
        raise ValueError("staging attestation does not bind the staged store")
    if peer_lease.peer.profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("staged peer lease does not bind the peer profile")
    if peer_lease.staging.peer_profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("staging attestation does not bind the peer profile")
    if peer_lease.staging.container_id_sha256 != peer_lease.peer.container_id_sha256:
        raise ValueError("staging attestation does not bind the leased container")
    if store_identity.model_id != peer_profile.model_id:
        raise ValueError("staged store model does not match peer profile")
    if contract.model_id != peer_profile.model_id:
        raise ValueError("artifact contract model does not match peer profile")
    if contract.manifest_digest != store_identity.manifest_digest:
        raise ValueError("artifact contract digest does not match staged store manifest")
    if probe_profile.peer_profile_sha256 != peer_profile.profile_sha256:
        raise ValueError("artifact probe profile does not bind the staged peer profile")


def _validate_runtime_artifact(
    *,
    staged_store: PreparedOllamaModelStore,
    peer_lease: DockerOllamaStagedPeerLease,
    verification: DockerOllamaArtifactVerification,
) -> None:
    if verification.container_id_sha256 != peer_lease.peer.container_id_sha256:
        raise ValueError("artifact verification does not bind the staged peer container")
    if verification.peer_profile_sha256 != peer_lease.peer.profile_sha256:
        raise ValueError("artifact verification does not bind the staged peer profile")
    if (
        verification.artifact.identity.artifact_digest
        != staged_store.identity.manifest_digest
    ):
        raise ValueError("runtime artifact digest does not match staged store manifest")
