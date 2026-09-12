"""Stable model-artifact identity for reproducible Blue measurements.

A human-readable model name is not sufficient measurement identity: mutable tags may
resolve to different weights/configuration over time. This module records a provider-
reported content digest separately from runtime/application configuration and provides a
small binding contract for model-service peers.
"""

from __future__ import annotations

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_HASH_PATTERN = r"^[0-9a-f]{64}$"


class ModelArtifactIdentity(StrictModel):
    """Stable content identity for one concrete model artifact."""

    version: int = Field(ge=1, default=1)
    provider_id: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    artifact_size_bytes: int = Field(ge=0)
    local_artifact: bool
    format: str | None = None
    family: str | None = None
    parameter_size: str | None = None
    quantization_level: str | None = None

    @property
    def identity_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class ModelArtifactObservation(StrictModel):
    """Hash-safe evidence that a provider inventory resolved to one artifact identity."""

    identity: ModelArtifactIdentity
    source_kind: str = Field(min_length=1, max_length=128)
    source_response_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class ModelPeerArtifactBinding(StrictModel):
    """Stable composition of a model peer policy and one exact model artifact."""

    version: int = Field(ge=1, default=1)
    peer_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    provider_id: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def binding_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def bind_model_peer_artifact(
    *,
    peer_profile_sha256: str,
    peer_provider_id: str,
    peer_model_id: str,
    artifact: ModelArtifactIdentity,
) -> ModelPeerArtifactBinding:
    """Fail closed unless peer configuration and artifact identity name the same model."""

    if artifact.provider_id != peer_provider_id:
        raise ValueError("model artifact provider does not match model-peer provider")
    if artifact.model_id != peer_model_id:
        raise ValueError("model artifact ID does not match model-peer model ID")
    return ModelPeerArtifactBinding(
        peer_profile_sha256=peer_profile_sha256,
        provider_id=peer_provider_id,
        model_id=peer_model_id,
        artifact_identity_sha256=artifact.identity_sha256,
    )
