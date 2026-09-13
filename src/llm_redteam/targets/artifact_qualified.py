"""Provider-neutral binding of a Blue target to one exact model artifact.

A target application's configuration and the model weights it executes are separate pieces
of security-target identity. Mutable tags such as ``latest`` can preserve the configured
model name while resolving to different weights. This module composes the existing
``TargetIdentity`` with an independently verified ``ModelArtifactIdentity`` and delegates
execution to the original target adapter without changing its permissions or protocol.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ..agent_actions import canonical_json_hash
from ..domain import StrictModel, TargetIdentity
from ..model_artifact import ModelArtifactIdentity
from .base import TargetAdapter, TargetRequest, TargetResponse

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"


class TargetModelArtifactBinding(StrictModel):
    """Stable proof that one configured Blue target uses one exact model artifact."""

    version: int = Field(ge=1, default=1)
    target_id: str = Field(min_length=1)
    target_configuration_hash: str = Field(min_length=1)
    provider_id: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    local_artifact: bool
    require_local: bool = True

    @model_validator(mode="after")
    def local_requirement_is_satisfied(self) -> TargetModelArtifactBinding:
        if self.require_local and not self.local_artifact:
            raise ValueError("Blue target binding requires a local model artifact")
        return self

    @property
    def binding_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    @property
    def qualified_configuration_hash(self) -> str:
        """Compose application/runtime policy and exact weights into target identity."""

        return canonical_json_hash(
            {
                "version": self.version,
                "target_id": self.target_id,
                "base_configuration_hash": self.target_configuration_hash,
                "model_artifact_identity_sha256": self.artifact_identity_sha256,
                "binding_sha256": self.binding_sha256,
            }
        )


def bind_target_model_artifact(
    *,
    target: TargetIdentity,
    artifact: ModelArtifactIdentity,
    require_local: bool = True,
) -> TargetModelArtifactBinding:
    """Fail closed unless target configuration and artifact name the same model."""

    if target.provider != artifact.provider_id:
        raise ValueError("Blue target provider does not match model artifact provider")
    if target.model != artifact.model_id:
        raise ValueError("Blue target model ID does not match model artifact ID")
    if target.model_digest is not None and target.model_digest != artifact.artifact_digest:
        raise ValueError("Blue target existing model_digest conflicts with verified artifact")
    if require_local and not artifact.local_artifact:
        raise ValueError("Blue target requires a local model artifact, not a remote artifact")

    return TargetModelArtifactBinding(
        target_id=target.id,
        target_configuration_hash=target.configuration_hash,
        provider_id=artifact.provider_id,
        model_id=artifact.model_id,
        artifact_identity_sha256=artifact.identity_sha256,
        artifact_digest=artifact.artifact_digest,
        local_artifact=artifact.local_artifact,
        require_local=require_local,
    )


def qualify_target_identity(
    *,
    target: TargetIdentity,
    artifact: ModelArtifactIdentity,
    require_local: bool = True,
) -> TargetIdentity:
    """Return a target identity whose configuration hash is exact-artifact sensitive."""

    binding = bind_target_model_artifact(
        target=target,
        artifact=artifact,
        require_local=require_local,
    )
    return target.model_copy(
        update={
            "model_digest": artifact.artifact_digest,
            "configuration_hash": binding.qualified_configuration_hash,
        }
    )


class ArtifactQualifiedTarget:
    """Delegate a Blue target while exposing exact-artifact-qualified identity."""

    def __init__(
        self,
        target: TargetAdapter,
        artifact: ModelArtifactIdentity,
        *,
        require_local: bool = True,
    ) -> None:
        self._target = target
        self._base_identity = target.identity
        self.artifact = artifact
        self.binding = bind_target_model_artifact(
            target=self._base_identity,
            artifact=artifact,
            require_local=require_local,
        )
        self._identity = self._base_identity.model_copy(
            update={
                "model_digest": artifact.artifact_digest,
                "configuration_hash": self.binding.qualified_configuration_hash,
            }
        )

    @property
    def identity(self) -> TargetIdentity:
        """Exact security-target identity including application config and model weights."""

        return self._identity

    @property
    def base_identity(self) -> TargetIdentity:
        """Original application/runtime identity before artifact composition."""

        return self._base_identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        """Reject post-admission target drift, then delegate the unchanged request."""

        if self._target.identity != self._base_identity:
            raise ValueError("Blue target runtime identity changed after artifact admission")
        return await self._target.execute(request)
