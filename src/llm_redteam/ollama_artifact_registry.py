"""Versioned registry for predeclared Ollama model artifact contracts.

The registry is an operator/runtime edge. It converts a versioned YAML declaration and
one later ``/api/tags`` payload into provider-neutral ``ModelArtifactIdentity`` objects.
It performs no inference and does not make HTTP requests itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactIdentity, ModelArtifactObservation
from .ollama_artifact import OllamaArtifactContract

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"


class OllamaArtifactRegistryEntry(StrictModel):
    """One predeclared manifest digest plus non-authoritative operator role hints."""

    digest: str = Field(pattern=_SHA256_PATTERN)
    roles: tuple[str, ...] = ()

    @model_validator(mode="after")
    def roles_are_nonempty_unique_tokens(self) -> OllamaArtifactRegistryEntry:
        if any(not role.strip() for role in self.roles):
            raise ValueError("artifact registry roles cannot contain empty values")
        if len(self.roles) != len(set(self.roles)):
            raise ValueError("artifact registry roles must be unique")
        return self


class OllamaArtifactRegistry(StrictModel):
    """Predeclared set of Ollama artifact contracts used during local qualification."""

    version: int = Field(ge=1)
    provider: Literal["ollama"] = "ollama"
    source: str = Field(min_length=1, max_length=256)
    require_local: bool = True
    artifacts: dict[str, OllamaArtifactRegistryEntry]

    @model_validator(mode="after")
    def artifacts_are_nonempty_and_well_named(self) -> OllamaArtifactRegistry:
        if not self.artifacts:
            raise ValueError("Ollama artifact registry cannot be empty")
        if any(not model_id.strip() for model_id in self.artifacts):
            raise ValueError("Ollama artifact registry contains an empty model ID")
        return self

    @property
    def registry_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "provider": self.provider,
                "source": self.source,
                "require_local": self.require_local,
                "artifacts": {
                    model_id: {
                        "digest": entry.digest,
                        "roles": sorted(entry.roles),
                    }
                    for model_id, entry in sorted(self.artifacts.items())
                },
            }
        )

    def contract_for(self, model_id: str) -> OllamaArtifactContract:
        try:
            entry = self.artifacts[model_id]
        except KeyError as exc:
            raise ValueError(f"model is not declared in Ollama artifact registry: {model_id}") from exc
        return OllamaArtifactContract(
            model_id=model_id,
            expected_manifest_digest=entry.digest,
            require_local=self.require_local,
        )

    def verify_tags_response(
        self,
        payload: object,
        *,
        required_model_ids: tuple[str, ...],
    ) -> OllamaArtifactQualification:
        """Verify exactly the requested declared models against one inventory payload."""

        if not required_model_ids:
            raise ValueError("Ollama artifact qualification requires at least one model")
        if len(required_model_ids) != len(set(required_model_ids)):
            raise ValueError("required Ollama model IDs must be unique")

        observations = tuple(
            self.contract_for(model_id).verify_tags_response(payload)
            for model_id in sorted(required_model_ids)
        )
        return OllamaArtifactQualification(
            registry_sha256=self.registry_sha256,
            observations=observations,
        )


class OllamaArtifactQualification(StrictModel):
    """Hash-bound evidence from one registry and one verified Ollama inventory payload."""

    version: int = Field(ge=1, default=1)
    registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observations: tuple[ModelArtifactObservation, ...]

    @model_validator(mode="after")
    def observations_are_nonempty_unique_ollama_models(self) -> OllamaArtifactQualification:
        if not self.observations:
            raise ValueError("Ollama artifact qualification cannot be empty")
        model_ids = [observation.identity.model_id for observation in self.observations]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("Ollama artifact qualification model IDs must be unique")
        if any(observation.identity.provider_id != "ollama" for observation in self.observations):
            raise ValueError("Ollama artifact qualification contains a non-Ollama artifact")
        return self

    @property
    def ordered_observations(self) -> tuple[ModelArtifactObservation, ...]:
        return tuple(
            sorted(self.observations, key=lambda observation: observation.identity.model_id)
        )

    @property
    def qualification_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "registry_sha256": self.registry_sha256,
                "observations": [
                    observation.proof_sha256 for observation in self.ordered_observations
                ],
            }
        )

    @property
    def artifact_map(self) -> dict[tuple[str, str], ModelArtifactIdentity]:
        return {
            (observation.identity.provider_id, observation.identity.model_id): observation.identity
            for observation in self.ordered_observations
        }


def load_ollama_artifact_registry(path: str | Path) -> OllamaArtifactRegistry:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Ollama artifact registry does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return OllamaArtifactRegistry.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid Ollama artifact registry {source}: {exc}") from exc
