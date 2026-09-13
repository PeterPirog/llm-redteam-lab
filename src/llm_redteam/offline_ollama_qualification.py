"""Offline qualification of predeclared Ollama artifacts from a saved `/api/tags` payload.

The workflow deliberately separates artifact verification from model inference. Operators may
capture the local Ollama inventory once, then verify it against a predeclared contract document
without contacting Ollama again and without sending any prompt to any model.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactIdentity, ModelArtifactObservation
from .ollama_artifact import OllamaArtifactContract

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OllamaArtifactDeclaration(StrictModel):
    """One predeclared artifact plus operator-facing role labels."""

    digest: str = Field(min_length=1)
    roles: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def roles_are_unique_and_non_empty(self) -> OllamaArtifactDeclaration:
        if any(not role.strip() for role in self.roles):
            raise ValueError("Ollama artifact roles must be non-empty")
        if len(self.roles) != len(set(self.roles)):
            raise ValueError("Ollama artifact roles must be unique per model")
        return self


class OllamaArtifactContractDocument(StrictModel):
    """Versioned local artifact declarations compatible with the smoke profile contract."""

    version: int = Field(ge=1)
    provider: str = Field(min_length=1)
    source: str = Field(min_length=1)
    require_local: bool = True
    artifacts: dict[str, OllamaArtifactDeclaration] = Field(min_length=1)

    @model_validator(mode="after")
    def local_ollama_document_is_required(self) -> OllamaArtifactContractDocument:
        if self.provider.casefold() != "ollama":
            raise ValueError("offline artifact qualification currently supports provider=ollama")
        if not self.require_local:
            raise ValueError("offline local artifact qualification requires require_local=true")
        if any(not model_id.strip() for model_id in self.artifacts):
            raise ValueError("Ollama artifact model IDs must be non-empty")
        return self

    @property
    def contracts_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class VerifiedOllamaArtifact(StrictModel):
    """One verified declaration with its provider-neutral artifact observation."""

    model_id: str = Field(min_length=1)
    roles: tuple[str, ...] = Field(min_length=1)
    contract_sha256: str = Field(pattern=_HASH_PATTERN)
    observation: ModelArtifactObservation

    @property
    def identity(self) -> ModelArtifactIdentity:
        return self.observation.identity


class OfflineOllamaQualificationReport(StrictModel):
    """Hash-bound output proving all declared local artifacts matched one saved inventory."""

    version: int = Field(ge=1, default=1)
    provider: str = "ollama"
    source: str = Field(min_length=1)
    require_local: bool = True
    inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    contracts_sha256: str = Field(pattern=_HASH_PATTERN)
    artifacts: tuple[VerifiedOllamaArtifact, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def report_is_canonical_and_local(self) -> OfflineOllamaQualificationReport:
        if self.provider != "ollama":
            raise ValueError("offline qualification report provider must be ollama")
        if not self.require_local:
            raise ValueError("offline qualification report must require local artifacts")
        model_ids = tuple(item.model_id for item in self.artifacts)
        if model_ids != tuple(sorted(model_ids)):
            raise ValueError("offline qualification artifacts must use canonical model ordering")
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("offline qualification artifacts must have unique model IDs")
        if any(not item.identity.local_artifact for item in self.artifacts):
            raise ValueError("offline qualification report cannot contain remote artifacts")
        return self

    @property
    def artifact_set_sha256(self) -> str:
        return canonical_json_hash(
            [
                {
                    "model_id": item.model_id,
                    "roles": list(item.roles),
                    "artifact_identity_sha256": item.identity.identity_sha256,
                    "contract_sha256": item.contract_sha256,
                }
                for item in self.artifacts
            ]
        )

    @property
    def report_sha256(self) -> str:
        return canonical_json_hash(
            {
                **self.model_dump(mode="json"),
                "artifact_set_sha256": self.artifact_set_sha256,
            }
        )

    def artifact_identities(self) -> dict[tuple[str, str], ModelArtifactIdentity]:
        """Expose verified provider/model keys for later provider-neutral admission."""

        return {
            (item.identity.provider_id, item.identity.model_id): item.identity
            for item in self.artifacts
        }


def load_ollama_artifact_contract_document(
    path: str | Path,
) -> OllamaArtifactContractDocument:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Ollama artifact contract document does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return OllamaArtifactContractDocument.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid Ollama artifact contract document {source}: {exc}") from exc


def load_ollama_tags_payload(path: str | Path) -> object:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"saved Ollama tags payload does not exist: {source}")
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid saved Ollama tags JSON {source}: {exc}") from exc


def qualify_saved_ollama_inventory(
    *,
    document: OllamaArtifactContractDocument,
    tags_payload: object,
) -> OfflineOllamaQualificationReport:
    """Verify every declaration against one saved inventory; fail the whole report on drift."""

    verified: list[VerifiedOllamaArtifact] = []
    for model_id, declaration in sorted(document.artifacts.items()):
        contract = OllamaArtifactContract(
            model_id=model_id,
            expected_manifest_digest=declaration.digest,
            require_local=document.require_local,
        )
        observation = contract.verify_tags_response(tags_payload)
        verified.append(
            VerifiedOllamaArtifact(
                model_id=model_id,
                roles=declaration.roles,
                contract_sha256=contract.contract_sha256,
                observation=observation,
            )
        )

    inventory_sha256 = canonical_json_hash(tags_payload)
    if any(item.observation.source_response_sha256 != inventory_sha256 for item in verified):
        raise RuntimeError("verified Ollama observations do not reference one inventory payload")

    return OfflineOllamaQualificationReport(
        source=document.source,
        require_local=document.require_local,
        inventory_sha256=inventory_sha256,
        contracts_sha256=document.contracts_sha256,
        artifacts=tuple(verified),
    )
