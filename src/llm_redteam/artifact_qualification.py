"""Qualification-grade binding of admitted HAL models to exact Ollama artifacts.

Local-only admission answers whether a selected model is a local HAL model reached through
an admitted route. Comparable qualification additionally needs stable artifact identity:
mutable model tags must resolve to predeclared Ollama manifest digests.

This module intentionally consumes saved control-plane evidence. It performs no model
inference and makes no network requests.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_inventory import LocalOnlyAdmissionReport, OpenWebUIOllamaInventory
from .ollama_artifact import OllamaArtifactContract

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"


class OllamaArtifactPin(StrictModel):
    """Predeclared manifest identity for one model used by a qualification run."""

    model_id: str = Field(min_length=1, max_length=256)
    manifest_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def digest_is_valid(self) -> OllamaArtifactPin:
        _ = self.contract.manifest_digest
        return self

    @property
    def contract(self) -> OllamaArtifactContract:
        return OllamaArtifactContract(
            model_id=self.model_id,
            expected_manifest_digest=self.manifest_digest,
            require_local=True,
        )


class OllamaArtifactContractSet(StrictModel):
    """Versioned set of operator-frozen local artifact expectations."""

    version: int = Field(ge=1, default=1)
    models: tuple[OllamaArtifactPin, ...]

    @model_validator(mode="after")
    def model_ids_are_unique(self) -> OllamaArtifactContractSet:
        model_ids = [item.model_id for item in self.models]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("artifact contract model IDs must be unique")
        if not self.models:
            raise ValueError("artifact contract set cannot be empty")
        return self

    def require(self, model_id: str) -> OllamaArtifactContract:
        matches = [item for item in self.models if item.model_id == model_id]
        if len(matches) != 1:
            raise ValueError(f"artifact contract must resolve exactly one model: {model_id}")
        return matches[0].contract


class QualifiedOllamaArtifactBinding(StrictModel):
    """Hash-safe proof that one admitted model resolved to one pinned artifact."""

    model_id: str = Field(min_length=1, max_length=256)
    labels: tuple[str, ...]
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    artifact_size_bytes: int = Field(ge=0)
    inventory_record_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_observation_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_contract_sha256: str = Field(pattern=_HASH_PATTERN)


class OllamaArtifactQualificationReport(StrictModel):
    """Qualification proof for all model artifacts actually admitted to one run."""

    version: int = Field(ge=1, default=1)
    admission_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    tags_snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    bindings: tuple[QualifiedOllamaArtifactBinding, ...]

    @property
    def qualified_model_ids(self) -> tuple[str, ...]:
        return tuple(binding.model_id for binding in self.bindings)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def qualify_admitted_ollama_artifacts(
    *,
    admission: LocalOnlyAdmissionReport,
    inventory: OpenWebUIOllamaInventory,
    contracts: OllamaArtifactContractSet,
    tags_snapshot: dict[str, object],
) -> OllamaArtifactQualificationReport:
    """Require exact pinned local artifact identity for every admitted model ID."""

    if admission.inventory_sha256 != inventory.inventory_sha256:
        raise ValueError("artifact qualification inventory does not match admission proof")

    labels_by_model: dict[str, set[str]] = {}
    record_hashes_by_model: dict[str, set[str]] = {}
    for binding in admission.bindings:
        labels_by_model.setdefault(binding.model_id, set()).add(binding.label)
        record_hashes_by_model.setdefault(binding.model_id, set()).add(
            binding.inventory_record_sha256
        )

    if not labels_by_model:
        raise ValueError("artifact qualification requires at least one admitted model")

    qualified: list[QualifiedOllamaArtifactBinding] = []
    for model_id in sorted(labels_by_model):
        record = inventory.require_local(model_id)
        expected_record_hashes = record_hashes_by_model[model_id]
        if expected_record_hashes != {record.record_sha256}:
            raise ValueError(
                f"artifact qualification inventory binding mismatch for model: {model_id}"
            )

        contract = contracts.require(model_id)
        observation = contract.verify_tags_response(tags_snapshot)
        identity = observation.identity

        if identity.artifact_digest != record.artifact_digest:
            raise ValueError(
                f"Ollama tags digest disagrees with admitted inventory for model: {model_id}"
            )
        if identity.artifact_size_bytes != record.artifact_size_bytes:
            raise ValueError(
                f"Ollama tags size disagrees with admitted inventory for model: {model_id}"
            )

        qualified.append(
            QualifiedOllamaArtifactBinding(
                model_id=model_id,
                labels=tuple(sorted(labels_by_model[model_id])),
                artifact_digest=identity.artifact_digest,
                artifact_size_bytes=identity.artifact_size_bytes,
                inventory_record_sha256=record.record_sha256,
                artifact_identity_sha256=identity.identity_sha256,
                artifact_observation_sha256=observation.proof_sha256,
                artifact_contract_sha256=contract.contract_sha256,
            )
        )

    return OllamaArtifactQualificationReport(
        admission_proof_sha256=admission.proof_sha256,
        inventory_sha256=inventory.inventory_sha256,
        tags_snapshot_sha256=canonical_json_hash(tags_snapshot),
        bindings=tuple(qualified),
    )


def load_ollama_artifact_contracts(path: str | Path) -> OllamaArtifactContractSet:
    """Load operator-frozen artifact pins from YAML."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"artifact contract file does not exist: {source}")
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        return OllamaArtifactContractSet.model_validate(payload)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid artifact contract file {source}: {exc}") from exc


def load_ollama_tags_snapshot(path: str | Path) -> dict[str, object]:
    """Load saved local Ollama `/api/tags` JSON, optionally from a Markdown fence."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Ollama tags snapshot does not exist: {source}")
    text = source.read_text(encoding="utf-8").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) < 3 or not lines[-1].strip().startswith("```"):
            raise ValueError("fenced Ollama tags snapshot is incomplete")
        text = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Ollama tags snapshot is not valid JSON: {source}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Ollama tags snapshot must be a JSON object")
    return payload
