"""Qualification-grade binding of admitted HAL models to exact Ollama artifacts.

Local admission proves that execution is routed through the trusted HAL boundary and that
selected Ollama records are not remote proxies. Policy qualification needs a stronger
reproducibility contract: every admitted model must be predeclared by exact manifest digest
and independently verified against a saved local ``/api/tags`` snapshot before inference.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactObservation
from .model_inventory import LocalOnlyAdmissionReport, OpenWebUIOllamaInventory
from .ollama_artifact import OllamaArtifactContract

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OllamaArtifactContractSet(StrictModel):
    """Predeclared exact artifact contracts for one qualification execution."""

    version: int = Field(ge=1, default=1)
    contracts: tuple[OllamaArtifactContract, ...]

    @model_validator(mode="after")
    def model_ids_are_unique(self) -> OllamaArtifactContractSet:
        ids = [contract.model_id for contract in self.contracts]
        if len(ids) != len(set(ids)):
            raise ValueError("artifact contract model IDs must be unique")
        if not ids:
            raise ValueError("artifact contract set cannot be empty")
        return self

    @property
    def model_ids(self) -> tuple[str, ...]:
        return tuple(sorted(contract.model_id for contract in self.contracts))

    @property
    def contract_set_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "contracts": [
                    {
                        "model_id": contract.model_id,
                        "contract_sha256": contract.contract_sha256,
                    }
                    for contract in sorted(self.contracts, key=lambda item: item.model_id)
                ],
            }
        )


class QualifiedArtifactBinding(StrictModel):
    """Hash-safe proof for one admitted model and one exact local artifact."""

    model_id: str = Field(min_length=1)
    contract_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_observation_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ReferenceArtifactQualificationReport(StrictModel):
    """Stable proof that every admitted model resolved to its predeclared artifact."""

    version: int = Field(ge=1, default=1)
    local_admission_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    contract_set_sha256: str = Field(pattern=_HASH_PATTERN)
    tags_snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    bindings: tuple[QualifiedArtifactBinding, ...]

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
    tags_snapshot: object,
) -> ReferenceArtifactQualificationReport:
    """Fail closed unless every admitted HAL model has one exact verified artifact."""

    admitted_ids = admission.admitted_model_ids
    if contracts.model_ids != admitted_ids:
        missing = sorted(set(admitted_ids).difference(contracts.model_ids))
        extra = sorted(set(contracts.model_ids).difference(admitted_ids))
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise ValueError(
            "artifact contracts must exactly cover admitted model IDs"
            + (": " + "; ".join(details) if details else "")
        )

    if not isinstance(tags_snapshot, dict):
        raise ValueError("Ollama tags snapshot must be a JSON object")
    tags_snapshot_sha256 = canonical_json_hash(tags_snapshot)

    by_id = {contract.model_id: contract for contract in contracts.contracts}
    bindings: list[QualifiedArtifactBinding] = []
    for model_id in admitted_ids:
        contract = by_id[model_id]
        observation: ModelArtifactObservation = contract.verify_tags_response(tags_snapshot)
        admitted_record = inventory.require_local(model_id)
        identity = observation.identity
        if identity.artifact_digest != admitted_record.artifact_digest:
            raise ValueError(
                f"artifact digest disagrees between admission inventory and /api/tags: {model_id}"
            )
        if identity.artifact_size_bytes != admitted_record.artifact_size_bytes:
            raise ValueError(
                f"artifact size disagrees between admission inventory and /api/tags: {model_id}"
            )
        bindings.append(
            QualifiedArtifactBinding(
                model_id=model_id,
                contract_sha256=contract.contract_sha256,
                artifact_identity_sha256=identity.identity_sha256,
                artifact_observation_sha256=observation.proof_sha256,
                artifact_digest=identity.artifact_digest,
            )
        )

    return ReferenceArtifactQualificationReport(
        local_admission_proof_sha256=admission.proof_sha256,
        contract_set_sha256=contracts.contract_set_sha256,
        tags_snapshot_sha256=tags_snapshot_sha256,
        bindings=tuple(bindings),
    )


def load_ollama_artifact_contracts(path: str | Path) -> OllamaArtifactContractSet:
    """Load a YAML/JSON exact-artifact contract document."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"artifact contract file does not exist: {source}")
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"artifact contract file is not valid YAML/JSON: {source}") from exc
    if not isinstance(payload, dict):
        raise ValueError("artifact contract document must be an object")
    return OllamaArtifactContractSet.model_validate(payload)


def load_ollama_tags_snapshot(path: str | Path) -> object:
    """Load a saved local Ollama ``/api/tags`` response without contacting a daemon."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Ollama tags snapshot does not exist: {source}")
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Ollama tags snapshot is not valid JSON: {source}") from exc
