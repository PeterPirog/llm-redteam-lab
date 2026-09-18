"""Stable exact-artifact identity for model-backed Red roles.

Mutable provider model tags are not sufficient attacker identity. This module derives one
stable measurement binding from the exact qualified planner/mutator artifacts and their
role-configuration fingerprints. Fresh inventory/runtime observations remain separate
execution provenance.
"""

from __future__ import annotations

from .agent_actions import canonical_json_hash
from .reference_artifact_qualification import (
    QualifiedArtifactBinding,
    ReferenceArtifactQualificationReport,
)

_HASH_CHARS = frozenset("0123456789abcdef")


def red_artifact_measurement_binding_sha256(
    *,
    planner_model_id: str,
    planner_configuration_sha256: str,
    mutator_model_id: str,
    mutator_configuration_sha256: str,
    qualification: ReferenceArtifactQualificationReport,
) -> str:
    """Return the stable exact-artifact identity for the Red planner/mutator pair."""

    _require_sha256(planner_configuration_sha256, label="planner configuration")
    _require_sha256(mutator_configuration_sha256, label="mutator configuration")
    planner = _qualified_binding(qualification, planner_model_id)
    mutator = _qualified_binding(qualification, mutator_model_id)
    return red_artifact_measurement_binding_from_exact_artifacts(
        planner_model_id=planner_model_id,
        planner_configuration_sha256=planner_configuration_sha256,
        planner_artifact_digest=planner.artifact_digest,
        planner_artifact_identity_sha256=planner.artifact_identity_sha256,
        planner_contract_sha256=planner.contract_sha256,
        mutator_model_id=mutator_model_id,
        mutator_configuration_sha256=mutator_configuration_sha256,
        mutator_artifact_digest=mutator.artifact_digest,
        mutator_artifact_identity_sha256=mutator.artifact_identity_sha256,
        mutator_contract_sha256=mutator.contract_sha256,
    )


def red_artifact_measurement_binding_from_exact_artifacts(
    *,
    planner_model_id: str,
    planner_configuration_sha256: str,
    planner_artifact_digest: str,
    planner_artifact_identity_sha256: str,
    planner_contract_sha256: str,
    mutator_model_id: str,
    mutator_configuration_sha256: str,
    mutator_artifact_digest: str,
    mutator_artifact_identity_sha256: str,
    mutator_contract_sha256: str,
) -> str:
    """Hash exact role configuration and concrete planner/mutator artifact identities."""

    _require_sha256(planner_configuration_sha256, label="planner configuration")
    _require_sha256(mutator_configuration_sha256, label="mutator configuration")
    _require_sha256(planner_artifact_identity_sha256, label="planner artifact identity")
    _require_sha256(mutator_artifact_identity_sha256, label="mutator artifact identity")
    _require_sha256(planner_contract_sha256, label="planner artifact contract")
    _require_sha256(mutator_contract_sha256, label="mutator artifact contract")
    return canonical_json_hash(
        {
            "version": 1,
            "red_planner": {
                "model_id": planner_model_id,
                "configuration_sha256": planner_configuration_sha256,
                "artifact_digest": planner_artifact_digest,
                "artifact_identity_sha256": planner_artifact_identity_sha256,
                "contract_sha256": planner_contract_sha256,
            },
            "red_mutator": {
                "model_id": mutator_model_id,
                "configuration_sha256": mutator_configuration_sha256,
                "artifact_digest": mutator_artifact_digest,
                "artifact_identity_sha256": mutator_artifact_identity_sha256,
                "contract_sha256": mutator_contract_sha256,
            },
        }
    )


def _qualified_binding(
    report: ReferenceArtifactQualificationReport,
    model_id: str,
) -> QualifiedArtifactBinding:
    matches = [binding for binding in report.bindings if binding.model_id == model_id]
    if len(matches) != 1:
        raise ValueError(
            f"artifact qualification must contain exactly one binding for model: {model_id}"
        )
    return matches[0]


def _require_sha256(value: str, *, label: str) -> None:
    if len(value) != 64 or any(character not in _HASH_CHARS for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
