"""Execution-provenance adapter for reference model artifact qualification."""

from __future__ import annotations

from .reference_artifact_qualification import ReferenceArtifactQualificationReport
from .storage.execution_provenance_repository import (
    ExecutionProvenanceDescriptor,
    build_execution_provenance_descriptor,
)

MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND = "model_artifact_qualification_v1"


def artifact_qualification_provenance(
    report: ReferenceArtifactQualificationReport,
) -> ExecutionProvenanceDescriptor:
    """Bind a verified exact-artifact report into immutable campaign provenance."""

    return build_execution_provenance_descriptor(
        kind=MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
        payload=report.model_dump(mode="json"),
    )
