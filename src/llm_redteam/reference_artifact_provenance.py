"""Stage-aware execution provenance for local reference evaluation."""

from __future__ import annotations

from .model_inventory import LocalOnlyAdmissionReport
from .reference_artifact_qualification import ReferenceArtifactQualificationReport
from .reference_evaluation import ReferenceEvaluationStage
from .storage.execution_provenance_repository import (
    ExecutionProvenanceDescriptor,
    build_execution_provenance_descriptor,
)

LOCAL_MODEL_ADMISSION_PROVENANCE_KIND = "local_model_admission_v1"
MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND = "model_artifact_qualification_v1"


def artifact_qualification_provenance(
    report: ReferenceArtifactQualificationReport,
) -> ExecutionProvenanceDescriptor:
    """Bind a verified exact-artifact report into immutable campaign provenance."""

    return build_execution_provenance_descriptor(
        kind=MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
        payload=report.model_dump(mode="json"),
    )


def build_reference_execution_provenance(
    *,
    stage: ReferenceEvaluationStage,
    admission: LocalOnlyAdmissionReport,
    artifact_qualification: ReferenceArtifactQualificationReport | None = None,
) -> tuple[ExecutionProvenanceDescriptor, ...]:
    """Build stage-appropriate provenance and fail closed for qualification runs."""

    admission_descriptor = build_execution_provenance_descriptor(
        kind=LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
        payload=admission.model_dump(mode="json"),
    )
    if artifact_qualification is None:
        if stage == ReferenceEvaluationStage.POLICY_QUALIFICATION:
            raise ValueError(
                "POLICY_QUALIFICATION requires exact local model artifact qualification"
            )
        return (admission_descriptor,)

    if artifact_qualification.local_admission_proof_sha256 != admission.proof_sha256:
        raise ValueError("artifact qualification is not bound to this local admission proof")

    return (
        admission_descriptor,
        artifact_qualification_provenance(artifact_qualification),
    )
