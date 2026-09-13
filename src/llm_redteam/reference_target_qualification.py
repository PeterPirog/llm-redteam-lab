"""Exact Blue model-artifact admission for local Reference Evaluation.

Reference Evaluation is a comparative measurement protocol, so a mutable model tag is not
sufficient target identity. This module requires a target whose ordinary application/runtime
identity has already been bound to one independently verified ``ModelArtifactIdentity``.
It then delegates the experiment unchanged to the existing paired reference runner.

The adapter performs no provider request and no model inference. Artifact verification must
happen before this boundary (for example through the Ollama manifest contract).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel, TargetIdentity
from .judges.base import Judge
from .model_client import RoleModelClient
from .model_roles import ModelsConfig
from .reference_evaluation import ReferenceEvaluationSpec, ReferenceEvaluationStage
from .reference_runner import ReferenceEvaluationRunResult, run_reference_evaluation_stage
from .runtime_config import BudgetConfigDocument
from .storage.repository import ExperimentRepository
from .targets.artifact_qualified import TargetModelArtifactBinding
from .targets.base import TargetAdapter, TargetRequest, TargetResponse

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"


@runtime_checkable
class ArtifactQualifiedTargetAdapter(TargetAdapter, Protocol):
    """Target adapter exposing the trusted exact-model binding used for admission."""

    @property
    def binding(self) -> TargetModelArtifactBinding: ...

    @property
    def base_identity(self) -> TargetIdentity: ...

    async def execute(self, request: TargetRequest) -> TargetResponse: ...


class ReferenceBlueArtifactAdmission(StrictModel):
    """Hash-bound proof of the exact Blue target admitted to one reference design."""

    version: int = Field(ge=1, default=1)
    experiment_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    target_configuration_hash: str = Field(pattern=_HASH_PATTERN)
    target_provider: str = Field(min_length=1)
    target_model: str = Field(min_length=1)
    model_artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    model_artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    model_artifact_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    local_artifact: bool
    require_local: bool

    @model_validator(mode="after")
    def local_reference_target_is_required(self) -> ReferenceBlueArtifactAdmission:
        if not self.require_local or not self.local_artifact:
            raise ValueError("Reference Evaluation requires an explicitly local Blue artifact")
        return self

    @property
    def admission_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class ArtifactQualifiedReferenceRunResult:
    """Reference result plus the exact Blue admission proof used before execution."""

    blue_admission: ReferenceBlueArtifactAdmission
    result: ReferenceEvaluationRunResult


def build_reference_blue_artifact_admission(
    *,
    spec: ReferenceEvaluationSpec,
    target: ArtifactQualifiedTargetAdapter,
) -> ReferenceBlueArtifactAdmission:
    """Fail closed unless the reference target is bound to one exact local artifact."""

    if not isinstance(target, ArtifactQualifiedTargetAdapter):
        raise TypeError("Reference Evaluation requires an artifact-qualified Blue target")

    identity = target.identity
    binding = target.binding
    base_identity = target.base_identity

    if binding.target_id != base_identity.id:
        raise ValueError("Blue artifact binding target_id does not match base target")
    if binding.target_configuration_hash != base_identity.configuration_hash:
        raise ValueError("Blue artifact binding no longer matches base target configuration")
    if identity.id != base_identity.id:
        raise ValueError("qualified Blue target ID drifted from admitted base target")
    if identity.provider != binding.provider_id or identity.model != binding.model_id:
        raise ValueError("qualified Blue target provider/model drifted from artifact binding")
    if identity.model_digest != binding.artifact_digest:
        raise ValueError("qualified Blue target digest does not match artifact binding")
    if identity.configuration_hash != binding.qualified_configuration_hash:
        raise ValueError("qualified Blue configuration hash does not match artifact binding")
    if not binding.require_local or not binding.local_artifact:
        raise ValueError("Reference Evaluation requires a verified local Blue artifact")

    if identity.target_class != spec.target_class:
        raise ValueError("qualified Blue target class does not match reference specification")
    if identity.target_mode != spec.target_mode:
        raise ValueError("qualified Blue target mode does not match reference specification")
    if identity.provider.casefold() != spec.required_target_provider.casefold():
        raise ValueError("qualified Blue provider does not match reference specification")

    return ReferenceBlueArtifactAdmission(
        experiment_id=spec.experiment_id,
        target_id=identity.id,
        target_configuration_hash=identity.configuration_hash,
        target_provider=identity.provider,
        target_model=identity.model,
        model_artifact_digest=binding.artifact_digest,
        model_artifact_identity_sha256=binding.artifact_identity_sha256,
        model_artifact_binding_sha256=binding.binding_sha256,
        local_artifact=binding.local_artifact,
        require_local=binding.require_local,
    )


async def run_artifact_qualified_reference_evaluation_stage(
    *,
    stage: ReferenceEvaluationStage,
    spec: ReferenceEvaluationSpec,
    cases: tuple,
    budgets: BudgetConfigDocument,
    models: ModelsConfig,
    target: ArtifactQualifiedTargetAdapter,
    judge: Judge,
    judge_policy_descriptor: object,
    red_model_client: RoleModelClient,
    repository: ExperimentRepository,
    run_id: str | None = None,
) -> ArtifactQualifiedReferenceRunResult:
    """Admit exact Blue identity, then delegate the unchanged paired reference runner."""

    admission = build_reference_blue_artifact_admission(spec=spec, target=target)
    result = await run_reference_evaluation_stage(
        stage=stage,
        spec=spec,
        cases=cases,
        budgets=budgets,
        models=models,
        target=target,
        judge=judge,
        judge_policy_descriptor=judge_policy_descriptor,
        red_model_client=red_model_client,
        repository=repository,
        run_id=run_id,
    )
    if result.preflight.target_configuration_hash != admission.target_configuration_hash:
        raise RuntimeError("reference runner target identity changed after Blue artifact admission")
    return ArtifactQualifiedReferenceRunResult(
        blue_admission=admission,
        result=result,
    )
