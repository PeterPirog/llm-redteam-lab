"""Artifact-qualified provenance for model-backed Judge policy descriptors."""

from __future__ import annotations

from collections.abc import Mapping

from ..model_artifact import ModelArtifactIdentity
from ..model_role_artifact import (
    ModelRoleQualificationRequest,
    QualifiedModelRoleSet,
    bind_policy_descriptor_to_model_roles,
    qualify_model_roles,
)
from ..model_roles import ModelRole, ModelsConfig


def qualify_judge_model_roles(
    *,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    semantic: bool = True,
    multimodal: bool = False,
) -> QualifiedModelRoleSet:
    """Resolve and artifact-qualify exactly the model-backed Judge roles in use."""

    requests: list[ModelRoleQualificationRequest] = []
    if semantic:
        requests.append(
            ModelRoleQualificationRequest(
                role=ModelRole.JUDGE_SEMANTIC,
                required_capabilities=frozenset({"text"}),
            )
        )
    if multimodal:
        requests.append(
            ModelRoleQualificationRequest(
                role=ModelRole.JUDGE_MULTIMODAL,
                required_capabilities=frozenset({"text", "vision"}),
            )
        )
    if not requests:
        raise ValueError("artifact-qualified Judge provenance requires a model-backed Judge role")

    return qualify_model_roles(
        models=models,
        artifacts=artifacts,
        requests=tuple(requests),
    )


def build_artifact_qualified_judge_policy_descriptor(
    *,
    policy_descriptor: Mapping[str, object],
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    semantic: bool = True,
    multimodal: bool = False,
) -> dict[str, object]:
    """Bind an existing Judge policy descriptor to the exact Judge model artifacts."""

    qualified = qualify_judge_model_roles(
        models=models,
        artifacts=artifacts,
        semantic=semantic,
        multimodal=multimodal,
    )
    required: list[str] = []
    if semantic:
        required.append(ModelRole.JUDGE_SEMANTIC.value)
    if multimodal:
        required.append(ModelRole.JUDGE_MULTIMODAL.value)
    return bind_policy_descriptor_to_model_roles(
        policy_descriptor=policy_descriptor,
        qualified_roles=qualified,
        required_route_ids=tuple(required),
    )
