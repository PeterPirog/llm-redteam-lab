"""Operator wiring for the first real HAL instrumentation smoke.

This module is the final composition layer between persisted evidence documents and the
runtime supervisors. It deliberately separates:

1. runtime-pin capture (local filesystem + Docker image inspection, no inference), and
2. live smoke runner construction/execution.

The operator must still explicitly cross the runtime boundary from the CLI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field

from .disposable_workspace import DisposableWorkspaceSupervisor
from .docker_model_network_supervisor import DockerModelNetworkSupervisor
from .docker_networked_opencode_supervisor import DockerNetworkedOpenCodeSupervisor
from .docker_networked_supervisor import DockerNetworkedAgentSupervisor
from .docker_ollama_staged_artifact import DockerOllamaStagedArtifactVerifier
from .docker_ollama_staged_peer_supervisor import DockerOllamaStagedPeerSupervisor
from .docker_opencode_environment import DockerNetworkedOpenCodeEnvironmentAttestor
from .docker_supervisor import (
    DockerCommandRunner,
    DockerProcessSupervisor,
    SubprocessDockerCommandRunner,
)
from .domain import StrictModel
from .hal_smoke_campaign import HalSmokeCampaignRunner
from .hal_smoke_preflight import HalSmokeOfflineComposition, HalSmokeRuntimePins
from .hal_smoke_runtime import HalSmokeBlueInfrastructureSupervisor
from .hal_smoke_scenario import (
    HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256,
    build_hal_smoke_judge,
    build_hal_smoke_workspace_verifiers,
    hal_smoke_judge_policy_descriptor,
)
from .model_client import OpenAICompatibleRoleModelClient
from .model_inventory import LocalOnlyAdmissionReport
from .model_roles import ModelsConfig
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import (
    OllamaModelStagingSupervisor,
    PreparedOllamaModelStore,
)
from .red_runtime_artifact import HttpxLocalOllamaTagsProbe
from .reference_artifact_qualification import ReferenceArtifactQualificationReport
from .runtime_config import BudgetConfigDocument
from .storage.repository import ExperimentRepository

_IMAGE_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"


class DockerImagePinObservation(StrictModel):
    """Hash-safe result of verifying one digest-pinned local Docker image."""

    image_ref: str = Field(min_length=1)
    image_id: str = Field(pattern=_IMAGE_ID_PATTERN)


@dataclass(frozen=True, slots=True)
class CapturedHalSmokeRuntime:
    """Prepared Blue stage plus immutable runtime pins captured on HAL."""

    staged_store: PreparedOllamaModelStore
    runtime_pins: HalSmokeRuntimePins
    opencode_image: DockerImagePinObservation
    ollama_peer_image: DockerImagePinObservation


def capture_hal_smoke_runtime(
    *,
    blue_artifact_contract: OllamaArtifactContract,
    manifest_relative_path: str,
    source_models_root: str | Path,
    staging_root: str | Path,
    opencode_application_version: str,
    opencode_image_ref: str,
    ollama_peer_image_ref: str,
    docker_runner: DockerCommandRunner | None = None,
) -> CapturedHalSmokeRuntime:
    """Stage exact Blue bytes and resolve local image IDs without model inference."""

    if not blue_artifact_contract.require_local:
        raise ValueError("HAL runtime capture requires a local-only Blue artifact contract")
    if not opencode_application_version.strip():
        raise ValueError("OpenCode application version must be non-empty")

    staging = OllamaModelStagingSupervisor(
        source_models_root=source_models_root,
        staging_root=staging_root,
    )
    staged_store = staging.stage(
        contract=blue_artifact_contract,
        manifest_relative_path=manifest_relative_path,
    )

    runner = docker_runner or SubprocessDockerCommandRunner()
    opencode_image = _capture_docker_image_pin(
        runner,
        image_ref=opencode_image_ref,
        label="OpenCode",
    )
    ollama_peer_image = _capture_docker_image_pin(
        runner,
        image_ref=ollama_peer_image_ref,
        label="Ollama peer",
    )
    runtime_pins = HalSmokeRuntimePins(
        staged_blue_store_identity=staged_store.identity,
        opencode_application_version=opencode_application_version.strip(),
        opencode_image_ref=opencode_image.image_ref,
        opencode_image_id=opencode_image.image_id,
        ollama_peer_image_ref=ollama_peer_image.image_ref,
        ollama_peer_image_id=ollama_peer_image.image_id,
    )
    return CapturedHalSmokeRuntime(
        staged_store=staged_store,
        runtime_pins=runtime_pins,
        opencode_image=opencode_image,
        ollama_peer_image=ollama_peer_image,
    )


def rebuild_captured_staged_store(
    *,
    runtime_pins: HalSmokeRuntimePins,
    blue_artifact_contract: OllamaArtifactContract,
    manifest_relative_path: str,
    source_models_root: str | Path,
    staging_root: str | Path,
) -> PreparedOllamaModelStore:
    """Reverify/reuse the exact stage and require it to match persisted runtime pins."""

    staged = OllamaModelStagingSupervisor(
        source_models_root=source_models_root,
        staging_root=staging_root,
    ).stage(
        contract=blue_artifact_contract,
        manifest_relative_path=manifest_relative_path,
    )
    if staged.identity != runtime_pins.staged_blue_store_identity:
        raise ValueError("live staged Blue store differs from persisted HAL runtime pins")
    return staged


def build_hal_smoke_live_runner(
    *,
    composition: HalSmokeOfflineComposition,
    admission: LocalOnlyAdmissionReport,
    qualification: ReferenceArtifactQualificationReport,
    models: ModelsConfig,
    staged_store: PreparedOllamaModelStore,
    blue_artifact_contract: OllamaArtifactContract,
    workspace_template_root: str | Path,
    workspace_sandbox_root: str | Path,
    repository: ExperimentRepository,
    budgets: BudgetConfigDocument,
    network_name: str,
    docker_runner: DockerCommandRunner | None = None,
    provider_id: str = "hal-smoke-opencode",
    health_python_executable: str = "python",
) -> HalSmokeCampaignRunner:
    """Wire real HAL supervisors into the audited smoke orchestration."""

    _require_secret_environment(composition)
    runner = docker_runner or SubprocessDockerCommandRunner()

    network_supervisor = DockerModelNetworkSupervisor(runner)
    peer_supervisor = DockerOllamaStagedPeerSupervisor(runner)
    artifact_verifier = DockerOllamaStagedArtifactVerifier(runner)
    blue_infrastructure = HalSmokeBlueInfrastructureSupervisor(
        network_supervisor=network_supervisor,
        peer_supervisor=peer_supervisor,
        artifact_verifier=artifact_verifier,
    )

    agent_supervisor = DockerNetworkedAgentSupervisor(
        network_supervisor=network_supervisor,
        runner=runner,
    )
    environment_attestor = DockerNetworkedOpenCodeEnvironmentAttestor(runner)
    health_supervisor = DockerProcessSupervisor(runner)
    opencode_runtime = DockerNetworkedOpenCodeSupervisor(
        agent_supervisor=agent_supervisor,
        environment_attestor=environment_attestor,
        health_supervisor=health_supervisor,
    )

    workspace_supervisor = DisposableWorkspaceSupervisor(
        template_root=workspace_template_root,
        sandbox_root=workspace_sandbox_root,
    )
    red_client = OpenAICompatibleRoleModelClient(models)
    red_probe = HttpxLocalOllamaTagsProbe()

    return HalSmokeCampaignRunner(
        composition=composition,
        admission=admission,
        qualification=qualification,
        models=models,
        staged_store=staged_store,
        blue_artifact_contract=blue_artifact_contract,
        blue_infrastructure_supervisor=blue_infrastructure,
        red_tags_probe=red_probe,
        workspace_supervisor=workspace_supervisor,
        opencode_runtime_supervisor=opencode_runtime,
        docker_runner=runner,
        red_model_client=red_client,
        judge=build_hal_smoke_judge(),
        repository=repository,
        budgets=budgets,
        judge_policy_descriptor=hal_smoke_judge_policy_descriptor(),
        state_verifier_factory=build_hal_smoke_workspace_verifiers,
        state_verifier_policy_sha256=HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256,
        network_name=network_name,
        provider_id=provider_id,
        health_python_executable=health_python_executable,
    )


def _capture_docker_image_pin(
    runner: DockerCommandRunner,
    *,
    image_ref: str,
    label: str,
) -> DockerImagePinObservation:
    if "@sha256:" not in image_ref:
        raise ValueError(f"{label} image ref must be digest-pinned")
    result = runner.run(
        ("docker", "image", "inspect", "--format", "{{.Id}}", image_ref),
        timeout_seconds=30.0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{label} image is not locally inspectable")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"{label} image inspect returned invalid output")
    return DockerImagePinObservation(image_ref=image_ref, image_id=lines[0])


def _require_secret_environment(composition: HalSmokeOfflineComposition) -> None:
    missing = [
        name
        for name in composition.opencode_agent.required_secret_env_names
        if not os.getenv(name)
    ]
    if missing:
        raise ValueError(
            "required OpenCode secret environment is absent: " + ", ".join(sorted(missing))
        )
