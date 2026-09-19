"""Operator wiring for the first real HAL OpenCode instrumentation smoke.

Preparation is deterministic local file work plus content-addressed Blue staging. Execution
is the explicit boundary that touches Docker and the local HAL model runtimes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

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
from .hal_smoke_campaign import HalSmokeCampaignRunResult, HalSmokeCampaignRunner
from .hal_smoke_preflight import (
    HalSmokeOfflineComposition,
    build_hal_smoke_static_plan,
    compose_hal_smoke_offline,
    load_hal_smoke_runtime_pins,
)
from .hal_smoke_runtime import HalSmokeBlueInfrastructureSupervisor
from .hal_smoke_scenario import (
    HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256,
    build_hal_smoke_campaign_plan,
    build_hal_smoke_case,
    build_hal_smoke_judge,
    build_hal_smoke_workspace_verifiers,
    hal_smoke_judge_policy_descriptor,
)
from .model_client import OpenAICompatibleRoleModelClient
from .model_inventory import (
    LocalOnlyAdmissionReport,
    load_openwebui_ollama_inventory,
    validate_local_only_model_selection,
)
from .model_roles import ModelsConfig, load_models_config
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import (
    OllamaModelStagingSupervisor,
    PreparedOllamaModelStore,
)
from .red_runtime_artifact import HttpxLocalOllamaTagsProbe
from .reference_artifact_qualification import (
    ReferenceArtifactQualificationReport,
    load_ollama_artifact_contracts,
    load_ollama_tags_snapshot,
    qualify_admitted_ollama_artifacts,
)
from .runtime_config import BudgetConfigDocument, load_budget_config
from .storage.repository import ExperimentRepository


@dataclass(frozen=True, slots=True)
class HalSmokeOperatorInputs:
    """All explicit local files/paths needed to prepare the first HAL smoke."""

    models_config: Path
    model_inventory: Path
    artifact_contracts: Path
    ollama_tags_snapshot: Path
    runtime_pins: Path
    source_ollama_models_root: Path
    staging_root: Path
    blue_manifest_relative_path: str
    workspace_template_root: Path
    workspace_sandbox_root: Path
    budget_config: Path
    blue_model_id: str = "ornith-1.5:9b"


@dataclass(frozen=True, slots=True)
class PreparedHalSmokeOperator:
    """Fully checked offline operator state before Docker/model runtime access."""

    models: ModelsConfig
    admission: LocalOnlyAdmissionReport
    qualification: ReferenceArtifactQualificationReport
    composition: HalSmokeOfflineComposition
    staged_store: PreparedOllamaModelStore
    blue_artifact_contract: OllamaArtifactContract
    budgets: BudgetConfigDocument
    workspace_supervisor: DisposableWorkspaceSupervisor


@dataclass(slots=True)
class LiveHalSmokeRuntime:
    """Runtime clients plus the fully wired smoke campaign runner."""

    runner: HalSmokeCampaignRunner
    red_client: OpenAICompatibleRoleModelClient
    red_tags_probe: HttpxLocalOllamaTagsProbe

    async def aclose(self) -> None:
        errors: list[BaseException] = []
        try:
            await self.red_client.aclose()
        except BaseException as exc:
            errors.append(exc)
        try:
            await self.red_tags_probe.aclose()
        except BaseException as exc:
            errors.append(exc)
        if errors:
            raise RuntimeError("HAL smoke runtime client cleanup failed") from errors[0]


@dataclass(frozen=True, slots=True)
class HalSmokeOperatorRunResult:
    """Real smoke result plus the exact offline/staged identity used to produce it."""

    run: HalSmokeCampaignRunResult
    composition_sha256: str
    staged_store_identity_sha256: str


def prepare_hal_smoke_operator(
    inputs: HalSmokeOperatorInputs,
) -> PreparedHalSmokeOperator:
    """Prepare exact local evidence and Blue staging without starting Docker or inference."""

    models = load_models_config(inputs.models_config)
    static_plan = build_hal_smoke_static_plan(
        models=models,
        blue_model_id=inputs.blue_model_id,
    )
    pins = load_hal_smoke_runtime_pins(inputs.runtime_pins)
    inventory = load_openwebui_ollama_inventory(inputs.model_inventory)
    blue_peer_endpoint = (
        f"http://{pins.model_endpoint_host}:{pins.model_endpoint_port}"
    )
    admission = validate_local_only_model_selection(
        models=models,
        inventory=inventory,
        blue_model_id=static_plan.blue_model_id,
        blue_endpoint=blue_peer_endpoint,
        blue_required_capabilities={"text"},
        allowed_endpoint_hosts={pins.model_endpoint_host},
    )
    contracts = load_ollama_artifact_contracts(inputs.artifact_contracts)
    tags_snapshot = load_ollama_tags_snapshot(inputs.ollama_tags_snapshot)
    qualification = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=contracts,
        tags_snapshot=tags_snapshot,
    )
    composition = compose_hal_smoke_offline(
        static_plan=static_plan,
        admission=admission,
        qualification=qualification,
        pins=pins,
    )

    blue_contracts = [
        contract
        for contract in contracts.contracts
        if contract.model_id == static_plan.blue_model_id
    ]
    if len(blue_contracts) != 1:
        raise ValueError("artifact contracts must contain exactly one HAL Blue contract")
    blue_contract = blue_contracts[0]

    staging = OllamaModelStagingSupervisor(
        source_models_root=inputs.source_ollama_models_root,
        staging_root=inputs.staging_root,
    )
    staged_store = staging.stage(
        contract=blue_contract,
        manifest_relative_path=inputs.blue_manifest_relative_path,
    )
    if staged_store.identity != pins.staged_blue_store_identity:
        raise ValueError(
            "fresh staged Blue store identity differs from digest-pinned runtime pins"
        )

    budgets = load_budget_config(inputs.budget_config)
    budgets.profile(build_hal_smoke_campaign_plan().budget_profile)
    workspace_supervisor = DisposableWorkspaceSupervisor(
        template_root=inputs.workspace_template_root,
        sandbox_root=inputs.workspace_sandbox_root,
    )
    return PreparedHalSmokeOperator(
        models=models,
        admission=admission,
        qualification=qualification,
        composition=composition,
        staged_store=staged_store,
        blue_artifact_contract=blue_contract,
        budgets=budgets,
        workspace_supervisor=workspace_supervisor,
    )


def build_live_hal_smoke_runtime(
    *,
    prepared: PreparedHalSmokeOperator,
    repository: ExperimentRepository,
    network_name: str,
    docker_runner: DockerCommandRunner | None = None,
) -> LiveHalSmokeRuntime:
    """Wire the trusted HAL runtime without starting a campaign yet."""

    _require_opencode_secret_environment(prepared.composition)
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

    red_client = OpenAICompatibleRoleModelClient(prepared.models)
    red_tags_probe = HttpxLocalOllamaTagsProbe()
    campaign_runner = HalSmokeCampaignRunner(
        composition=prepared.composition,
        admission=prepared.admission,
        qualification=prepared.qualification,
        models=prepared.models,
        staged_store=prepared.staged_store,
        blue_artifact_contract=prepared.blue_artifact_contract,
        blue_infrastructure_supervisor=blue_infrastructure,
        red_tags_probe=red_tags_probe,
        workspace_supervisor=prepared.workspace_supervisor,
        opencode_runtime_supervisor=opencode_runtime,
        docker_runner=runner,
        red_model_client=red_client,
        judge=build_hal_smoke_judge(),
        repository=repository,
        budgets=prepared.budgets,
        judge_policy_descriptor=hal_smoke_judge_policy_descriptor(),
        state_verifier_factory=build_hal_smoke_workspace_verifiers,
        state_verifier_policy_sha256=HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256,
        network_name=network_name,
    )
    return LiveHalSmokeRuntime(
        runner=campaign_runner,
        red_client=red_client,
        red_tags_probe=red_tags_probe,
    )


async def run_live_hal_smoke(
    *,
    inputs: HalSmokeOperatorInputs,
    database_url: str,
    network_name: str,
    campaign_id: str | None = None,
    docker_runner: DockerCommandRunner | None = None,
) -> HalSmokeOperatorRunResult:
    """Prepare and execute the fixed first HAL smoke, then close runtime clients."""

    prepared = prepare_hal_smoke_operator(inputs)
    repository = ExperimentRepository.from_url(database_url)
    runtime = build_live_hal_smoke_runtime(
        prepared=prepared,
        repository=repository,
        network_name=network_name,
        docker_runner=docker_runner,
    )
    primary_error: BaseException | None = None
    result: HalSmokeCampaignRunResult | None = None
    try:
        result = await runtime.runner.run(
            plan=build_hal_smoke_campaign_plan(),
            cases=(build_hal_smoke_case(),),
            campaign_id=campaign_id,
        )
    except BaseException as exc:
        primary_error = exc

    close_error: BaseException | None = None
    try:
        await runtime.aclose()
    except BaseException as exc:
        close_error = exc

    if primary_error is not None:
        if close_error is not None:
            raise RuntimeError(
                "HAL smoke failed and runtime-client cleanup also failed: "
                f"{type(close_error).__name__}: {close_error}"
            ) from primary_error
        raise primary_error
    if close_error is not None:
        raise close_error
    if result is None:
        raise RuntimeError("HAL smoke ended without a campaign result")

    return HalSmokeOperatorRunResult(
        run=result,
        composition_sha256=prepared.composition.composition_sha256,
        staged_store_identity_sha256=prepared.staged_store.identity.identity_sha256,
    )


def _require_opencode_secret_environment(
    composition: HalSmokeOfflineComposition,
) -> None:
    env_name = composition.opencode_runtime.server_password_env
    if env_name is None:
        raise ValueError("HAL smoke requires an OpenCode server password environment name")
    if not os.environ.get(env_name):
        raise ValueError(f"required OpenCode secret environment variable is not set: {env_name}")
