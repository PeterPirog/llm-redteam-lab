"""End-to-end orchestration for the first bounded HAL OpenCode AGENT smoke.

This layer connects the already-audited boundaries without weakening them:

offline exact composition -> campaign-scoped Blue infrastructure -> live Red artifact
recheck -> immutable campaign provenance -> per-trial disposable OpenCode targets ->
standard campaign lifecycle -> campaign-scoped teardown.

The runner itself does not decide attack content, Judge semantics, budgets, or concrete model
clients. Those remain injected measurement inputs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .campaign_plan import CampaignPlan
from .campaigns.lifecycle import CampaignLifecycleExecutor, CampaignLifecycleResult
from .disposable_workspace import DisposableWorkspaceSupervisor
from .docker_networked_opencode_supervisor import DockerNetworkedOpenCodeSupervisor
from .docker_supervisor import DockerCommandRunner
from .domain import AttackCase, TargetClass, TargetMode
from .hal_smoke_preflight import (
    HalSmokeOfflineComposition,
    build_hal_smoke_static_plan,
)
from .hal_smoke_runtime import (
    HalSmokeBlueInfrastructureLease,
    HalSmokeBlueInfrastructureRelease,
    HalSmokeBlueInfrastructureSupervisor,
)
from .judges.base import Judge
from .model_client import RoleModelClient
from .model_inventory import LocalOnlyAdmissionReport
from .model_roles import ModelsConfig
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import PreparedOllamaModelStore
from .red_runtime_artifact import (
    OllamaTagsProbe,
    RedRuntimeArtifactRecheck,
    recheck_red_runtime_artifacts,
    red_runtime_artifact_recheck_provenance,
)
from .reference_artifact_provenance import (
    LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
    artifact_qualification_provenance,
)
from .reference_artifact_qualification import ReferenceArtifactQualificationReport
from .runtime_config import BudgetConfigDocument
from .storage.execution_provenance_repository import (
    ExecutionProvenanceDescriptor,
    build_execution_provenance_descriptor,
)
from .storage.repository import ExperimentRepository
from .targets.base import SessionMode

HAL_BLUE_INFRASTRUCTURE_PROVENANCE_KIND = "hal_blue_infrastructure_v1"


@dataclass(frozen=True, slots=True)
class HalSmokeCampaignRunResult:
    """Completed campaign plus verified campaign-scoped runtime lifecycle evidence."""

    campaign: CampaignLifecycleResult
    red_runtime_recheck: RedRuntimeArtifactRecheck
    blue_infrastructure: HalSmokeBlueInfrastructureLease
    blue_release: HalSmokeBlueInfrastructureRelease
    execution_provenance_hashes: tuple[tuple[str, str], ...]


class HalSmokeCampaignRunner:
    """Run one bounded HAL smoke only after every pre-inference gate succeeds."""

    def __init__(
        self,
        *,
        composition: HalSmokeOfflineComposition,
        admission: LocalOnlyAdmissionReport,
        qualification: ReferenceArtifactQualificationReport,
        models: ModelsConfig,
        staged_store: PreparedOllamaModelStore,
        blue_artifact_contract: OllamaArtifactContract,
        blue_infrastructure_supervisor: HalSmokeBlueInfrastructureSupervisor,
        red_tags_probe: OllamaTagsProbe,
        workspace_supervisor: DisposableWorkspaceSupervisor,
        opencode_runtime_supervisor: DockerNetworkedOpenCodeSupervisor,
        docker_runner: DockerCommandRunner,
        red_model_client: RoleModelClient,
        judge: Judge,
        repository: ExperimentRepository,
        budgets: BudgetConfigDocument,
        judge_policy_descriptor: object,
        network_name: str,
        provider_id: str = "hal-smoke-opencode",
        allowed_red_endpoint_hosts: set[str] | frozenset[str] = frozenset(),
        health_python_executable: str = "python",
    ) -> None:
        self.composition = composition
        self.admission = admission
        self.qualification = qualification
        self.models = models
        self.staged_store = staged_store
        self.blue_artifact_contract = blue_artifact_contract
        self.blue_infrastructure_supervisor = blue_infrastructure_supervisor
        self.red_tags_probe = red_tags_probe
        self.workspace_supervisor = workspace_supervisor
        self.opencode_runtime_supervisor = opencode_runtime_supervisor
        self.docker_runner = docker_runner
        self.red_model_client = red_model_client
        self.judge = judge
        self.repository = repository
        self.budgets = budgets
        self.judge_policy_descriptor = judge_policy_descriptor
        self.network_name = network_name
        self.provider_id = provider_id
        self.allowed_red_endpoint_hosts = frozenset(
            value.strip().casefold() for value in allowed_red_endpoint_hosts
        )
        self.health_python_executable = health_python_executable
        self._validate_static_inputs()

    async def run(
        self,
        *,
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
        campaign_id: str | None = None,
    ) -> HalSmokeCampaignRunResult:
        """Run one smoke and return only after campaign-scoped cleanup completes."""

        _validate_smoke_plan(plan)

        infrastructure: HalSmokeBlueInfrastructureLease | None = None
        release: HalSmokeBlueInfrastructureRelease | None = None
        red_recheck: RedRuntimeArtifactRecheck | None = None
        campaign: CampaignLifecycleResult | None = None
        primary_error: BaseException | None = None

        try:
            infrastructure = self.blue_infrastructure_supervisor.launch(
                composition=self.composition,
                staged_store=self.staged_store,
                artifact_contract=self.blue_artifact_contract,
                network_name=self.network_name,
            )
            trial_provider = self.blue_infrastructure_supervisor.build_trial_provider(
                lease=infrastructure,
                provider_id=self.provider_id,
                workspace_supervisor=self.workspace_supervisor,
                runtime_supervisor=self.opencode_runtime_supervisor,
                runner=self.docker_runner,
                health_python_executable=self.health_python_executable,
            )

            # Keep this gate as close as possible to first Red inference to reduce TOCTOU.
            red_recheck = await recheck_red_runtime_artifacts(
                models=self.models,
                qualification=self.qualification,
                expected_red_measurement_binding_sha256=(
                    self.composition.red_measurement_binding_sha256
                ),
                probe=self.red_tags_probe,
                allowed_endpoint_hosts=self.allowed_red_endpoint_hosts,
            )
            provenance = build_hal_smoke_execution_provenance(
                composition=self.composition,
                admission=self.admission,
                qualification=self.qualification,
                red_recheck=red_recheck,
                blue_infrastructure=infrastructure,
            )

            executor = CampaignLifecycleExecutor(
                target=trial_provider.declared_target,
                judge=self.judge,
                repository=self.repository,
                budgets=self.budgets,
                judge_policy_descriptor=self.judge_policy_descriptor,
                models=self.models,
                red_model_client=self.red_model_client,
                target_lease_provider=trial_provider,
                red_measurement_binding_sha256=(
                    self.composition.red_measurement_binding_sha256
                ),
                execution_provenance=provenance,
            )
            campaign = await executor.run(
                plan=plan,
                cases=cases,
                campaign_id=campaign_id,
            )
        except BaseException as exc:
            primary_error = exc

        cleanup_error: BaseException | None = None
        if infrastructure is not None:
            try:
                release = self.blue_infrastructure_supervisor.release(infrastructure)
                if not release.cleanup_complete:
                    cleanup_error = RuntimeError(
                        "HAL Blue campaign infrastructure teardown did not complete"
                    )
            except BaseException as exc:
                cleanup_error = exc

        if primary_error is not None:
            if cleanup_error is not None:
                raise RuntimeError(
                    "HAL smoke campaign failed and campaign-scoped cleanup also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                ) from primary_error
            raise primary_error
        if cleanup_error is not None:
            raise RuntimeError(
                "HAL smoke campaign completed but campaign-scoped cleanup failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            ) from cleanup_error

        if (
            campaign is None
            or red_recheck is None
            or infrastructure is None
            or release is None
        ):
            raise RuntimeError("HAL smoke orchestration ended without complete evidence")

        return HalSmokeCampaignRunResult(
            campaign=campaign,
            red_runtime_recheck=red_recheck,
            blue_infrastructure=infrastructure,
            blue_release=release,
            execution_provenance_hashes=campaign.execution_provenance_hashes,
        )

    def _validate_static_inputs(self) -> None:
        static = build_hal_smoke_static_plan(
            models=self.models,
            blue_model_id=self.composition.static_plan.blue_model_id,
        )
        if static != self.composition.static_plan:
            raise ValueError("HAL smoke model configuration drifted from offline composition")
        if self.admission.proof_sha256 != self.composition.local_admission_proof_sha256:
            raise ValueError("HAL smoke admission differs from offline composition")
        if (
            self.qualification.proof_sha256
            != self.composition.artifact_qualification_proof_sha256
        ):
            raise ValueError("HAL smoke artifact qualification differs from offline composition")
        if (
            self.qualification.local_admission_proof_sha256
            != self.admission.proof_sha256
        ):
            raise ValueError("HAL smoke artifact qualification does not bind admission")
        if (
            self.staged_store.identity.identity_sha256
            != self.composition.model_peer.staged_store_identity_sha256
        ):
            raise ValueError("HAL smoke staged Blue store differs from offline composition")
        if self.blue_artifact_contract.model_id != self.composition.static_plan.blue_model_id:
            raise ValueError("HAL smoke Blue artifact contract names a different model")
        if (
            self.blue_artifact_contract.manifest_digest
            != self.composition.blue_artifact_digest
        ):
            raise ValueError("HAL smoke Blue artifact contract digest differs from composition")


def build_hal_smoke_execution_provenance(
    *,
    composition: HalSmokeOfflineComposition,
    admission: LocalOnlyAdmissionReport,
    qualification: ReferenceArtifactQualificationReport,
    red_recheck: RedRuntimeArtifactRecheck,
    blue_infrastructure: HalSmokeBlueInfrastructureLease,
) -> tuple[ExecutionProvenanceDescriptor, ...]:
    """Compose all campaign-scoped pre-inference HAL evidence."""

    if admission.proof_sha256 != composition.local_admission_proof_sha256:
        raise ValueError("local admission does not bind the HAL smoke composition")
    if qualification.proof_sha256 != composition.artifact_qualification_proof_sha256:
        raise ValueError("artifact qualification does not bind the HAL smoke composition")
    if qualification.local_admission_proof_sha256 != admission.proof_sha256:
        raise ValueError("artifact qualification does not bind the supplied admission")
    if (
        red_recheck.expected_red_measurement_binding_sha256
        != composition.red_measurement_binding_sha256
        or red_recheck.observed_red_measurement_binding_sha256
        != composition.red_measurement_binding_sha256
    ):
        raise ValueError("live Red artifact recheck does not bind the HAL smoke composition")
    if blue_infrastructure.composition_sha256 != composition.composition_sha256:
        raise ValueError("Blue infrastructure does not bind the HAL smoke composition")
    if (
        blue_infrastructure.target_measurement_binding_sha256
        != composition.target_measurement_binding_sha256
    ):
        raise ValueError("Blue infrastructure binds a different target measurement identity")

    descriptors = (
        build_execution_provenance_descriptor(
            kind=LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
            payload=admission.model_dump(mode="json"),
        ),
        artifact_qualification_provenance(qualification),
        red_runtime_artifact_recheck_provenance(red_recheck),
        _blue_infrastructure_provenance(blue_infrastructure),
    )
    return tuple(sorted(descriptors, key=lambda item: item.kind))


def _blue_infrastructure_provenance(
    lease: HalSmokeBlueInfrastructureLease,
) -> ExecutionProvenanceDescriptor:
    return build_execution_provenance_descriptor(
        kind=HAL_BLUE_INFRASTRUCTURE_PROVENANCE_KIND,
        payload={
            "version": 1,
            "lease_id_hash": lease.lease_id_hash,
            "infrastructure_proof_sha256": lease.proof_sha256,
            "composition_sha256": lease.composition_sha256,
            "target_measurement_binding_sha256": (
                lease.target_measurement_binding_sha256
            ),
            "network_profile_sha256": lease.network.network_profile_sha256,
            "network_id_sha256": lease.network.network_id_sha256,
            "peer_profile_sha256": lease.peer.peer.profile_sha256,
            "peer_container_id_sha256": lease.peer.peer.container_id_sha256,
            "staged_store_identity_sha256": lease.staged_store_identity_sha256,
            "blue_artifact_proof_sha256": lease.artifact.proof_sha256,
        },
    )


def _validate_smoke_plan(plan: CampaignPlan) -> None:
    if plan.target_class != TargetClass.CODING or plan.target_mode != TargetMode.AGENT:
        raise ValueError("HAL smoke campaign requires CODING/AGENT target")
    if not plan.red_policy.model_backed:
        raise ValueError("HAL smoke campaign requires model-backed Red")
    if plan.session_mode != SessionMode.TARGET_MANAGED:
        raise ValueError("HAL OpenCode smoke requires TARGET_MANAGED session history")
    if plan.allow_agent_network:
        raise ValueError("first HAL smoke forbids agent network access")
    if plan.allow_agent_git_push:
        raise ValueError("first HAL smoke forbids agent git publication")
