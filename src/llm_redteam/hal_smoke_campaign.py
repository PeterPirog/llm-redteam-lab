"""End-to-end orchestration for the first bounded HAL OpenCode AGENT smoke.

This is the last composition layer before real HAL execution. It deliberately delegates
all security-sensitive checks to already-tested primitives and only enforces their order:

offline exact composition -> live Red artifact recheck -> exact Blue infrastructure ->
per-trial disposable OpenCode targets -> standard campaign lifecycle -> Blue teardown.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .campaign_plan import CampaignPlan
from .campaigns.lifecycle import CampaignLifecycleExecutor, CampaignLifecycleResult
from .disposable_workspace import DisposableWorkspaceSupervisor
from .docker_networked_opencode_supervisor import DockerNetworkedOpenCodeSupervisor
from .docker_supervisor import DockerCommandRunner
from .domain import AttackCase, TargetClass, TargetMode
from .evaluation_protocol import CampaignPurpose
from .hal_smoke_preflight import (
    HalSmokeOfflineComposition,
    build_hal_smoke_static_plan,
)
from .hal_smoke_runtime import (
    HalSmokeBlueInfrastructureLease,
    HalSmokeBlueInfrastructureRelease,
)
from .judges.base import Judge
from .model_client import RoleModelClient
from .model_inventory import LocalOnlyAdmissionReport
from .model_roles import ModelsConfig
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import PreparedOllamaModelStore
from .opencode_trial_isolation import DockerOpenCodeTrialLeaseProvider
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


@runtime_checkable
class HalSmokeBlueInfrastructureControl(Protocol):
    """Minimal campaign-scoped Blue infrastructure control surface."""

    def launch(
        self,
        *,
        composition: HalSmokeOfflineComposition,
        staged_store: PreparedOllamaModelStore,
        artifact_contract: OllamaArtifactContract,
        network_name: str,
    ) -> HalSmokeBlueInfrastructureLease: ...

    def execution_provenance(
        self,
        lease: HalSmokeBlueInfrastructureLease,
    ) -> ExecutionProvenanceDescriptor: ...

    def build_trial_provider(
        self,
        *,
        lease: HalSmokeBlueInfrastructureLease,
        provider_id: str,
        workspace_supervisor: DisposableWorkspaceSupervisor,
        runtime_supervisor: DockerNetworkedOpenCodeSupervisor,
        runner: DockerCommandRunner,
        health_python_executable: str = "python",
    ) -> DockerOpenCodeTrialLeaseProvider: ...

    def release(
        self,
        lease: HalSmokeBlueInfrastructureLease,
    ) -> HalSmokeBlueInfrastructureRelease: ...


@dataclass(frozen=True, slots=True)
class HalSmokeCampaignRunResult:
    """Finished campaign plus the runtime admission/teardown proofs used for it."""

    campaign: CampaignLifecycleResult
    red_runtime_recheck: RedRuntimeArtifactRecheck
    blue_infrastructure_provenance_sha256: str
    blue_infrastructure_teardown_proof_sha256: str


class HalSmokeCampaignOrchestrator:
    """Run one bounded single-profile HAL smoke under exact Red/Blue evidence."""

    def __init__(
        self,
        *,
        blue_infrastructure: HalSmokeBlueInfrastructureControl,
        red_tags_probe: OllamaTagsProbe,
    ) -> None:
        self.blue_infrastructure = blue_infrastructure
        self.red_tags_probe = red_tags_probe

    async def run(
        self,
        *,
        composition: HalSmokeOfflineComposition,
        admission: LocalOnlyAdmissionReport,
        qualification: ReferenceArtifactQualificationReport,
        models: ModelsConfig,
        staged_store: PreparedOllamaModelStore,
        blue_artifact_contract: OllamaArtifactContract,
        network_name: str,
        provider_id: str,
        workspace_supervisor: DisposableWorkspaceSupervisor,
        runtime_supervisor: DockerNetworkedOpenCodeSupervisor,
        runner: DockerCommandRunner,
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
        budgets: BudgetConfigDocument,
        judge: Judge,
        judge_policy_descriptor: object,
        red_model_client: RoleModelClient,
        repository: ExperimentRepository,
        campaign_id: str | None = None,
        allowed_red_endpoint_hosts: set[str] | frozenset[str] = frozenset(),
        health_python_executable: str = "python",
    ) -> HalSmokeCampaignRunResult:
        """Admit runtime state, run the campaign, then require complete Blue teardown."""

        self._validate_offline_inputs(
            composition=composition,
            admission=admission,
            qualification=qualification,
            models=models,
            plan=plan,
            cases=cases,
        )

        red_recheck = await recheck_red_runtime_artifacts(
            models=models,
            qualification=qualification,
            expected_red_measurement_binding_sha256=(
                composition.red_measurement_binding_sha256
            ),
            probe=self.red_tags_probe,
            allowed_endpoint_hosts=allowed_red_endpoint_hosts,
        )
        red_runtime_provenance = red_runtime_artifact_recheck_provenance(red_recheck)

        blue_lease: HalSmokeBlueInfrastructureLease | None = None
        try:
            blue_lease = self.blue_infrastructure.launch(
                composition=composition,
                staged_store=staged_store,
                artifact_contract=blue_artifact_contract,
                network_name=network_name,
            )
            blue_provenance = self.blue_infrastructure.execution_provenance(blue_lease)
            target_provider = self.blue_infrastructure.build_trial_provider(
                lease=blue_lease,
                provider_id=provider_id,
                workspace_supervisor=workspace_supervisor,
                runtime_supervisor=runtime_supervisor,
                runner=runner,
                health_python_executable=health_python_executable,
            )
            self._validate_trial_provider(
                composition=composition,
                target_provider=target_provider,
            )
            execution_provenance = self._execution_provenance(
                admission=admission,
                qualification=qualification,
                red_runtime_provenance=red_runtime_provenance,
                blue_provenance=blue_provenance,
            )
            executor = CampaignLifecycleExecutor(
                target=target_provider.declared_target,
                judge=judge,
                repository=repository,
                budgets=budgets,
                judge_policy_descriptor=judge_policy_descriptor,
                models=models,
                red_model_client=red_model_client,
                target_lease_provider=target_provider,
                red_measurement_binding_sha256=(
                    composition.red_measurement_binding_sha256
                ),
                execution_provenance=execution_provenance,
            )
            campaign = await executor.run(
                plan=plan,
                cases=cases,
                campaign_id=campaign_id,
            )
        except Exception as exc:
            if blue_lease is not None:
                self._cleanup_after_failed_run(blue_lease, cause=exc)
            raise

        release = self.blue_infrastructure.release(blue_lease)
        if not release.cleanup_complete:
            raise RuntimeError(
                "HAL smoke campaign completed but Blue infrastructure cleanup is incomplete"
            )
        return HalSmokeCampaignRunResult(
            campaign=campaign,
            red_runtime_recheck=red_recheck,
            blue_infrastructure_provenance_sha256=blue_provenance.content_hash,
            blue_infrastructure_teardown_proof_sha256=release.teardown_proof_sha256,
        )

    def _cleanup_after_failed_run(
        self,
        lease: HalSmokeBlueInfrastructureLease,
        *,
        cause: Exception,
    ) -> None:
        try:
            release = self.blue_infrastructure.release(lease)
        except Exception as cleanup_exc:
            raise RuntimeError(
                "HAL smoke campaign failed and Blue infrastructure cleanup also failed"
            ) from cause
        if not release.cleanup_complete:
            raise RuntimeError(
                "HAL smoke campaign failed and Blue infrastructure cleanup is incomplete"
            ) from cause

    @staticmethod
    def _validate_offline_inputs(
        *,
        composition: HalSmokeOfflineComposition,
        admission: LocalOnlyAdmissionReport,
        qualification: ReferenceArtifactQualificationReport,
        models: ModelsConfig,
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
    ) -> None:
        recomputed = build_hal_smoke_static_plan(
            models=models,
            blue_model_id=composition.static_plan.blue_model_id,
        )
        if recomputed != composition.static_plan:
            raise ValueError("HAL smoke model configuration differs from offline composition")
        if admission.proof_sha256 != composition.local_admission_proof_sha256:
            raise ValueError("HAL smoke admission proof differs from offline composition")
        if qualification.proof_sha256 != composition.artifact_qualification_proof_sha256:
            raise ValueError(
                "HAL smoke artifact qualification differs from offline composition"
            )
        if qualification.local_admission_proof_sha256 != admission.proof_sha256:
            raise ValueError("HAL smoke qualification is not bound to supplied admission")
        if plan.purpose != CampaignPurpose.DISCOVERY:
            raise ValueError("first HAL instrumentation smoke requires DISCOVERY purpose")
        if plan.target_class != TargetClass.CODING or plan.target_mode != TargetMode.AGENT:
            raise ValueError("first HAL smoke requires CODING AGENT campaign target")
        if not plan.red_policy.model_backed:
            raise ValueError("first HAL smoke requires a model-backed Red policy")
        if any(case.payload.fixture is not None for case in cases):
            raise ValueError(
                "first HAL smoke does not include fixtures until compound isolation exists"
            )
        if not cases:
            raise ValueError("first HAL smoke requires at least one attack case")

    @staticmethod
    def _validate_trial_provider(
        *,
        composition: HalSmokeOfflineComposition,
        target_provider: DockerOpenCodeTrialLeaseProvider,
    ) -> None:
        if (
            target_provider.target_measurement_binding_sha256
            != composition.target_measurement_binding_sha256
        ):
            raise RuntimeError(
                "HAL Blue trial provider binds a different target measurement identity"
            )
        identity = target_provider.declared_target.identity
        if identity.target_class != TargetClass.CODING or identity.target_mode != TargetMode.AGENT:
            raise RuntimeError("HAL Blue trial provider does not declare a CODING AGENT target")
        if "measurement_identity_bound" not in identity.capabilities:
            raise RuntimeError("HAL Blue target identity lacks measurement binding capability")

    @staticmethod
    def _execution_provenance(
        *,
        admission: LocalOnlyAdmissionReport,
        qualification: ReferenceArtifactQualificationReport,
        red_runtime_provenance: ExecutionProvenanceDescriptor,
        blue_provenance: ExecutionProvenanceDescriptor,
    ) -> tuple[ExecutionProvenanceDescriptor, ...]:
        admission_provenance = build_execution_provenance_descriptor(
            kind=LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
            payload=admission.model_dump(mode="json"),
        )
        return (
            admission_provenance,
            artifact_qualification_provenance(qualification),
            red_runtime_provenance,
            blue_provenance,
        )
