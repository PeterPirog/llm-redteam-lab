"""Artifact-qualified campaign lifecycle admission and provenance persistence.

This module provides the fail-closed lifecycle path for campaigns whose measurement
apparatus uses model-backed Red and/or Judge roles.  It deliberately reuses
``CampaignLifecycleExecutor`` for target execution, budgeting, evidence, judgment,
metrics and terminal-state handling.  Only policy admission and model-role provenance
are added here.

No provider call is made by this adapter.  The supplied ``ArtifactQualifiedCampaignPolicies``
must already have been built from independently verified ``ModelArtifactIdentity``
objects (for example through the Ollama artifact registry edge).
"""

from __future__ import annotations

from collections.abc import Mapping

from ..budget import BudgetLedger
from ..campaign_plan import CampaignPlan, preflight_campaign
from ..campaigns.multiturn import ConversationRunResult, MultiTurnStrategy
from ..domain import AttackCase, CampaignBudget
from ..evaluation_protocol import CampaignPurpose
from ..evaluation_sets import HeldOutEvaluationManifest
from ..fixture_runtime import FixturePrimer, FixtureRuntime
from ..judges.base import Judge
from ..model_client import RoleModelClient
from ..model_roles import ModelsConfig
from ..red.runtime import RedRuntimeDiagnostics, RedStrategyRuntime
from ..runtime_config import BudgetConfigDocument
from ..storage.model_role_repository import (
    ModelRolePolicyScope,
    build_campaign_model_role_provenance,
    save_campaign_model_role_provenance,
)
from ..storage.repository import ExperimentRepository
from ..targets.base import TargetAdapter
from .lifecycle import CampaignLifecycleExecutor, CampaignLifecycleResult, static_attack_policy_descriptor
from .model_qualification import (
    ArtifactQualifiedCampaignPolicies,
    validate_artifact_qualified_campaign_policies,
    validate_qualified_runtime_policy_descriptors,
)


class _ArtifactQualifiedRedRuntime:
    """Delegate execution to one Red runtime while exposing its qualified descriptor."""

    def __init__(
        self,
        runtime: RedStrategyRuntime,
        qualified_descriptor: Mapping[str, object],
    ) -> None:
        self._runtime = runtime
        self._qualified_descriptor = dict(qualified_descriptor)

    @property
    def conversation_budget(self):  # type: ignore[no-untyped-def]
        return self._runtime.conversation_budget

    def descriptor(self) -> dict[str, object]:
        return dict(self._qualified_descriptor)

    def strategy_for(
        self,
        case: AttackCase,
        *,
        fixture_primer: FixturePrimer | None = None,
    ) -> MultiTurnStrategy:
        return self._runtime.strategy_for(case, fixture_primer=fixture_primer)

    def observe(
        self,
        *,
        case: AttackCase,
        strategy: MultiTurnStrategy,
        result: ConversationRunResult,
    ) -> None:
        self._runtime.observe(case=case, strategy=strategy, result=result)

    def diagnostics(self) -> RedRuntimeDiagnostics | None:
        return self._runtime.diagnostics()


class ArtifactQualifiedCampaignLifecycleExecutor(CampaignLifecycleExecutor):
    """Run a campaign only after exact measurement-model artifact admission.

    Held-out EVALUATION with any model-backed measurement role is fail-closed: the plan
    must already declare the exact artifact-qualified attack/Judge fingerprints.

    DISCOVERY remains usable with the historical executor for cheap deterministic/mock
    development.  When callers choose this qualified executor, missing plan fingerprints
    are filled from the already-qualified policies so the resulting campaign configuration
    is still bound to exact model artifacts.
    """

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        repository: ExperimentRepository,
        budgets: BudgetConfigDocument,
        judge_policy_descriptor: Mapping[str, object],
        qualified_model_policies: ArtifactQualifiedCampaignPolicies,
        models: ModelsConfig | None = None,
        red_model_client: RoleModelClient | None = None,
        fixture_runtime: FixtureRuntime | None = None,
    ) -> None:
        super().__init__(
            target=target,
            judge=judge,
            repository=repository,
            budgets=budgets,
            judge_policy_descriptor=qualified_model_policies.judge_policy_descriptor,
            models=models,
            red_model_client=red_model_client,
            fixture_runtime=fixture_runtime,
        )
        self._actual_judge_policy_descriptor = dict(judge_policy_descriptor)
        self.qualified_model_policies = qualified_model_policies

    async def run(
        self,
        *,
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
        evaluation_manifest: HeldOutEvaluationManifest | None = None,
        campaign_id: str | None = None,
    ) -> CampaignLifecycleResult:
        """Admit qualified policies, then delegate the unchanged campaign execution loop."""

        effective_plan = self._bind_discovery_fingerprints(plan)
        preflight = preflight_campaign(
            plan=effective_plan,
            cases=cases,
            budgets=self.budgets,
            models=self.models,
            evaluation_manifest=evaluation_manifest,
            fixture_runner_available=self.fixture_runtime is not None,
            fixture_runtime=self.fixture_runtime,
        )
        if not preflight.ready:
            errors = [
                f"{issue.code}: {issue.message}"
                for issue in preflight.issues
                if issue.severity.value == "ERROR"
            ]
            raise ValueError(
                "artifact-qualified campaign preflight blocked execution: " + "; ".join(errors)
            )

        validate_artifact_qualified_campaign_policies(
            plan=effective_plan,
            preflight=preflight,
            qualified=self.qualified_model_policies,
        )
        return await super().run(
            plan=effective_plan,
            cases=cases,
            evaluation_manifest=evaluation_manifest,
            campaign_id=campaign_id,
        )

    def _build_red_runtime(
        self,
        *,
        plan: CampaignPlan,
        effective_budget: CampaignBudget,
        ledger: BudgetLedger,
        fixture_priming_enabled: bool,
    ):
        runtime = super()._build_red_runtime(
            plan=plan,
            effective_budget=effective_budget,
            ledger=ledger,
            fixture_priming_enabled=fixture_priming_enabled,
        )
        actual_attack_descriptor = (
            static_attack_policy_descriptor(plan)
            if runtime is None
            else runtime.descriptor()
        )
        validate_qualified_runtime_policy_descriptors(
            qualified=self.qualified_model_policies,
            attack_policy_descriptor=actual_attack_descriptor,
            judge_policy_descriptor=self._actual_judge_policy_descriptor,
        )
        if runtime is None:
            return None
        return _ArtifactQualifiedRedRuntime(
            runtime,
            self.qualified_model_policies.attack_policy_descriptor,
        )

    def _persist_measurement_snapshot(
        self,
        *,
        campaign_id: str,
        configuration_hash: str,
        target_snapshot_id: str,
        plan: CampaignPlan,
        attack_fingerprint: str,
        judge_fingerprint: str,
        budget_fingerprint: str,
        manifest: HeldOutEvaluationManifest | None,
    ) -> str:
        self._persist_model_role_provenance(campaign_id)
        return super()._persist_measurement_snapshot(
            campaign_id=campaign_id,
            configuration_hash=configuration_hash,
            target_snapshot_id=target_snapshot_id,
            plan=plan,
            attack_fingerprint=attack_fingerprint,
            judge_fingerprint=judge_fingerprint,
            budget_fingerprint=budget_fingerprint,
            manifest=manifest,
        )

    def _persist_model_role_provenance(self, campaign_id: str) -> None:
        qualified = self.qualified_model_policies
        if qualified.red_model_roles is not None:
            save_campaign_model_role_provenance(
                self.repository.engine,
                build_campaign_model_role_provenance(
                    campaign_id=campaign_id,
                    policy_scope=ModelRolePolicyScope.ATTACK,
                    role_set=qualified.red_model_roles,
                ),
            )
        if qualified.judge_model_roles is not None:
            save_campaign_model_role_provenance(
                self.repository.engine,
                build_campaign_model_role_provenance(
                    campaign_id=campaign_id,
                    policy_scope=ModelRolePolicyScope.JUDGE,
                    role_set=qualified.judge_model_roles,
                ),
            )

    def _bind_discovery_fingerprints(self, plan: CampaignPlan) -> CampaignPlan:
        qualified = self.qualified_model_policies
        if plan.purpose == CampaignPurpose.EVALUATION:
            # EVALUATION fingerprints are predeclared measurement identity.  Do not fill
            # them implicitly here; the admission validator must see the operator-prepared
            # values and reject missing or stale identity.
            return plan

        updates: dict[str, object] = {}
        if plan.attack_policy_fingerprint is None:
            updates["attack_policy_fingerprint"] = qualified.attack_policy_fingerprint
        elif plan.attack_policy_fingerprint != qualified.attack_policy_fingerprint:
            raise ValueError(
                "DISCOVERY attack_policy_fingerprint does not match artifact-qualified policy"
            )
        if plan.judge_policy_fingerprint is None:
            updates["judge_policy_fingerprint"] = qualified.judge_policy_fingerprint
        elif plan.judge_policy_fingerprint != qualified.judge_policy_fingerprint:
            raise ValueError(
                "DISCOVERY judge_policy_fingerprint does not match artifact-qualified policy"
            )
        return plan.model_copy(update=updates) if updates else plan
