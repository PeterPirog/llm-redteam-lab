"""Operator-facing lifecycle for fixed full-cross multi-attacker DISCOVERY campaigns.

This module keeps attacker-pool discovery explicit rather than auto-enabling it merely
because multiple Red variants are configured. It reuses the ordinary campaign preflight,
target snapshot, Judge, evidence, persistence and budget contracts, then applies stricter
full-cross resource and measurement rules before any inference is allowed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import model_validator

from ..agent_actions import canonical_json_hash
from ..budget import BudgetLedger, BudgetSnapshot
from ..campaign_plan import (
    CampaignPlan,
    CampaignPreflight,
    PreflightIssue,
    PreflightSeverity,
    preflight_campaign,
)
from ..corpus import select_cases
from ..domain import AttackCase, CompromiseOutcome, ExecutionResult
from ..evaluation_protocol import (
    CampaignPurpose,
    DiscoveryMetrics,
    discovery_protocol,
    summarize_discovery,
)
from ..judges.base import Judge
from ..metrics import RateEstimate, wilson_rate
from ..model_client import RoleModelClient
from ..model_roles import ModelsConfig
from ..red.runtime import RedAttackerPoolRuntime, RedRuntimeDiagnostics
from ..runtime_config import BudgetConfigDocument
from ..storage.attacker_pool_execution import AttackerPoolTrialRecord
from ..storage.campaign_status import CampaignTerminalStatus, finish_campaign
from ..storage.measurement_repository import (
    build_campaign_measurement_snapshot,
    fingerprint_attack_policy,
    fingerprint_budget,
    fingerprint_judge_policy,
    save_campaign_measurement_snapshot,
)
from ..storage.repository import ExperimentRepository
from ..storage.target_trial_isolation import TargetTrialIsolationRecord
from ..target_trial_isolation import TargetTrialLeaseProvider, minimum_isolation_level
from ..targets.base import TargetAdapter
from .attacker_pool_runner import (
    PersistedAttackerPoolRunner,
    attacker_pool_scope_manifest_hash,
    build_attacker_pool_contract,
)

ATTACKER_POOL_METRIC_DEFINITION_VERSION = "attacker-pool-trials-v1"
_ATTACKER_POOL_POLICY_VERSION = 2


class AttackerPoolExecutionMode(StrEnum):
    FIXED_FULL_CROSS = "fixed_full_cross"


class AttackerPoolCampaignPlan(CampaignPlan):
    """Explicit opt-in plan for discovery by a fixed pool of Red attackers."""

    attacker_pool: Literal[True] = True
    attacker_pool_mode: AttackerPoolExecutionMode = AttackerPoolExecutionMode.FIXED_FULL_CROSS

    @model_validator(mode="after")
    def attacker_pool_plan_is_supported(self) -> AttackerPoolCampaignPlan:
        if self.purpose != CampaignPurpose.DISCOVERY:
            raise ValueError(
                "attacker-pool lifecycle currently supports DISCOVERY only; "
                "held-out pool EVALUATION needs a separate predeclared inference contract"
            )
        if not self.red_policy.model_backed:
            raise ValueError("attacker-pool lifecycle requires a model-backed Red policy")
        return self


@dataclass(frozen=True, slots=True)
class AttackerVariantTrialMetrics:
    variant_id: str
    discovery: DiscoveryMetrics
    target_interactions: int
    planner_calls: int
    mutator_calls: int
    planner_output_tokens: int
    mutator_output_tokens: int


@dataclass(frozen=True, slots=True)
class AttackerPoolTrialMetrics:
    """Security-trial yield before distinct findings are established by forensics."""

    total_trials: int
    opportunity_count: int
    conclusive_opportunities: int
    unresolved_opportunities: int
    opportunities_with_violation: int
    opportunity_violation_rate: RateEstimate
    unresolved_opportunity_rate: RateEstimate
    aggregate_search_yield: DiscoveryMetrics
    variant_metrics: tuple[AttackerVariantTrialMetrics, ...]
    comparable_blue_estimate: bool = False


@dataclass(frozen=True, slots=True)
class AttackerPoolCampaignLifecycleResult:
    campaign_id: str
    target_snapshot_id: str
    measurement_hash: str
    contract_fingerprint: str
    status: CampaignTerminalStatus
    executions: tuple[ExecutionResult, ...]
    trial_records: tuple[AttackerPoolTrialRecord, ...]
    isolation_records: tuple[TargetTrialIsolationRecord, ...]
    metrics: AttackerPoolTrialMetrics
    red_diagnostics: dict[str, RedRuntimeDiagnostics | None]
    budget: BudgetSnapshot


def preflight_attacker_pool_campaign(
    *,
    plan: AttackerPoolCampaignPlan,
    cases: tuple[AttackCase, ...],
    budgets: BudgetConfigDocument,
    models: ModelsConfig | None,
    target_lease_provider: TargetTrialLeaseProvider | None = None,
) -> CampaignPreflight:
    """Extend ordinary preflight with full-cross, inference and isolation constraints."""

    base = preflight_campaign(
        plan=plan,
        cases=cases,
        budgets=budgets,
        models=models,
    )
    issues = list(base.issues)

    variants = models.red_attacker_pool.enabled_variants if models is not None else ()
    if len(variants) < 2:
        _pool_error(
            issues,
            "ATTACKER_POOL_REQUIRED",
            "attacker-pool campaign requires at least two enabled Red variants",
        )
        variant_count = max(1, len(variants))
    else:
        variant_count = len(variants)

    planned_trials = base.planned_trials * variant_count
    minimum_interactions = base.minimum_target_interactions * variant_count
    maximum_interactions = base.maximum_target_interactions * variant_count

    try:
        _, budget = budgets.profile(plan.budget_profile)
    except ValueError:
        budget = next(iter(budgets.profiles.values()))

    if planned_trials > budget.max_attacks:
        _pool_error(
            issues,
            "ATTACKER_POOL_ATTACK_BUDGET",
            (
                f"full-cross planned trials={planned_trials} exceed "
                f"max_attacks={budget.max_attacks}"
            ),
        )
    if minimum_interactions > budget.max_attacks * budget.max_turns_per_attack:
        _pool_error(
            issues,
            "ATTACKER_POOL_INTERACTION_BUDGET",
            "full-cross minimum target interactions exceed authorized attack/turn capacity",
        )

    if variants:
        opportunities_per_variant = base.planned_trials
        minimum_planner_calls = opportunities_per_variant * len(variants)
        minimum_planner_tokens = opportunities_per_variant * sum(
            variant.planner.max_output_tokens for variant in variants
        )
        planner_call_limit = budget.max_model_calls_by_role.get("red_planner")
        planner_token_limit = budget.max_output_tokens_by_role.get("red_planner")
        if minimum_planner_calls > budget.max_model_calls:
            _pool_error(
                issues,
                "ATTACKER_POOL_MODEL_CALL_BUDGET",
                (
                    f"full-cross requires at least {minimum_planner_calls} Red planner calls, "
                    f"exceeding max_model_calls={budget.max_model_calls}"
                ),
            )
        if planner_call_limit is not None and minimum_planner_calls > planner_call_limit:
            _pool_error(
                issues,
                "ATTACKER_POOL_PLANNER_CALL_BUDGET",
                (
                    f"full-cross requires at least {minimum_planner_calls} planner calls, "
                    f"exceeding red_planner limit={planner_call_limit}"
                ),
            )
        if minimum_planner_tokens > budget.max_total_output_tokens:
            _pool_error(
                issues,
                "ATTACKER_POOL_OUTPUT_TOKEN_BUDGET",
                (
                    f"minimum planner output reservation={minimum_planner_tokens} exceeds "
                    f"max_total_output_tokens={budget.max_total_output_tokens}"
                ),
            )
        if planner_token_limit is not None and minimum_planner_tokens > planner_token_limit:
            _pool_error(
                issues,
                "ATTACKER_POOL_PLANNER_TOKEN_BUDGET",
                (
                    f"minimum planner output reservation={minimum_planner_tokens} exceeds "
                    f"red_planner token limit={planner_token_limit}"
                ),
            )

    required_isolation = minimum_isolation_level(
        target_mode=plan.target_mode,
        session_mode=plan.session_mode,
    )
    if required_isolation is not None:
        if target_lease_provider is None:
            _pool_error(
                issues,
                "ATTACKER_POOL_TARGET_ISOLATION_REQUIRED",
                (
                    "target/session mode requires an independently enforced per-trial "
                    "Blue isolation provider"
                ),
            )
        elif target_lease_provider.isolation_level < required_isolation:
            _pool_error(
                issues,
                "ATTACKER_POOL_TARGET_ISOLATION_STRENGTH",
                (
                    f"provider isolation={target_lease_provider.isolation_level.name.lower()} "
                    f"is weaker than required={required_isolation.name.lower()}"
                ),
            )

    if target_lease_provider is not None and not _is_sha256(
        target_lease_provider.provider_fingerprint
    ):
        _pool_error(
            issues,
            "ATTACKER_POOL_TARGET_ISOLATION_IDENTITY",
            "target isolation provider must expose a stable SHA-256 policy fingerprint",
        )

    selected = select_cases(
        cases,
        target_class=plan.target_class,
        target_mode=plan.target_mode,
        enabled_only=plan.enabled_only,
    )
    if any(case.payload.fixture is not None for case in selected):
        _pool_error(
            issues,
            "ATTACKER_POOL_FIXTURE_LEASE_REQUIRED",
            (
                "fixture-backed pool execution requires compound fixture and target "
                "isolation and remains deferred"
            ),
        )

    return base.model_copy(
        update={
            "planned_trials": planned_trials,
            "minimum_target_interactions": minimum_interactions,
            "maximum_target_interactions": maximum_interactions,
            "issues": tuple(issues),
        }
    )


class AttackerPoolCampaignLifecycleExecutor:
    """Run one explicit full-cross attacker-pool campaign through persisted evidence."""

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        repository: ExperimentRepository,
        budgets: BudgetConfigDocument,
        judge_policy_descriptor: object,
        models: ModelsConfig,
        red_model_client: RoleModelClient,
        target_lease_provider: TargetTrialLeaseProvider | None = None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.repository = repository
        self.budgets = budgets
        self.judge_policy_descriptor = judge_policy_descriptor
        self.models = models
        self.red_model_client = red_model_client
        self.target_lease_provider = target_lease_provider

    async def run(
        self,
        *,
        plan: AttackerPoolCampaignPlan,
        cases: tuple[AttackCase, ...],
        campaign_id: str | None = None,
    ) -> AttackerPoolCampaignLifecycleResult:
        preflight = preflight_attacker_pool_campaign(
            plan=plan,
            cases=cases,
            budgets=self.budgets,
            models=self.models,
            target_lease_provider=self.target_lease_provider,
        )
        if not preflight.ready:
            errors = [
                f"{issue.code}: {issue.message}"
                for issue in preflight.issues
                if issue.severity == PreflightSeverity.ERROR
            ]
            raise ValueError(
                "attacker-pool campaign preflight blocked execution: " + "; ".join(errors)
            )

        selected = select_cases(
            cases,
            target_class=plan.target_class,
            target_mode=plan.target_mode,
            enabled_only=plan.enabled_only,
        )
        profile_name, effective_budget = self.budgets.profile(plan.budget_profile)
        ledger = BudgetLedger(effective_budget)
        runtime = RedAttackerPoolRuntime(
            policy=plan.red_policy,
            purpose=plan.purpose,
            target_class=plan.target_class,
            target_mode=plan.target_mode,
            session_mode=plan.session_mode,
            campaign_budget=effective_budget,
            models=self.models,
            model_client=self.red_model_client,
            budget=ledger,
        )
        target_snapshot_id = self.repository.target_snapshot_id(self.target.identity)
        if plan.target_snapshot_id is not None and plan.target_snapshot_id != target_snapshot_id:
            raise ValueError("configured target_snapshot_id does not match actual Blue target")

        required_isolation = minimum_isolation_level(
            target_mode=plan.target_mode,
            session_mode=plan.session_mode,
        )
        isolation_descriptor = {
            "required_level": (
                required_isolation.name.lower() if required_isolation is not None else "none"
            ),
            "provider_fingerprint": (
                self.target_lease_provider.provider_fingerprint
                if required_isolation is not None and self.target_lease_provider is not None
                else None
            ),
            "provider_level": (
                self.target_lease_provider.isolation_level.name.lower()
                if required_isolation is not None and self.target_lease_provider is not None
                else None
            ),
        }
        attack_descriptor = {
            "kind": "attacker_pool",
            "version": _ATTACKER_POOL_POLICY_VERSION,
            "red_policy": plan.red_policy.value,
            "execution_mode": plan.attacker_pool_mode.value,
            "session_mode": plan.session_mode.value,
            "pool_fingerprint": runtime.pool_fingerprint,
            "variants": runtime.descriptors(),
            "target_isolation": isolation_descriptor,
            "live_judge_feedback_to_red": False,
        }
        attack_fingerprint = fingerprint_attack_policy(attack_descriptor)
        judge_fingerprint = fingerprint_judge_policy(self.judge_policy_descriptor)
        if (
            plan.attack_policy_fingerprint is not None
            and plan.attack_policy_fingerprint != attack_fingerprint
        ):
            raise ValueError("configured attack_policy_fingerprint does not match attacker pool")
        if (
            plan.judge_policy_fingerprint is not None
            and plan.judge_policy_fingerprint != judge_fingerprint
        ):
            raise ValueError("configured judge_policy_fingerprint does not match actual Judge")

        budget_fingerprint = fingerprint_budget(effective_budget.model_dump(mode="json"))
        resolved_campaign_id = campaign_id or f"campaign-pool-{uuid4().hex}"
        scope_hash = attacker_pool_scope_manifest_hash(selected)
        configuration_hash = canonical_json_hash(
            {
                "plan": plan.model_dump(mode="json"),
                "selected_case_ids": [case.id for case in selected],
                "scope_manifest_hash": scope_hash,
                "budget_profile": profile_name,
                "budget_fingerprint": budget_fingerprint,
                "target_snapshot_id": target_snapshot_id,
                "attack_policy_fingerprint": attack_fingerprint,
                "judge_policy_fingerprint": judge_fingerprint,
                "metric_definition_version": ATTACKER_POOL_METRIC_DEFINITION_VERSION,
            }
        )

        self.repository.create_schema()
        persisted_snapshot_id = self.repository.save_target(self.target.identity)
        if persisted_snapshot_id != target_snapshot_id:
            raise RuntimeError("target snapshot identity changed during pool campaign setup")
        self.repository.start_campaign(
            campaign_id=resolved_campaign_id,
            target_snapshot_id=target_snapshot_id,
            configuration_hash=configuration_hash,
            metric_definition_version=ATTACKER_POOL_METRIC_DEFINITION_VERSION,
        )

        measurement_hash = ""
        try:
            snapshot = build_campaign_measurement_snapshot(
                campaign_id=resolved_campaign_id,
                target_snapshot_id=target_snapshot_id,
                campaign_configuration_hash=configuration_hash,
                metric_definition_version=ATTACKER_POOL_METRIC_DEFINITION_VERSION,
                protocol=discovery_protocol(),
                attack_policy_fingerprint=attack_fingerprint,
                judge_policy_fingerprint=judge_fingerprint,
                budget_fingerprint=budget_fingerprint,
            )
            measurement_hash = save_campaign_measurement_snapshot(
                self.repository.engine,
                snapshot,
            )
            contract = build_attacker_pool_contract(
                runtime=runtime,
                experiment_id=resolved_campaign_id,
                target_snapshot_id=target_snapshot_id,
                cases=selected,
                replicates_per_case=plan.replicates,
            )
            runner = PersistedAttackerPoolRunner(
                target=self.target,
                judge=self.judge,
                repository=self.repository,
                runtime=runtime,
                target_lease_provider=self.target_lease_provider,
            )
            pool_result = await runner.run(
                contract=contract,
                cases=selected,
                campaign_id=resolved_campaign_id,
            )
            metrics = summarize_attacker_pool_trial_metrics(
                pool_result.executions,
                pool_result.trial_records,
            )
        except Exception:
            finish_campaign(
                self.repository.engine,
                campaign_id=resolved_campaign_id,
                status=CampaignTerminalStatus.FAILED,
            )
            raise

        finish_campaign(
            self.repository.engine,
            campaign_id=resolved_campaign_id,
            status=CampaignTerminalStatus.COMPLETED,
        )
        return AttackerPoolCampaignLifecycleResult(
            campaign_id=resolved_campaign_id,
            target_snapshot_id=target_snapshot_id,
            measurement_hash=measurement_hash,
            contract_fingerprint=pool_result.contract_fingerprint,
            status=CampaignTerminalStatus.COMPLETED,
            executions=pool_result.executions,
            trial_records=pool_result.trial_records,
            isolation_records=pool_result.isolation_records,
            metrics=metrics,
            red_diagnostics={
                variant_id: runtime.runtime_for(variant_id).diagnostics()
                for variant_id in runtime.variant_ids
            },
            budget=pool_result.budget,
        )


def summarize_attacker_pool_trial_metrics(
    executions: tuple[ExecutionResult, ...],
    records: tuple[AttackerPoolTrialRecord, ...],
    confidence_level: float = 0.95,
) -> AttackerPoolTrialMetrics:
    """Summarize trial security yield without pretending trials are distinct findings."""

    if not records:
        raise ValueError("attacker-pool trial metrics require persisted records")
    if len(executions) != len(records):
        raise ValueError("attacker-pool executions and persisted trial records differ in size")
    execution_by_id = {execution.execution_id: execution for execution in executions}
    if len(execution_by_id) != len(executions):
        raise ValueError("attacker-pool executions require unique execution IDs")

    by_variant: dict[str, list[ExecutionResult]] = defaultdict(list)
    resources: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    opportunity_rows: dict[tuple[str, int], list[ExecutionResult]] = defaultdict(list)
    for record in records:
        if record.execution_id is None:
            raise ValueError("attacker-pool trial metrics require completed persisted trials")
        execution = execution_by_id.get(record.execution_id)
        if execution is None:
            raise ValueError("persisted attacker-pool trial references an unknown execution")
        if execution.attack_id != record.case_id:
            raise ValueError("persisted attacker-pool trial case does not match execution")
        by_variant[record.variant_id].append(execution)
        opportunity_rows[(record.case_id, record.replicate)].append(execution)
        for name in (
            "target_interactions",
            "planner_calls",
            "mutator_calls",
            "planner_output_tokens",
            "mutator_output_tokens",
        ):
            value = getattr(record, name)
            if value is None:
                raise ValueError("attacker-pool trial metrics require persisted resource deltas")
            resources[record.variant_id][name] += value

    unresolved_outcomes = {
        CompromiseOutcome.ERROR,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.PARTIAL,
    }
    opportunities_with_violation = 0
    unresolved_opportunities = 0
    for rows in opportunity_rows.values():
        if any(row.objective_violated is True for row in rows):
            opportunities_with_violation += 1
        elif any(row.outcome in unresolved_outcomes for row in rows):
            unresolved_opportunities += 1

    opportunity_count = len(opportunity_rows)
    conclusive_opportunities = opportunity_count - unresolved_opportunities
    variant_metrics = tuple(
        AttackerVariantTrialMetrics(
            variant_id=variant_id,
            discovery=summarize_discovery(rows, confidence_level),
            target_interactions=resources[variant_id]["target_interactions"],
            planner_calls=resources[variant_id]["planner_calls"],
            mutator_calls=resources[variant_id]["mutator_calls"],
            planner_output_tokens=resources[variant_id]["planner_output_tokens"],
            mutator_output_tokens=resources[variant_id]["mutator_output_tokens"],
        )
        for variant_id, rows in sorted(by_variant.items())
    )
    return AttackerPoolTrialMetrics(
        total_trials=len(records),
        opportunity_count=opportunity_count,
        conclusive_opportunities=conclusive_opportunities,
        unresolved_opportunities=unresolved_opportunities,
        opportunities_with_violation=opportunities_with_violation,
        opportunity_violation_rate=wilson_rate(
            opportunities_with_violation,
            conclusive_opportunities,
            confidence_level,
        ),
        unresolved_opportunity_rate=wilson_rate(
            unresolved_opportunities,
            opportunity_count,
            confidence_level,
        ),
        aggregate_search_yield=summarize_discovery(executions, confidence_level),
        variant_metrics=variant_metrics,
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _pool_error(issues: list[PreflightIssue], code: str, message: str) -> None:
    issues.append(
        PreflightIssue(
            code=code,
            severity=PreflightSeverity.ERROR,
            message=message,
        )
    )
