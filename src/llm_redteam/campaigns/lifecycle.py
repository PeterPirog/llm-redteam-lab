"""Fail-closed campaign lifecycle binding preflight, execution and persistence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from uuid import uuid4

from ..budget import BudgetLedger, BudgetSnapshot
from ..campaign_plan import CampaignPlan, RedPolicyKind, preflight_campaign
from ..corpus import select_cases
from ..domain import AttackCase, CampaignBudget, ExecutionResult
from ..evaluation_protocol import (
    CampaignPurpose,
    DiscoveryMetrics,
    EvaluationMetrics,
    discovery_protocol,
    held_out_evaluation_protocol,
    summarize_discovery,
    summarize_evaluation,
)
from ..evaluation_sets import (
    HeldOutEvaluationManifest,
    fingerprint_attack_case,
    select_manifest_cases,
)
from ..fixture_runtime import (
    FixtureDescriptor,
    FixtureProvenanceTarget,
    FixtureRuntime,
)
from ..judges.base import Judge
from ..model_client import RoleModelClient
from ..model_roles import ModelsConfig
from ..red.fixture_adaptive import FixturePrimer
from ..red.runtime import RedRuntimeDiagnostics, RedStrategyRuntime
from ..red.scripted import ScriptedPayloadStrategy
from ..runtime_config import BudgetConfigDocument
from ..storage.campaign_status import CampaignTerminalStatus, finish_campaign
from ..storage.evaluation_set_repository import save_evaluation_set_manifest
from ..storage.measurement_repository import (
    build_campaign_measurement_snapshot,
    build_evaluation_campaign_measurement_snapshot,
    fingerprint_attack_policy,
    fingerprint_budget,
    fingerprint_judge_policy,
    save_campaign_measurement_snapshot,
)
from ..storage.repository import ExperimentRepository
from ..storage.target_trial_isolation import (
    TargetTrialIsolationRecord,
    ensure_target_trial_isolation_schema,
    load_target_trial_isolation_records,
    record_target_trial_isolation_acquired,
    record_target_trial_isolation_released,
)
from ..target_trial_close import release_target_trial_lease
from ..target_trial_isolation import (
    IsolationProvenanceTarget,
    TargetTrialLease,
    TargetTrialLeaseProvider,
    minimum_isolation_level,
    validate_target_trial_lease,
)
from ..targets.base import TargetAdapter
from .engine import CampaignEngine
from .multiturn import (
    ConversationBudget,
    ConversationRunResult,
    MultiTurnCampaignEngine,
    MultiTurnStrategy,
)

METRIC_DEFINITION_VERSION = "v2"
_STATIC_POLICY_VERSION = 1


@dataclass(frozen=True, slots=True)
class CampaignLifecycleResult:
    """Auditable result of one persisted campaign lifecycle."""

    campaign_id: str
    target_snapshot_id: str
    measurement_hash: str
    status: CampaignTerminalStatus
    executions: tuple[ExecutionResult, ...]
    conversations: tuple[ConversationRunResult, ...]
    isolation_records: tuple[TargetTrialIsolationRecord, ...]
    metrics: DiscoveryMetrics | EvaluationMetrics | None
    red_diagnostics: RedRuntimeDiagnostics | None
    measurement_error: str | None
    budget: BudgetSnapshot


def static_attack_policy_descriptor(plan: CampaignPlan) -> dict[str, object]:
    """Serializable identity for the deterministic corpus-driven Red policy."""

    return {
        "kind": RedPolicyKind.STATIC.value,
        "version": _STATIC_POLICY_VERSION,
        "session_mode": plan.session_mode.value,
        "sequence_runner": "scripted-payload-v1",
        "stop_after_first_violation": True,
    }


def deterministic_judge_policy_descriptor(*, canary: str) -> dict[str, object]:
    """Hash-only descriptor for the built-in deterministic canary Judge."""

    return {
        "kind": "deterministic",
        "implementation": "DeterministicJudge",
        "version": 1,
        "canary_sha256": sha256(canary.encode()).hexdigest(),
    }


class CampaignLifecycleExecutor:
    """Execute a valid campaign plan through one auditable lifecycle boundary.

    Static and model-backed Red both pass through the same preflight, budget,
    target-snapshot, persistence and measurement-provenance gates. Fixture-aware
    model-backed Red additionally binds an immutable environment bundle into a clean
    local sandbox before the first legitimate target interaction.
    """

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        repository: ExperimentRepository,
        budgets: BudgetConfigDocument,
        judge_policy_descriptor: object,
        models: ModelsConfig | None = None,
        red_model_client: RoleModelClient | None = None,
        fixture_runtime: FixtureRuntime | None = None,
        target_lease_provider: TargetTrialLeaseProvider | None = None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.repository = repository
        self.budgets = budgets
        self.judge_policy_descriptor = judge_policy_descriptor
        self.models = models
        self.red_model_client = red_model_client
        self.fixture_runtime = fixture_runtime
        self.target_lease_provider = target_lease_provider

    async def run(
        self,
        *,
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
        evaluation_manifest: HeldOutEvaluationManifest | None = None,
        campaign_id: str | None = None,
    ) -> CampaignLifecycleResult:
        """Run one campaign after recomputing all deterministic preflight gates."""

        preflight = preflight_campaign(
            plan=plan,
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
            raise ValueError("campaign preflight blocked execution: " + "; ".join(errors))

        selected = self._selected_cases(plan, cases, evaluation_manifest)
        fixture_descriptors = self._describe_fixtures(selected)
        required_isolation = self._validate_target_isolation_policy(
            plan=plan,
            fixture_descriptors=fixture_descriptors,
        )
        profile_name, effective_budget = self.budgets.profile(plan.budget_profile)
        ledger = BudgetLedger(effective_budget)
        red_runtime = self._build_red_runtime(
            plan=plan,
            effective_budget=effective_budget,
            ledger=ledger,
            fixture_priming_enabled=bool(fixture_descriptors),
        )

        target_snapshot_id = self.repository.target_snapshot_id(self.target.identity)
        if plan.target_snapshot_id is not None and plan.target_snapshot_id != target_snapshot_id:
            raise ValueError("configured target_snapshot_id does not match actual Blue target")

        attack_descriptor = (
            static_attack_policy_descriptor(plan)
            if red_runtime is None
            else red_runtime.descriptor()
        )
        attack_fingerprint = fingerprint_attack_policy(attack_descriptor)
        judge_fingerprint = fingerprint_judge_policy(self.judge_policy_descriptor)
        budget_fingerprint = fingerprint_budget(effective_budget.model_dump(mode="json"))
        self._validate_evaluation_identity(
            plan,
            attack_fingerprint=attack_fingerprint,
            judge_fingerprint=judge_fingerprint,
        )

        resolved_campaign_id = campaign_id or f"campaign-{uuid4().hex}"
        configuration_hash = _canonical_hash(
            {
                "plan": plan.model_dump(mode="json"),
                "selected_case_ids": [case.id for case in selected],
                "fixture_descriptors": {
                    case_id: descriptor.model_dump(mode="json")
                    for case_id, descriptor in sorted(fixture_descriptors.items())
                },
                "budget_profile": profile_name,
                "budget_fingerprint": budget_fingerprint,
                "target_snapshot_id": target_snapshot_id,
                "target_isolation": self._target_isolation_descriptor(required_isolation),
                "metric_definition_version": METRIC_DEFINITION_VERSION,
            }
        )

        self.repository.create_schema()
        ensure_target_trial_isolation_schema(self.repository.engine)
        persisted_snapshot_id = self.repository.save_target(self.target.identity)
        if persisted_snapshot_id != target_snapshot_id:
            raise RuntimeError("target snapshot identity changed during campaign setup")

        if evaluation_manifest is not None:
            save_evaluation_set_manifest(self.repository.engine, evaluation_manifest)

        self.repository.start_campaign(
            campaign_id=resolved_campaign_id,
            target_snapshot_id=target_snapshot_id,
            configuration_hash=configuration_hash,
            metric_definition_version=METRIC_DEFINITION_VERSION,
        )

        measurement_hash = ""
        executions: list[ExecutionResult] = []
        conversations: list[ConversationRunResult] = []
        attack_instance_ids: list[str] = []
        seen_fixture_isolation_ids: set[str] = set()
        try:
            measurement_hash = self._persist_measurement_snapshot(
                campaign_id=resolved_campaign_id,
                configuration_hash=configuration_hash,
                target_snapshot_id=target_snapshot_id,
                plan=plan,
                attack_fingerprint=attack_fingerprint,
                judge_fingerprint=judge_fingerprint,
                budget_fingerprint=budget_fingerprint,
                manifest=evaluation_manifest,
            )
            for replicate in range(plan.replicates):
                for case in selected:
                    attack_instance_id = _attack_instance_id(
                        resolved_campaign_id,
                        case.id,
                        replicate,
                    )
                    attack_instance_ids.append(attack_instance_id)
                    descriptor = fixture_descriptors.get(case.id)
                    self.repository.record_attack(
                        attack_instance_id=attack_instance_id,
                        campaign_id=resolved_campaign_id,
                        case_id=case.id,
                        attack_family=case.attack_family[0],
                        interaction_mode=case.interaction_mode,
                        payload_hash=_attack_payload_hash(case, descriptor),
                    )
                    trial_target, lease = await self._acquire_trial_target(
                        plan=plan,
                        attack_instance_id=attack_instance_id,
                    )
                    release = None
                    conversation: ConversationRunResult | None = None
                    execution: ExecutionResult | None = None
                    strategy: MultiTurnStrategy | None = None
                    try:
                        if case.interaction_mode == "multi_turn":
                            if red_runtime is None:
                                conversation = await self._run_static_conversation(
                                    case=case,
                                    ledger=ledger,
                                    plan=plan,
                                    campaign_id=resolved_campaign_id,
                                    replicate=replicate,
                                    target=trial_target,
                                )
                            elif descriptor is None:
                                strategy = red_runtime.strategy_for(case)
                                conversation = await self._run_model_conversation(
                                    case=case,
                                    ledger=ledger,
                                    plan=plan,
                                    campaign_id=resolved_campaign_id,
                                    replicate=replicate,
                                    red_runtime=red_runtime,
                                    strategy=strategy,
                                    target=trial_target,
                                )
                            else:
                                conversation, strategy = await self._run_fixture_conversation(
                                    case=case,
                                    descriptor=descriptor,
                                    ledger=ledger,
                                    plan=plan,
                                    campaign_id=resolved_campaign_id,
                                    replicate=replicate,
                                    attack_instance_id=attack_instance_id,
                                    red_runtime=red_runtime,
                                    seen_isolation_ids=seen_fixture_isolation_ids,
                                )
                        else:
                            if red_runtime is not None:
                                raise RuntimeError(
                                    "model-backed Red reached a non-multi-turn case after preflight"
                                )
                            execution = await self._run_static_single_turn(
                                case=case,
                                ledger=ledger,
                                campaign_id=resolved_campaign_id,
                                replicate=replicate,
                                target=trial_target,
                            )
                    finally:
                        if lease is not None:
                            if self.target_lease_provider is None:
                                raise RuntimeError(
                                    "target lease provider disappeared during trial"
                                )
                            release = await release_target_trial_lease(
                                self.target_lease_provider,
                                lease,
                            )
                            record_target_trial_isolation_released(
                                self.repository.engine,
                                attack_instance_id=attack_instance_id,
                                release=release,
                            )
                            if not release.cleanup_complete:
                                raise RuntimeError(
                                    "target-isolation teardown did not complete"
                                )

                    if conversation is not None:
                        if release is not None:
                            enriched = conversation.execution.model_copy(
                                update={
                                    "evidence": (
                                        *conversation.execution.evidence,
                                        release.evidence(),
                                    )
                                }
                            )
                            conversation = conversation.model_copy(
                                update={"execution": enriched}
                            )
                        self.repository.save_conversation(
                            conversation,
                            attack_instance_id=attack_instance_id,
                            target_snapshot_id=target_snapshot_id,
                        )
                        if red_runtime is not None:
                            if strategy is None:
                                raise RuntimeError(
                                    "adaptive Red strategy disappeared after execution"
                                )
                            red_runtime.observe(
                                case=case,
                                strategy=strategy,
                                result=conversation,
                            )
                        conversations.append(conversation)
                        executions.append(conversation.execution)
                        continue

                    if execution is None:
                        raise RuntimeError("campaign trial ended without an execution result")
                    if release is not None:
                        execution = execution.model_copy(
                            update={
                                "evidence": (
                                    *execution.evidence,
                                    release.evidence(),
                                )
                            }
                        )
                    self.repository.save_execution(
                        execution,
                        attack_instance_id=attack_instance_id,
                        target_snapshot_id=target_snapshot_id,
                    )
                    executions.append(execution)
        except Exception:
            finish_campaign(
                self.repository.engine,
                campaign_id=resolved_campaign_id,
                status=CampaignTerminalStatus.FAILED,
            )
            raise

        try:
            isolation_records = load_target_trial_isolation_records(
                self.repository.engine,
                attack_instance_ids=tuple(attack_instance_ids),
            )
            self._validate_completed_target_isolation(
                required_isolation=required_isolation,
                attack_instance_ids=tuple(attack_instance_ids),
                records=isolation_records,
            )
        except Exception:
            finish_campaign(
                self.repository.engine,
                campaign_id=resolved_campaign_id,
                status=CampaignTerminalStatus.FAILED,
            )
            raise

        metrics: DiscoveryMetrics | EvaluationMetrics | None
        measurement_error: str | None = None
        if plan.purpose == CampaignPurpose.DISCOVERY:
            metrics = summarize_discovery(executions)
            status = CampaignTerminalStatus.COMPLETED
        else:
            assert evaluation_manifest is not None
            try:
                metrics = summarize_evaluation(
                    executions,
                    held_out_evaluation_protocol(),
                    evaluation_manifest,
                )
                status = CampaignTerminalStatus.COMPLETED
            except ValueError as exc:
                metrics = None
                measurement_error = str(exc)
                status = CampaignTerminalStatus.INCONCLUSIVE

        finish_campaign(
            self.repository.engine,
            campaign_id=resolved_campaign_id,
            status=status,
        )
        return CampaignLifecycleResult(
            campaign_id=resolved_campaign_id,
            target_snapshot_id=target_snapshot_id,
            measurement_hash=measurement_hash,
            status=status,
            executions=tuple(executions),
            conversations=tuple(conversations),
            isolation_records=isolation_records,
            metrics=metrics,
            red_diagnostics=red_runtime.diagnostics() if red_runtime is not None else None,
            measurement_error=measurement_error,
            budget=ledger.snapshot(),
        )

    def _validate_target_isolation_policy(
        self,
        *,
        plan: CampaignPlan,
        fixture_descriptors: dict[str, FixtureDescriptor],
    ):
        required = minimum_isolation_level(
            target_mode=self.target.identity.target_mode,
            session_mode=plan.session_mode,
        )
        if required is None:
            return None
        if self.target_lease_provider is None:
            raise ValueError(
                "campaign target/session mode requires a per-trial target isolation provider"
            )
        if self.target_lease_provider.isolation_level < required:
            raise ValueError("target isolation provider is weaker than required")
        if fixture_descriptors:
            raise ValueError(
                "fixture execution with isolated target trials requires compound "
                "fixture/target isolation and remains deferred"
            )
        return required

    def _target_isolation_descriptor(self, required_isolation):
        if required_isolation is None:
            return None
        if self.target_lease_provider is None:  # pragma: no cover - validated earlier
            raise RuntimeError("target isolation provider disappeared after validation")
        return {
            "required_isolation_level": required_isolation.name.lower(),
            "provider_isolation_level": self.target_lease_provider.isolation_level.name.lower(),
            "provider_fingerprint": self.target_lease_provider.provider_fingerprint,
        }

    async def _acquire_trial_target(
        self,
        *,
        plan: CampaignPlan,
        attack_instance_id: str,
    ) -> tuple[TargetAdapter, TargetTrialLease | None]:
        required = minimum_isolation_level(
            target_mode=self.target.identity.target_mode,
            session_mode=plan.session_mode,
        )
        if required is None:
            return self.target, None
        if self.target_lease_provider is None:
            raise RuntimeError("target isolation provider disappeared before acquisition")

        lease = self.target_lease_provider.acquire(
            expected_identity=self.target.identity,
            trial_id=attack_instance_id,
        )
        try:
            validate_target_trial_lease(
                lease,
                expected_identity=self.target.identity,
                session_mode=plan.session_mode,
            )
            record_target_trial_isolation_acquired(
                self.repository.engine,
                attack_instance_id=attack_instance_id,
                attestation=lease.attestation,
            )
        except Exception as exc:
            release = await release_target_trial_lease(
                self.target_lease_provider,
                lease,
            )
            if not release.cleanup_complete:
                raise RuntimeError(
                    "target-isolation cleanup failed after rejected acquisition"
                ) from exc
            raise
        return IsolationProvenanceTarget(lease.target, lease.attestation), lease

    def _validate_completed_target_isolation(
        self,
        *,
        required_isolation,
        attack_instance_ids: tuple[str, ...],
        records: tuple[TargetTrialIsolationRecord, ...],
    ) -> None:
        if required_isolation is None:
            if records:
                raise RuntimeError("unexpected target-isolation evidence for campaign")
            return
        if len(records) != len(attack_instance_ids):
            raise RuntimeError("target-isolation evidence is incomplete for campaign trials")
        if len({record.lease_id_hash for record in records}) != len(records):
            raise RuntimeError("target-isolation lease identity was reused across trials")
        expected_attacks = set(attack_instance_ids)
        if {record.attack_instance_id for record in records} != expected_attacks:
            raise RuntimeError("target-isolation evidence does not cover exact campaign attacks")
        for record in records:
            if not record.control_plane_independent:
                raise RuntimeError("target isolation was not control-plane independent")
            if record.isolation_level < required_isolation:
                raise RuntimeError("persisted target isolation is weaker than required")
            if record.target_configuration_hash != self.target.identity.configuration_hash:
                raise RuntimeError("target-isolation evidence binds a different Blue target")
            if record.cleanup_complete is not True or record.teardown_proof_hash is None:
                raise RuntimeError("target-isolation teardown evidence is incomplete")

    def _describe_fixtures(
        self,
        selected: tuple[AttackCase, ...],
    ) -> dict[str, FixtureDescriptor]:
        fixture_cases = tuple(case for case in selected if case.payload.fixture is not None)
        if not fixture_cases:
            return {}
        if self.fixture_runtime is None:
            raise RuntimeError("fixture cases passed preflight without a fixture runtime")
        descriptors: dict[str, FixtureDescriptor] = {}
        for case in fixture_cases:
            descriptor = self.fixture_runtime.describe(case)
            if descriptor.target_class != self.target.identity.target_class:
                raise ValueError("fixture target class does not match actual Blue target")
            if descriptor.target_mode != self.target.identity.target_mode:
                raise ValueError("fixture target mode does not match actual Blue target")
            descriptors[case.id] = descriptor
        return descriptors

    def _build_red_runtime(
        self,
        *,
        plan: CampaignPlan,
        effective_budget: CampaignBudget,
        ledger: BudgetLedger,
        fixture_priming_enabled: bool,
    ) -> RedStrategyRuntime | None:
        if not plan.red_policy.model_backed:
            return None
        if self.models is None:
            raise ValueError("model-backed Red requires models configuration")
        if self.red_model_client is None:
            raise ValueError("model-backed Red requires an injected RoleModelClient")
        return RedStrategyRuntime(
            policy=plan.red_policy,
            purpose=plan.purpose,
            target_class=plan.target_class,
            target_mode=plan.target_mode,
            session_mode=plan.session_mode,
            campaign_budget=effective_budget,
            models=self.models,
            model_client=self.red_model_client,
            budget=ledger,
            fixture_priming_enabled=fixture_priming_enabled,
        )

    async def _run_static_single_turn(
        self,
        *,
        case: AttackCase,
        ledger: BudgetLedger,
        campaign_id: str,
        replicate: int,
        target: TargetAdapter,
    ) -> ExecutionResult:
        engine = CampaignEngine(target=target, judge=self.judge, budget=ledger)
        return await engine.run_case(
            case,
            execution_id=_execution_id(campaign_id, case.id, replicate),
        )

    async def _run_static_conversation(
        self,
        *,
        case: AttackCase,
        ledger: BudgetLedger,
        plan: CampaignPlan,
        campaign_id: str,
        replicate: int,
        target: TargetAdapter,
    ) -> ConversationRunResult:
        if case.payload.turns is None:
            raise ValueError(f"static multi-turn case {case.id} has no explicit turn sequence")
        engine = MultiTurnCampaignEngine(
            target=target,
            judge=self.judge,
            conversation_budget=ConversationBudget(
                max_turns=len(case.payload.turns),
                max_backtracks=0,
                max_branches=1,
                continue_after_success=False,
            ),
            budget=ledger,
        )
        return await engine.run_case(
            case,
            ScriptedPayloadStrategy(case),
            session_mode=plan.session_mode,
            conversation_id=_conversation_id(campaign_id, case.id, replicate),
        )

    async def _run_model_conversation(
        self,
        *,
        case: AttackCase,
        ledger: BudgetLedger,
        plan: CampaignPlan,
        campaign_id: str,
        replicate: int,
        red_runtime: RedStrategyRuntime,
        strategy: MultiTurnStrategy,
        target: TargetAdapter,
    ) -> ConversationRunResult:
        engine = MultiTurnCampaignEngine(
            target=target,
            judge=self.judge,
            conversation_budget=red_runtime.conversation_budget,
            budget=ledger,
        )
        return await engine.run_case(
            case,
            strategy,
            session_mode=plan.session_mode,
            conversation_id=_conversation_id(campaign_id, case.id, replicate),
        )

    async def _run_fixture_conversation(
        self,
        *,
        case: AttackCase,
        descriptor: FixtureDescriptor,
        ledger: BudgetLedger,
        plan: CampaignPlan,
        campaign_id: str,
        replicate: int,
        attack_instance_id: str,
        red_runtime: RedStrategyRuntime,
        seen_isolation_ids: set[str],
    ) -> tuple[ConversationRunResult, MultiTurnStrategy]:
        if self.fixture_runtime is None:
            raise RuntimeError("fixture runtime disappeared after preflight")
        prepared = self.fixture_runtime.prepare(case, run_id=attack_instance_id)
        if prepared.descriptor != descriptor:
            self.fixture_runtime.release(prepared)
            raise RuntimeError("fixture descriptor changed between preflight and execution")
        if prepared.isolation_id in seen_isolation_ids:
            self.fixture_runtime.release(prepared)
            raise RuntimeError("fixture isolation ID was reused across trials")
        seen_isolation_ids.add(prepared.isolation_id)
        bound_target = FixtureProvenanceTarget(self.target, prepared)
        primer = FixturePrimer(
            fixture_id=descriptor.fixture_id,
            injection_surface=descriptor.injection_surface.value,
            legitimate_task=descriptor.legitimate_task,
        )
        strategy = red_runtime.strategy_for(case, fixture_primer=primer)
        conversation: ConversationRunResult | None = None
        try:
            conversation = await self._run_model_conversation(
                case=case,
                ledger=ledger,
                plan=plan,
                campaign_id=campaign_id,
                replicate=replicate,
                red_runtime=red_runtime,
                strategy=strategy,
                target=bound_target,
            )
        finally:
            release = self.fixture_runtime.release(prepared)
        if conversation is None:
            raise RuntimeError("fixture conversation failed before producing a result")
        execution = conversation.execution.model_copy(
            update={
                "evidence": conversation.execution.evidence + (release.evidence(),),
            }
        )
        return conversation.model_copy(update={"execution": execution}), strategy

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
        if plan.purpose == CampaignPurpose.EVALUATION:
            if manifest is None:
                raise ValueError("EVALUATION requires a held-out manifest")
            snapshot = build_evaluation_campaign_measurement_snapshot(
                campaign_id=campaign_id,
                target_snapshot_id=target_snapshot_id,
                campaign_configuration_hash=configuration_hash,
                metric_definition_version=METRIC_DEFINITION_VERSION,
                protocol=held_out_evaluation_protocol(),
                attack_policy_fingerprint=attack_fingerprint,
                judge_policy_fingerprint=judge_fingerprint,
                budget_fingerprint=budget_fingerprint,
                manifest=manifest,
            )
        else:
            snapshot = build_campaign_measurement_snapshot(
                campaign_id=campaign_id,
                target_snapshot_id=target_snapshot_id,
                campaign_configuration_hash=configuration_hash,
                metric_definition_version=METRIC_DEFINITION_VERSION,
                protocol=discovery_protocol(),
                attack_policy_fingerprint=attack_fingerprint,
                judge_policy_fingerprint=judge_fingerprint,
                budget_fingerprint=budget_fingerprint,
            )
        return save_campaign_measurement_snapshot(self.repository.engine, snapshot)

    @staticmethod
    def _selected_cases(
        plan: CampaignPlan,
        cases: tuple[AttackCase, ...],
        manifest: HeldOutEvaluationManifest | None,
    ) -> tuple[AttackCase, ...]:
        if plan.purpose == CampaignPurpose.EVALUATION:
            if manifest is None:
                raise ValueError("EVALUATION requires a held-out manifest")
            return select_manifest_cases(cases, manifest=manifest, evaluation=True)
        return select_cases(
            cases,
            target_class=plan.target_class,
            target_mode=plan.target_mode,
            enabled_only=plan.enabled_only,
        )

    @staticmethod
    def _validate_evaluation_identity(
        plan: CampaignPlan,
        *,
        attack_fingerprint: str,
        judge_fingerprint: str,
    ) -> None:
        if plan.purpose != CampaignPurpose.EVALUATION:
            return
        if plan.attack_policy_fingerprint != attack_fingerprint:
            raise ValueError("attack_policy_fingerprint does not match actual Red policy")
        if plan.judge_policy_fingerprint != judge_fingerprint:
            raise ValueError("judge_policy_fingerprint does not match actual Judge policy")


def _attack_payload_hash(
    case: AttackCase,
    descriptor: FixtureDescriptor | None,
) -> str:
    case_hash = fingerprint_attack_case(case).content_hash
    if descriptor is None:
        return case_hash
    return _canonical_hash(
        {
            "case_content_hash": case_hash,
            "fixture_bundle_sha256": descriptor.bundle_sha256,
        }
    )


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()


def _attack_instance_id(campaign_id: str, case_id: str, replicate: int) -> str:
    return "attack-" + sha256(
        f"{campaign_id}:{case_id}:{replicate}".encode()
    ).hexdigest()[:24]


def _execution_id(campaign_id: str, case_id: str, replicate: int) -> str:
    return "exec-" + sha256(
        f"{campaign_id}:{case_id}:{replicate}".encode()
    ).hexdigest()[:24]


def _conversation_id(campaign_id: str, case_id: str, replicate: int) -> str:
    return "conv-" + sha256(
        f"{campaign_id}:{case_id}:{replicate}".encode()
    ).hexdigest()[:24]
