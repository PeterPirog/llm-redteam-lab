"""Persisted fixed full-cross execution for explicit Red attacker pools.

This runner executes the predeclared attacker x case x replicate allocation under one
shared campaign BudgetLedger. It is intentionally limited to REPLAY sessions in this
first slice: target-managed/AGENT campaigns need a per-trial target lease/reset boundary
before cross-attacker comparisons can be considered isolated.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ..agent_actions import canonical_json_hash
from ..budget import BudgetSnapshot
from ..domain import AttackCase, ExecutionResult
from ..evaluation_sets import fingerprint_attack_case
from ..red.attacker_pool import (
    AttackerPoolContract,
    AttackerPoolTrialAssignment,
    AttackerVariant,
    build_attacker_pool_trial_schedule,
)
from ..red.runtime import RedAttackerPoolRuntime
from ..storage.attacker_pool_execution import (
    AttackerPoolTrialRecord,
    AttackerPoolTrialStatus,
    complete_attacker_pool_assignment,
    ensure_attacker_pool_execution_schema,
    load_attacker_pool_trial_records,
    record_attacker_pool_assignment,
    validate_attacker_pool_campaign_binding,
)
from ..storage.measurement_repository import fingerprint_budget
from ..storage.repository import ExperimentRepository
from ..targets.base import SessionMode, TargetAdapter
from ..judges.base import Judge
from .multiturn import ConversationRunResult, MultiTurnCampaignEngine


@dataclass(frozen=True, slots=True)
class PersistedAttackerPoolRunResult:
    contract_fingerprint: str
    conversations: tuple[ConversationRunResult, ...]
    executions: tuple[ExecutionResult, ...]
    trial_records: tuple[AttackerPoolTrialRecord, ...]
    budget: BudgetSnapshot


def attacker_pool_scope_manifest_hash(cases: tuple[AttackCase, ...]) -> str:
    """Bind the exact case content, not merely case IDs, into a pool experiment scope."""

    rows = [
        {
            "case_id": case.id,
            "content_hash": fingerprint_attack_case(case).content_hash,
        }
        for case in sorted(cases, key=lambda item: item.id)
    ]
    return canonical_json_hash(rows)


def attacker_pool_variants(runtime: RedAttackerPoolRuntime) -> tuple[AttackerVariant, ...]:
    """Derive measurement-layer attacker identities from configured runtime variants."""

    return tuple(
        AttackerVariant(
            id=variant.id,
            planner_fingerprint=variant.planner.configuration_fingerprint,
            mutator_fingerprint=variant.mutator.configuration_fingerprint,
            description=variant.description,
        )
        for variant in runtime.models_config.red_attacker_pool.enabled_variants
    )


def build_attacker_pool_contract(
    *,
    runtime: RedAttackerPoolRuntime,
    experiment_id: str,
    target_snapshot_id: str,
    cases: tuple[AttackCase, ...],
    replicates_per_case: int,
) -> AttackerPoolContract:
    """Build the immutable full-cross contract from actual runtime configuration."""

    first = runtime.runtime_for(runtime.variant_ids[0])
    return AttackerPoolContract(
        experiment_id=experiment_id,
        purpose=first.purpose,
        target_snapshot_id=target_snapshot_id,
        scope_manifest_hash=attacker_pool_scope_manifest_hash(cases),
        budget_fingerprint=fingerprint_budget(
            runtime.budget.budget.model_dump(mode="json")
        ),
        case_ids=tuple(sorted(case.id for case in cases)),
        replicates_per_case=replicates_per_case,
        variants=attacker_pool_variants(runtime),
    )


class PersistedAttackerPoolRunner:
    """Execute and persist one fixed attacker pool without outcome-driven routing."""

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        repository: ExperimentRepository,
        runtime: RedAttackerPoolRuntime,
    ) -> None:
        self.target = target
        self.judge = judge
        self.repository = repository
        self.runtime = runtime

    async def run(
        self,
        *,
        contract: AttackerPoolContract,
        cases: tuple[AttackCase, ...],
        campaign_id: str,
    ) -> PersistedAttackerPoolRunResult:
        """Execute every contract assignment exactly once and persist audit facts.

        An interrupted trial leaves an ``allocated`` record rather than disappearing.
        Callers that own the surrounding campaign lifecycle should then mark the campaign
        failed/inconclusive according to their normal failure policy.
        """

        self._validate_contract(contract=contract, cases=cases, campaign_id=campaign_id)
        ensure_attacker_pool_execution_schema(self.repository.engine)
        validate_attacker_pool_campaign_binding(
            self.repository.engine,
            campaign_id=campaign_id,
            target_snapshot_id=contract.target_snapshot_id,
        )

        schedule = build_attacker_pool_trial_schedule(contract)
        remaining_attacks = (
            self.runtime.budget.budget.max_attacks - self.runtime.budget.snapshot().attacks
        )
        if len(schedule) > remaining_attacks:
            raise ValueError(
                "attacker-pool full-cross allocation exceeds remaining max_attacks budget"
            )

        by_id = {case.id: case for case in cases}
        conversations: list[ConversationRunResult] = []
        executions: list[ExecutionResult] = []

        for assignment in schedule:
            case = by_id[assignment.case_id]
            red_runtime = self.runtime.runtime_for(assignment.variant_id)
            strategy = red_runtime.strategy_for(case)
            attack_instance_id = _pool_attack_instance_id(campaign_id, assignment)
            conversation_id = _pool_conversation_id(campaign_id, assignment)

            self.repository.record_attack(
                attack_instance_id=attack_instance_id,
                campaign_id=campaign_id,
                case_id=case.id,
                attack_family=case.attack_family[0],
                interaction_mode=case.interaction_mode,
                payload_hash=fingerprint_attack_case(case).content_hash,
            )
            record_attacker_pool_assignment(
                self.repository.engine,
                campaign_id=campaign_id,
                contract_fingerprint=contract.contract_fingerprint,
                attack_instance_id=attack_instance_id,
                assignment=assignment,
            )

            before = self.runtime.budget.snapshot()
            engine = MultiTurnCampaignEngine(
                target=self.target,
                judge=self.judge,
                conversation_budget=red_runtime.conversation_budget,
                budget=self.runtime.budget,
            )
            conversation = await engine.run_case(
                case,
                strategy,
                session_mode=SessionMode.REPLAY,
                conversation_id=conversation_id,
            )
            self.repository.save_conversation(
                conversation,
                attack_instance_id=attack_instance_id,
                target_snapshot_id=contract.target_snapshot_id,
            )
            red_runtime.observe(case=case, strategy=strategy, result=conversation)
            after = self.runtime.budget.snapshot()
            delta = _trial_resource_delta(before, after)
            complete_attacker_pool_assignment(
                self.repository.engine,
                attack_instance_id=attack_instance_id,
                execution_id=conversation.execution.execution_id,
                **delta,
            )
            conversations.append(conversation)
            executions.append(conversation.execution)

        records = load_attacker_pool_trial_records(
            self.repository.engine,
            campaign_id=campaign_id,
        )
        if len(records) != len(schedule):
            raise RuntimeError("persisted attacker-pool allocation is incomplete")
        if any(record.status != AttackerPoolTrialStatus.COMPLETED for record in records):
            raise RuntimeError("persisted attacker-pool allocation contains incomplete trials")
        if tuple(record.order_index for record in records) != tuple(
            assignment.order_index for assignment in schedule
        ):
            raise RuntimeError("persisted attacker-pool order diverged from contract schedule")

        return PersistedAttackerPoolRunResult(
            contract_fingerprint=contract.contract_fingerprint,
            conversations=tuple(conversations),
            executions=tuple(executions),
            trial_records=records,
            budget=self.runtime.budget.snapshot(),
        )

    def _validate_contract(
        self,
        *,
        contract: AttackerPoolContract,
        cases: tuple[AttackCase, ...],
        campaign_id: str,
    ) -> None:
        if contract.experiment_id != campaign_id:
            raise ValueError("attacker-pool experiment_id must equal campaign_id")
        actual_snapshot_id = self.repository.target_snapshot_id(self.target.identity)
        if contract.target_snapshot_id != actual_snapshot_id:
            raise ValueError("attacker-pool contract does not match actual Blue target")
        if contract.scope_manifest_hash != attacker_pool_scope_manifest_hash(cases):
            raise ValueError("attacker-pool scope manifest does not match exact case content")
        if tuple(sorted(contract.case_ids)) != tuple(sorted(case.id for case in cases)):
            raise ValueError("attacker-pool contract case IDs do not match supplied cases")
        if len({case.id for case in cases}) != len(cases):
            raise ValueError("attacker-pool cases require unique IDs")
        if contract.budget_fingerprint != fingerprint_budget(
            self.runtime.budget.budget.model_dump(mode="json")
        ):
            raise ValueError("attacker-pool contract budget does not match runtime budget")

        expected_variants = attacker_pool_variants(self.runtime)
        expected = {variant.id: variant.fingerprint for variant in expected_variants}
        observed = {variant.id: variant.fingerprint for variant in contract.variants}
        if observed != expected:
            raise ValueError("attacker-pool contract variants do not match runtime variants")

        for variant_id in self.runtime.variant_ids:
            red_runtime = self.runtime.runtime_for(variant_id)
            if red_runtime.purpose != contract.purpose:
                raise ValueError("attacker-pool purpose does not match Red runtime")
            if red_runtime.session_mode != SessionMode.REPLAY:
                raise ValueError(
                    "persisted attacker-pool runner requires REPLAY until per-trial "
                    "target lease/reset isolation is available"
                )
            if red_runtime.target_class != self.target.identity.target_class:
                raise ValueError("attacker-pool Red target class does not match Blue target")
            if red_runtime.target_mode != self.target.identity.target_mode:
                raise ValueError("attacker-pool Red target mode does not match Blue target")

        for case in cases:
            if case.interaction_mode != "multi_turn":
                raise ValueError("attacker-pool runner currently requires multi_turn cases")
            if case.payload.fixture is not None:
                raise ValueError(
                    "attacker-pool fixture execution requires per-trial target leases and is deferred"
                )


def _pool_attack_instance_id(
    campaign_id: str,
    assignment: AttackerPoolTrialAssignment,
) -> str:
    digest = sha256(
        (
            f"{campaign_id}:{assignment.variant_id}:{assignment.case_id}:"
            f"{assignment.replicate}:attack"
        ).encode()
    ).hexdigest()[:24]
    return f"attack-{digest}"


def _pool_conversation_id(
    campaign_id: str,
    assignment: AttackerPoolTrialAssignment,
) -> str:
    digest = sha256(
        (
            f"{campaign_id}:{assignment.variant_id}:{assignment.case_id}:"
            f"{assignment.replicate}:conversation"
        ).encode()
    ).hexdigest()[:24]
    return f"conv-{digest}"


def _trial_resource_delta(
    before: BudgetSnapshot,
    after: BudgetSnapshot,
) -> dict[str, int]:
    before_calls = dict(before.model_calls_by_role)
    after_calls = dict(after.model_calls_by_role)
    before_tokens = dict(before.output_tokens_by_role)
    after_tokens = dict(after.output_tokens_by_role)
    delta = {
        "target_interactions": after.turns - before.turns,
        "planner_calls": after_calls.get("red_planner", 0)
        - before_calls.get("red_planner", 0),
        "mutator_calls": after_calls.get("red_mutator", 0)
        - before_calls.get("red_mutator", 0),
        "planner_output_tokens": after_tokens.get("red_planner", 0)
        - before_tokens.get("red_planner", 0),
        "mutator_output_tokens": after_tokens.get("red_mutator", 0)
        - before_tokens.get("red_mutator", 0),
    }
    if any(value < 0 for value in delta.values()):
        raise RuntimeError("campaign budget counters moved backwards during attacker-pool trial")
    return delta
