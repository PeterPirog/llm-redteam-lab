"""Persisted fixed full-cross execution for explicit Red attacker pools.

The runner executes the predeclared attacker x case x replicate allocation under one
shared campaign BudgetLedger. Transcript replay alone is not treated as system-state
isolation: pipeline and agent targets require a trusted per-trial target lease even when
conversation history is replayed explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ..agent_actions import canonical_json_hash
from ..budget import BudgetSnapshot
from ..domain import AttackCase, ExecutionResult
from ..evaluation_sets import fingerprint_attack_case
from ..judges.base import Judge
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
from ..storage.target_trial_isolation import (
    TargetTrialIsolationRecord,
    ensure_target_trial_isolation_schema,
    load_target_trial_isolation_records,
    record_target_trial_isolation_acquired,
    record_target_trial_isolation_released,
)
from ..target_trial_isolation import (
    IsolationProvenanceTarget,
    TargetTrialLease,
    TargetTrialLeaseProvider,
    minimum_isolation_level,
    validate_target_trial_lease,
)
from ..targets.base import SessionMode, TargetAdapter
from .multiturn import ConversationRunResult, MultiTurnCampaignEngine


@dataclass(frozen=True, slots=True)
class PersistedAttackerPoolRunResult:
    contract_fingerprint: str
    conversations: tuple[ConversationRunResult, ...]
    executions: tuple[ExecutionResult, ...]
    trial_records: tuple[AttackerPoolTrialRecord, ...]
    isolation_records: tuple[TargetTrialIsolationRecord, ...]
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
    """Execute one fixed attacker pool with explicit Blue state-isolation boundaries."""

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        repository: ExperimentRepository,
        runtime: RedAttackerPoolRuntime,
        target_lease_provider: TargetTrialLeaseProvider | None = None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.repository = repository
        self.runtime = runtime
        self.target_lease_provider = target_lease_provider

    async def run(
        self,
        *,
        contract: AttackerPoolContract,
        cases: tuple[AttackCase, ...],
        campaign_id: str,
    ) -> PersistedAttackerPoolRunResult:
        """Execute every contract assignment exactly once and persist audit facts.

        An interrupted trial leaves an ``allocated`` record rather than disappearing.
        If an isolated target was acquired, its acquisition and teardown proofs are
        persisted independently from target execution so containment evidence survives
        transport/model failures.
        """

        self._validate_contract(contract=contract, cases=cases, campaign_id=campaign_id)
        ensure_attacker_pool_execution_schema(self.repository.engine)
        ensure_target_trial_isolation_schema(self.repository.engine)
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

            trial_target, lease = self._acquire_trial_target(
                red_runtime=red_runtime,
                attack_instance_id=attack_instance_id,
            )
            before = self.runtime.budget.snapshot()
            conversation: ConversationRunResult | None = None
            release = None
            try:
                engine = MultiTurnCampaignEngine(
                    target=trial_target,
                    judge=self.judge,
                    conversation_budget=red_runtime.conversation_budget,
                    budget=self.runtime.budget,
                )
                conversation = await engine.run_case(
                    case,
                    strategy,
                    session_mode=red_runtime.session_mode,
                    conversation_id=conversation_id,
                )
            finally:
                if lease is not None:
                    if self.target_lease_provider is None:
                        raise RuntimeError("target lease provider disappeared during trial")
                    release = self.target_lease_provider.release(lease)
                    record_target_trial_isolation_released(
                        self.repository.engine,
                        attack_instance_id=attack_instance_id,
                        release=release,
                    )
                    if not release.cleanup_complete:
                        raise RuntimeError("target-isolation teardown did not complete")

            if conversation is None:
                raise RuntimeError("attacker-pool trial ended without a conversation result")
            if release is not None:
                execution = conversation.execution.model_copy(
                    update={
                        "evidence": (
                            *conversation.execution.evidence,
                            release.evidence(),
                        )
                    }
                )
                conversation = conversation.model_copy(update={"execution": execution})

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
        self._validate_completed_schedule(records=records, schedule=schedule)
        isolation_records = load_target_trial_isolation_records(
            self.repository.engine,
            attack_instance_ids=tuple(record.attack_instance_id for record in records),
        )
        self._validate_isolation_records(
            records=records,
            isolation_records=isolation_records,
        )

        return PersistedAttackerPoolRunResult(
            contract_fingerprint=contract.contract_fingerprint,
            conversations=tuple(conversations),
            executions=tuple(executions),
            trial_records=records,
            isolation_records=isolation_records,
            budget=self.runtime.budget.snapshot(),
        )

    def _acquire_trial_target(
        self,
        *,
        red_runtime,
        attack_instance_id: str,
    ) -> tuple[TargetAdapter, TargetTrialLease | None]:
        required = minimum_isolation_level(
            target_mode=self.target.identity.target_mode,
            session_mode=red_runtime.session_mode,
        )
        if required is None:
            return self.target, None
        if self.target_lease_provider is None:
            raise ValueError("attacker-pool trial requires a target isolation lease provider")

        lease = self.target_lease_provider.acquire(
            expected_identity=self.target.identity,
            trial_id=attack_instance_id,
        )
        try:
            validate_target_trial_lease(
                lease,
                expected_identity=self.target.identity,
                session_mode=red_runtime.session_mode,
            )
            record_target_trial_isolation_acquired(
                self.repository.engine,
                attack_instance_id=attack_instance_id,
                attestation=lease.attestation,
            )
        except Exception:
            release = self.target_lease_provider.release(lease)
            if not release.cleanup_complete:
                raise RuntimeError(
                    "target-isolation cleanup failed after rejected acquisition"
                )
            raise
        return IsolationProvenanceTarget(lease.target, lease.attestation), lease

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

        session_modes: set[SessionMode] = set()
        for variant_id in self.runtime.variant_ids:
            red_runtime = self.runtime.runtime_for(variant_id)
            session_modes.add(red_runtime.session_mode)
            if red_runtime.purpose != contract.purpose:
                raise ValueError("attacker-pool purpose does not match Red runtime")
            if red_runtime.target_class != self.target.identity.target_class:
                raise ValueError("attacker-pool Red target class does not match Blue target")
            if red_runtime.target_mode != self.target.identity.target_mode:
                raise ValueError("attacker-pool Red target mode does not match Blue target")
        if len(session_modes) != 1:
            raise ValueError("attacker-pool variants must use the same session mode")
        session_mode = next(iter(session_modes))
        required = minimum_isolation_level(
            target_mode=self.target.identity.target_mode,
            session_mode=session_mode,
        )
        if required is not None and self.target_lease_provider is None:
            raise ValueError(
                "attacker-pool target/session mode requires a per-trial isolation provider"
            )

        for case in cases:
            if case.interaction_mode != "multi_turn":
                raise ValueError("attacker-pool runner currently requires multi_turn cases")
            if case.payload.fixture is not None:
                raise ValueError(
                    "attacker-pool fixture execution needs compound fixture/target isolation "
                    "and remains deferred"
                )

    @staticmethod
    def _validate_completed_schedule(
        *,
        records: tuple[AttackerPoolTrialRecord, ...],
        schedule: tuple[AttackerPoolTrialAssignment, ...],
    ) -> None:
        if len(records) != len(schedule):
            raise RuntimeError("persisted attacker-pool allocation is incomplete")
        if any(record.status != AttackerPoolTrialStatus.COMPLETED for record in records):
            raise RuntimeError("persisted attacker-pool allocation contains incomplete trials")
        if tuple(record.order_index for record in records) != tuple(
            assignment.order_index for assignment in schedule
        ):
            raise RuntimeError("persisted attacker-pool order diverged from contract schedule")

    def _validate_isolation_records(
        self,
        *,
        records: tuple[AttackerPoolTrialRecord, ...],
        isolation_records: tuple[TargetTrialIsolationRecord, ...],
    ) -> None:
        first = self.runtime.runtime_for(self.runtime.variant_ids[0])
        required = minimum_isolation_level(
            target_mode=self.target.identity.target_mode,
            session_mode=first.session_mode,
        )
        if required is None:
            if isolation_records:
                raise RuntimeError("unexpected target-isolation evidence for stateless MODEL+REPLAY")
            return
        if len(isolation_records) != len(records):
            raise RuntimeError("target-isolation evidence is incomplete for attacker-pool trials")
        if len({record.lease_id_hash for record in isolation_records}) != len(isolation_records):
            raise RuntimeError("target-isolation lease identity was reused across trials")
        for record in isolation_records:
            if not record.control_plane_independent:
                raise RuntimeError("target isolation was not control-plane independent")
            if record.isolation_level < required:
                raise RuntimeError("persisted target isolation is weaker than required")
            if record.teardown_proof_hash is None or record.cleanup_complete is not True:
                raise RuntimeError("target-isolation teardown evidence is incomplete")


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
