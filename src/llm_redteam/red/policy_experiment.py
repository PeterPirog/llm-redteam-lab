"""Strict held-out experiment loop for multi-turn Red mechanism policies.

This module makes the *mechanism scheduler* the only arm-dependent component. Blue
target, Judge factory, Red model configuration, frozen discovery memory, budgets,
conversation semantics and prompt-generator implementation are bound into the
experiment contract. The executor then produces persistence-grade paired
observations without enabling cross-trial learning on held-out evaluation cases.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from hashlib import sha256
from inspect import isawaitable
from typing import Protocol, runtime_checkable

from ..budget import BudgetLedger
from ..campaigns.multiturn import ConversationBudget, MultiTurnCampaignEngine
from ..domain import AttackCase, CampaignBudget, TargetIdentity
from ..evaluation_protocol import MeasurementProtocol
from ..evaluation_sets import HeldOutEvaluationManifest, select_manifest_cases
from ..judges.base import Judge
from ..model_client import BudgetedRoleModelClient, RoleModelClient
from ..model_roles import ModelRole, ModelsConfig
from ..targets.base import SessionMode, TargetAdapter
from .ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedObservation,
    PairingMode,
    observation_from_run,
)
from .ablation_runner import (
    PairedRedAblationExecution,
    execute_paired_red_ablation_with_observations,
)
from .adaptive import RedCampaignMemory
from .mechanism_adaptive import MechanismAwareAdaptiveRedStrategy
from .mechanisms import MechanismCampaignMemory, MechanismPolicy

_HASH_PATTERN_LENGTH = 64
_STRATEGY_CONTRACT_VERSION = "mechanism-aware-branch-v2"


@dataclass(frozen=True, slots=True)
class TargetTrialBinding:
    """Fresh target plus the persisted Blue snapshot identity it represents."""

    target: TargetAdapter
    target_snapshot_id: str


@dataclass(frozen=True, slots=True)
class JudgeTrialBinding:
    """Judge instance plus its externally reproducible policy fingerprint."""

    judge: Judge
    fingerprint: str


@runtime_checkable
class TargetTrialFactory(Protocol):
    """Create/reset Blue for one trial; arm is intentionally not an input."""

    def __call__(
        self,
        case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> TargetTrialBinding: ...


@runtime_checkable
class JudgeTrialFactory(Protocol):
    """Create the same Judge policy for either arm; arm is intentionally hidden."""

    def __call__(
        self,
        case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> JudgeTrialBinding: ...


@runtime_checkable
class RedModelDelegateFactory(Protocol):
    """Create a fresh provider client with the common Red model configuration."""

    def __call__(
        self,
        case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> RoleModelClient: ...


class MechanismPolicyTrialExecutor:
    """Run one arm while enforcing the common experimental conditions.

    The only arm-dependent choice is `baseline_policy` versus `treatment_policy`.
    Factories do not receive the arm, which prevents accidental target/Judge/model
    branching in normal experiment construction.
    """

    def __init__(
        self,
        *,
        contract: PairedRedAblationContract,
        manifest: HeldOutEvaluationManifest,
        evaluation_cases: Iterable[AttackCase],
        campaign_budget: CampaignBudget,
        conversation_budget: ConversationBudget,
        models_config: ModelsConfig,
        target_factory: TargetTrialFactory,
        judge_factory: JudgeTrialFactory,
        model_delegate_factory: RedModelDelegateFactory,
        baseline_policy: MechanismPolicy,
        treatment_policy: MechanismPolicy,
        red_memory: RedCampaignMemory | None = None,
        mechanism_memory: MechanismCampaignMemory | None = None,
        session_mode: SessionMode = SessionMode.REPLAY,
        duplicate_similarity_threshold: float = 0.92,
        pair_seed_supported: bool = False,
    ) -> None:
        selected = select_manifest_cases(
            evaluation_cases,
            manifest=manifest,
            evaluation=True,
        )
        self.contract = contract
        self.manifest = manifest
        self.evaluation_cases = selected
        self.campaign_budget = campaign_budget
        self.conversation_budget = conversation_budget
        self.models_config = models_config
        self.target_factory = target_factory
        self.judge_factory = judge_factory
        self.model_delegate_factory = model_delegate_factory
        self.baseline_policy = baseline_policy
        self.treatment_policy = treatment_policy
        self.red_memory = red_memory or RedCampaignMemory()
        self.mechanism_memory = mechanism_memory or MechanismCampaignMemory()
        self.session_mode = session_mode
        self.duplicate_similarity_threshold = duplicate_similarity_threshold
        self.pair_seed_supported = pair_seed_supported
        self._seen_targets: list[TargetAdapter] = []
        self._seen_model_delegates: list[RoleModelClient] = []
        self._target_identity_fingerprint: str | None = None

        expected = build_mechanism_policy_ablation_contract(
            experiment_id=contract.experiment_id,
            target_snapshot_id=contract.target_snapshot_id,
            judge_fingerprint=contract.judge_fingerprint,
            campaign_budget=campaign_budget,
            conversation_budget=conversation_budget,
            models_config=models_config,
            manifest=manifest,
            evaluation_cases=selected,
            red_memory=self.red_memory,
            mechanism_memory=self.mechanism_memory,
            baseline_policy=baseline_policy,
            treatment_policy=treatment_policy,
            metric_definition_version=contract.metric_definition_version,
            session_mode=session_mode,
            pairing_mode=contract.pairing_mode,
            duplicate_similarity_threshold=duplicate_similarity_threshold,
        )
        if contract != expected:
            raise ValueError(
                "mechanism-policy ablation contract does not match executable conditions"
            )
        if contract.pairing_mode == PairingMode.CASE_REPLICATE_SEED and not pair_seed_supported:
            raise ValueError(
                "seed-paired ablation requires explicit pair_seed_supported=True"
            )

    async def __call__(
        self,
        arm: AblationArm,
        case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> PairedRedObservation:
        if self.contract.pairing_mode == PairingMode.CASE_REPLICATE_SEED:
            if pair_seed is None or not self.pair_seed_supported:
                raise ValueError("seed-paired trial is missing verified seed support")
        elif pair_seed is not None:
            raise ValueError("unseeded pairing must not supply a pair seed")

        target_binding = self.target_factory(case, replicate, pair_seed)
        if target_binding.target_snapshot_id != self.contract.target_snapshot_id:
            raise ValueError("target factory returned the wrong target snapshot")
        self._require_fresh_instance(target_binding.target, self._seen_targets, "target")
        target_identity = _fingerprint_target_identity(target_binding.target.identity)
        if self._target_identity_fingerprint is None:
            self._target_identity_fingerprint = target_identity
        elif target_identity != self._target_identity_fingerprint:
            raise ValueError("paired experiment target identity changed between trials")

        judge_binding = self.judge_factory(case, replicate, pair_seed)
        if judge_binding.fingerprint != self.contract.judge_fingerprint:
            raise ValueError("judge factory returned a different Judge fingerprint")

        delegate = self.model_delegate_factory(case, replicate, pair_seed)
        self._require_fresh_instance(delegate, self._seen_model_delegates, "Red model client")

        policy = self.baseline_policy if arm == AblationArm.BASELINE else self.treatment_policy
        policy_fingerprint = _arm_policy_fingerprint(
            self.contract.shared_red_stack_fingerprint or "",
            policy,
        )
        expected_policy = (
            self.contract.baseline_policy_fingerprint
            if arm == AblationArm.BASELINE
            else self.contract.treatment_policy_fingerprint
        )
        if policy_fingerprint != expected_policy:
            raise ValueError("runtime mechanism policy fingerprint does not match contract")

        family = case.attack_family[0]
        memory_before = _family_memory_fingerprint(
            family,
            self.red_memory,
            self.mechanism_memory,
        )
        ledger = BudgetLedger(self.campaign_budget)
        budget_before = ledger.snapshot()
        models = BudgetedRoleModelClient(
            delegate,
            models=self.models_config,
            budget=ledger,
        )
        strategy = MechanismAwareAdaptiveRedStrategy(
            case=case,
            target_class=target_binding.target.identity.target_class,
            target_mode=target_binding.target.identity.target_mode,
            conversation_budget=self.conversation_budget,
            models=models,
            memory=self.red_memory,
            mechanism_memory=self.mechanism_memory,
            mechanism_policy=policy,
            duplicate_similarity_threshold=self.duplicate_similarity_threshold,
            cross_trial_learning_enabled=False,
        )
        engine = MultiTurnCampaignEngine(
            target=target_binding.target,
            judge=judge_binding.judge,
            conversation_budget=self.conversation_budget,
            budget=ledger,
        )

        try:
            result = await engine.run_case(
                case,
                strategy,
                session_mode=self.session_mode,
                conversation_id=(
                    f"{self.contract.experiment_id}:{case.id}:{replicate}:{arm.value.lower()}"
                ),
            )
            # Held-out evaluation never updates cross-trial memory. Calling learn still
            # clears per-conversation transient strategy state and verifies that rule.
            strategy.learn(result)
            memory_after = _family_memory_fingerprint(
                family,
                self.red_memory,
                self.mechanism_memory,
            )
            if memory_after != memory_before:
                raise ValueError("held-out Red evaluation mutated frozen discovery memory")
            budget_after = ledger.snapshot()
            return observation_from_run(
                arm=arm,
                replicate=replicate,
                policy_fingerprint=policy_fingerprint,
                result=result,
                budget_before=budget_before,
                budget_after=budget_after,
                pair_seed=pair_seed,
            )
        finally:
            await _maybe_close(delegate)
            await _maybe_close(target_binding.target)

    @staticmethod
    def _require_fresh_instance(
        value: object,
        seen: list[object],
        label: str,
    ) -> None:
        if any(value is previous for previous in seen):
            raise ValueError(f"{label} factory reused mutable trial state")
        seen.append(value)


async def execute_mechanism_policy_ablation(
    *,
    cases: Iterable[AttackCase],
    manifest: HeldOutEvaluationManifest,
    replicates_per_case: int,
    experiment_id: str,
    target_snapshot_id: str,
    judge_fingerprint: str,
    campaign_budget: CampaignBudget,
    conversation_budget: ConversationBudget,
    models_config: ModelsConfig,
    target_factory: TargetTrialFactory,
    judge_factory: JudgeTrialFactory,
    model_delegate_factory: RedModelDelegateFactory,
    baseline_policy: MechanismPolicy,
    treatment_policy: MechanismPolicy,
    red_memory: RedCampaignMemory | None = None,
    mechanism_memory: MechanismCampaignMemory | None = None,
    metric_definition_version: str = "metrics-v1",
    session_mode: SessionMode = SessionMode.REPLAY,
    pairing_mode: PairingMode = PairingMode.CASE_REPLICATE,
    duplicate_similarity_threshold: float = 0.92,
    pair_seed_supported: bool = False,
    protocol: MeasurementProtocol | None = None,
    confidence_level: float = 0.95,
) -> PairedRedAblationExecution:
    """Build, validate and execute one strict mechanism-scheduler held-out ablation."""

    selected = select_manifest_cases(cases, manifest=manifest, evaluation=True)
    shared_red_memory = red_memory or RedCampaignMemory()
    shared_mechanism_memory = mechanism_memory or MechanismCampaignMemory()
    contract = build_mechanism_policy_ablation_contract(
        experiment_id=experiment_id,
        target_snapshot_id=target_snapshot_id,
        judge_fingerprint=judge_fingerprint,
        campaign_budget=campaign_budget,
        conversation_budget=conversation_budget,
        models_config=models_config,
        manifest=manifest,
        evaluation_cases=selected,
        red_memory=shared_red_memory,
        mechanism_memory=shared_mechanism_memory,
        baseline_policy=baseline_policy,
        treatment_policy=treatment_policy,
        metric_definition_version=metric_definition_version,
        session_mode=session_mode,
        pairing_mode=pairing_mode,
        duplicate_similarity_threshold=duplicate_similarity_threshold,
    )
    executor = MechanismPolicyTrialExecutor(
        contract=contract,
        manifest=manifest,
        evaluation_cases=selected,
        campaign_budget=campaign_budget,
        conversation_budget=conversation_budget,
        models_config=models_config,
        target_factory=target_factory,
        judge_factory=judge_factory,
        model_delegate_factory=model_delegate_factory,
        baseline_policy=baseline_policy,
        treatment_policy=treatment_policy,
        red_memory=shared_red_memory,
        mechanism_memory=shared_mechanism_memory,
        session_mode=session_mode,
        duplicate_similarity_threshold=duplicate_similarity_threshold,
        pair_seed_supported=pair_seed_supported,
    )
    return await execute_paired_red_ablation_with_observations(
        cases=selected,
        contract=contract,
        manifest=manifest,
        replicates_per_case=replicates_per_case,
        run_trial=executor,
        protocol=protocol,
        confidence_level=confidence_level,
    )


def build_mechanism_policy_ablation_contract(
    *,
    experiment_id: str,
    target_snapshot_id: str,
    judge_fingerprint: str,
    campaign_budget: CampaignBudget,
    conversation_budget: ConversationBudget,
    models_config: ModelsConfig,
    manifest: HeldOutEvaluationManifest,
    evaluation_cases: Iterable[AttackCase],
    red_memory: RedCampaignMemory,
    mechanism_memory: MechanismCampaignMemory,
    baseline_policy: MechanismPolicy,
    treatment_policy: MechanismPolicy,
    metric_definition_version: str,
    session_mode: SessionMode,
    pairing_mode: PairingMode,
    duplicate_similarity_threshold: float = 0.92,
) -> PairedRedAblationContract:
    """Bind every shared condition needed to attribute change to mechanism policy."""

    selected = select_manifest_cases(
        evaluation_cases,
        manifest=manifest,
        evaluation=True,
    )
    if not selected:
        raise ValueError("mechanism-policy ablation requires held-out evaluation cases")
    if any(case.interaction_mode != "multi_turn" for case in selected):
        raise ValueError("mechanism-policy ablation requires multi_turn cases")
    if not 0.0 <= duplicate_similarity_threshold <= 1.0:
        raise ValueError("duplicate_similarity_threshold must be between 0 and 1")

    red_model_fingerprint = fingerprint_red_model_config(models_config)
    memory_by_family = {
        family: _family_memory_fingerprint(family, red_memory, mechanism_memory)
        for family in sorted({case.attack_family[0] for case in selected})
    }
    shared_stack = _canonical_hash(
        {
            "strategy": "MechanismAwareAdaptiveRedStrategy",
            "strategy_contract_version": _STRATEGY_CONTRACT_VERSION,
            "cross_trial_learning_enabled": False,
            "duplicate_similarity_threshold": duplicate_similarity_threshold,
            "conversation_budget": conversation_budget.model_dump(mode="json"),
            "red_model_config_fingerprint": red_model_fingerprint,
            "frozen_discovery_memory_by_family": memory_by_family,
        }
    )
    return PairedRedAblationContract(
        experiment_id=experiment_id,
        target_snapshot_id=target_snapshot_id,
        judge_fingerprint=_require_hash(judge_fingerprint, "judge_fingerprint"),
        budget_fingerprint=fingerprint_campaign_budget(campaign_budget),
        evaluation_manifest_hash=manifest.content_hash,
        metric_definition_version=metric_definition_version,
        session_mode=session_mode.value,
        changed_component="mechanism_policy",
        baseline_policy_fingerprint=_arm_policy_fingerprint(
            shared_stack,
            baseline_policy,
        ),
        treatment_policy_fingerprint=_arm_policy_fingerprint(
            shared_stack,
            treatment_policy,
        ),
        red_model_config_fingerprint=red_model_fingerprint,
        shared_red_stack_fingerprint=shared_stack,
        pairing_mode=pairing_mode,
    )


def fingerprint_red_model_config(models: ModelsConfig) -> str:
    """Fingerprint only the shared Red planner/mutator model configuration."""

    roles = {}
    for role in (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR):
        config = models.role(role)
        roles[role.value] = config.model_dump(mode="json", by_alias=True)
    return _canonical_hash(
        {
            "model_policy": models.policy.model_dump(mode="json"),
            "roles": roles,
        }
    )


def fingerprint_campaign_budget(budget: CampaignBudget) -> str:
    return _canonical_hash(budget.model_dump(mode="json"))


def _arm_policy_fingerprint(shared_stack_fingerprint: str, policy: MechanismPolicy) -> str:
    _require_hash(shared_stack_fingerprint, "shared_red_stack_fingerprint")
    return _canonical_hash(
        {
            "shared_red_stack_fingerprint": shared_stack_fingerprint,
            "mechanism_policy": policy.descriptor(),
        }
    )


def _family_memory_fingerprint(
    family: str,
    red_memory: RedCampaignMemory,
    mechanism_memory: MechanismCampaignMemory,
) -> str:
    return _canonical_hash(
        {
            "attack_family": family,
            "red": red_memory.snapshot(family).model_dump(mode="json"),
            "mechanism": mechanism_memory.snapshot(family).model_dump(mode="json"),
        }
    )


def _fingerprint_target_identity(identity: TargetIdentity) -> str:
    return _canonical_hash(identity.model_dump(mode="json"))


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(encoded.encode()).hexdigest()


def _require_hash(value: str, field: str) -> str:
    if len(value) != _HASH_PATTERN_LENGTH:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest") from exc
    return value


async def _maybe_close(value: object) -> None:
    closer = getattr(value, "aclose", None)
    if closer is None or not isinstance(closer, Callable):
        return
    result = closer()
    if isawaitable(result):
        await result
