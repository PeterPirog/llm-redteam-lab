from types import SimpleNamespace

from llm_redteam.budget import BudgetLedger
from llm_redteam.campaign_plan import RedPolicyKind
from llm_redteam.campaigns.multiturn import (
    ConversationRunResult,
    ConversationStopReason,
)
from llm_redteam.domain import (
    CampaignBudget,
    CompromiseOutcome,
    ExecutionResult,
    TargetClass,
    TargetMode,
)
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_client import ScriptedRoleModelClient
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.red.adaptive import RedLearningRecord
from llm_redteam.red.layer_memory import LayerAwareRedCampaignMemory
from llm_redteam.red.runtime import (
    RedStrategyRuntime,
    build_model_backed_red_policy_descriptor,
)
from llm_redteam.targets.base import SessionMode

_FAMILY = "agentic_system_boundary"


def _models() -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner-local",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "max_output_tokens": 64,
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "max_output_tokens": 64,
                },
            },
        }
    )


def _budget() -> CampaignBudget:
    return CampaignBudget(
        max_attacks=4,
        max_generations=2,
        max_turns_per_attack=4,
        max_backtracks_per_attack=0,
        max_branches_per_attack=1,
        max_model_calls=12,
        max_total_output_tokens=2048,
        max_image_generations=0,
        wall_clock_seconds=60,
    )


def _result(outcome: CompromiseOutcome) -> ConversationRunResult:
    flags = {
        CompromiseOutcome.MODEL_COMPROMISE: (True, False),
        CompromiseOutcome.SYSTEM_COMPROMISE: (False, True),
        CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE: (True, True),
        CompromiseOutcome.PASS: (False, False),
    }
    model_compromise, system_compromise = flags[outcome]
    objective_violated = outcome != CompromiseOutcome.PASS
    return ConversationRunResult(
        execution=ExecutionResult(
            execution_id=f"execution-{outcome.value}",
            attack_id="synthetic-case",
            target_id="synthetic-target",
            outcome=outcome,
            objective_violated=objective_violated,
            model_compromise=model_compromise,
            system_compromise=system_compromise,
            confidence=1.0,
        ),
        conversation_id=f"conversation-{outcome.value}",
        session_mode=SessionMode.TARGET_MANAGED,
        turns=(),
        backtracks=0,
        branches=1,
        stop_reason=ConversationStopReason.STRATEGY_STOP,
        flow_fingerprint="synthetic-flow-v1",
    )


class _LearningProbe:
    def __init__(self) -> None:
        self.learned: list[ConversationRunResult] = []

    def learn(self, result: ConversationRunResult) -> None:
        self.learned.append(result)


def test_layer_memory_distinguishes_contained_model_and_system_effects() -> None:
    memory = LayerAwareRedCampaignMemory()
    for index in range(3):
        memory.record(
            RedLearningRecord(
                attack_family=_FAMILY,
                tactics=(f"tactic-{index}",),
                successful=True,
                error=False,
                target_interactions=1,
                backtracks=0,
            )
        )
    memory.record_outcome_layers(
        attack_family=_FAMILY,
        model_compromise=True,
        system_compromise=False,
    )
    memory.record_outcome_layers(
        attack_family=_FAMILY,
        model_compromise=False,
        system_compromise=True,
    )
    memory.record_outcome_layers(
        attack_family=_FAMILY,
        model_compromise=True,
        system_compromise=True,
    )

    snapshot = memory.snapshot(_FAMILY)

    assert snapshot.model_compromises == 2
    assert snapshot.system_compromises == 2
    assert snapshot.contained_model_compromises == 1
    assert snapshot.system_only_compromises == 1
    assert snapshot.model_and_system_compromises == 1
    compact = snapshot.compact_text()
    assert "contained_model=1" in compact
    assert "model_and_system=1" in compact


def test_discovery_runtime_records_layer_outcomes_only_after_trial_learning() -> None:
    budget = _budget()
    runtime = RedStrategyRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        session_mode=SessionMode.TARGET_MANAGED,
        campaign_budget=budget,
        models=_models(),
        model_client=ScriptedRoleModelClient({}),
        budget=BudgetLedger(budget),
    )
    case = SimpleNamespace(attack_family=(_FAMILY,))
    strategy = _LearningProbe()

    runtime.observe(
        case=case,
        strategy=strategy,
        result=_result(CompromiseOutcome.MODEL_COMPROMISE),
    )
    runtime.observe(
        case=case,
        strategy=strategy,
        result=_result(CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE),
    )

    assert len(strategy.learned) == 2
    diagnostics = runtime.diagnostics()
    assert diagnostics is not None
    snapshot = diagnostics.tactic_memory[_FAMILY]
    assert snapshot.model_compromises == 2
    assert snapshot.system_compromises == 1
    assert snapshot.contained_model_compromises == 1
    assert snapshot.model_and_system_compromises == 1


def test_evaluation_runtime_keeps_post_run_layer_learning_frozen() -> None:
    budget = _budget()
    runtime = RedStrategyRuntime(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.EVALUATION,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        session_mode=SessionMode.TARGET_MANAGED,
        campaign_budget=budget,
        models=_models(),
        model_client=ScriptedRoleModelClient({}),
        budget=BudgetLedger(budget),
    )
    case = SimpleNamespace(attack_family=(_FAMILY,))
    strategy = _LearningProbe()

    runtime.observe(
        case=case,
        strategy=strategy,
        result=_result(CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE),
    )

    assert strategy.learned == []
    assert runtime.diagnostics() is None


def test_runtime_descriptor_binds_layer_learning_without_renumbering_runtime() -> None:
    descriptor = build_model_backed_red_policy_descriptor(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        session_mode=SessionMode.TARGET_MANAGED,
        campaign_budget=_budget(),
        models=_models(),
    )
    evaluation = build_model_backed_red_policy_descriptor(
        policy=RedPolicyKind.ADAPTIVE,
        purpose=CampaignPurpose.EVALUATION,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        session_mode=SessionMode.TARGET_MANAGED,
        campaign_budget=_budget(),
        models=_models(),
    )

    assert descriptor["runtime_version"] == 3
    assert descriptor["post_run_learning_signal"] == "outcome-layers-v1"
    assert descriptor["initial_learning_memory"] == "empty-layer-aware-v2"
    assert evaluation["runtime_version"] == 3
    assert evaluation["post_run_learning_signal"] == "disabled"
