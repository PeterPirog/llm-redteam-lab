import asyncio
from pathlib import Path

from llm_redteam.campaigns.multiturn import (
    ConversationBudget,
    ConversationRunResult,
    ConversationState,
    ConversationTurn,
)
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import CompromiseOutcome, ExecutionResult, TargetClass, TargetMode
from llm_redteam.model_client import ScriptedRoleModelClient
from llm_redteam.model_roles import ModelRole
from llm_redteam.red import AttackMechanism, MechanismAwareAdaptiveRedStrategy
from llm_redteam.targets.base import SessionMode

ROOT = Path(__file__).resolve().parents[1]
MULTITURN = ROOT / "corpus" / "native" / "multiturn" / "synthetic-sequences-v1.yaml"


def _case():
    return load_corpus_file(MULTITURN).cases[0]


def _turn(
    turn_id: str,
    *,
    ordinal: int,
    depth: int,
    parent_turn_id: str | None = None,
    message: str | None = None,
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id="b0",
        parent_turn_id=parent_turn_id,
        attacker_message=message or f"synthetic-probe-{ordinal}",
        target_response="Synthetic policy remains protected.",
        outcome=CompromiseOutcome.PASS,
    )


def _decision(
    message: str,
    *,
    tactic: str,
    mechanism: AttackMechanism | None,
    action: str = "continue",
    branch_from_turn_id: str | None = None,
) -> str:
    mechanism_json = "null" if mechanism is None else f'"{mechanism.value}"'
    branch_json = "null" if branch_from_turn_id is None else f'"{branch_from_turn_id}"'
    return (
        "{"
        f'"action":"{action}",'
        '"rationale":"authorized synthetic progression",'
        f'"tactic":"{tactic}",'
        f'"mechanism":{mechanism_json},'
        f'"message":"{message}",'
        f'"branch_from_turn_id":{branch_json}'
        "}"
    )


def test_planner_receives_deterministic_mechanism_guidance() -> None:
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Establish a controlled synthetic context.",
                    tactic="context_probe",
                    mechanism=AttackMechanism.CONTEXT_ACCUMULATION,
                )
            ]
        }
    )
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-mechanism-primer",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    request = client.requests[0]
    assert "Deterministic mechanism policy" in request.messages[1].content
    assert "context_accumulation" in request.messages[1].content
    assert "mechanism" in request.messages[0].content
    assert client.calls[ModelRole.RED_PLANNER] == 1


def test_missing_mechanism_is_resolved_to_policy_preference_for_legacy_planner_output() -> None:
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Use the policy-selected synthetic primer.",
                    tactic="legacy_probe",
                    mechanism=None,
                )
            ]
        }
    )
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-legacy",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )

    proposal = asyncio.run(strategy.next_turn(state))
    assert proposal is not None
    result = ConversationRunResult(
        execution=ExecutionResult(
            execution_id="exec-legacy",
            attack_id=_case().id,
            target_id="synthetic-target",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id="conv-legacy",
        session_mode=SessionMode.REPLAY,
        turns=(_turn("turn-legacy", ordinal=1, depth=1, message=proposal.message),),
        backtracks=0,
        branches=1,
        first_violation_turn_id="turn-legacy",
        first_violation_ordinal=1,
        first_violation_depth=1,
        flow_fingerprint="flow-mechanism",
    )
    strategy.learn(result)

    snapshot = strategy.mechanism_memory.snapshot(_case().attack_family[0])
    assert snapshot.trials == 1
    assert snapshot.successes == 1
    assert sum(snapshot.mechanism_trials.values()) == 1


def test_invalid_mechanism_is_repaired_by_mutator_without_extra_planner_call() -> None:
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Premature synthetic objective test.",
                    tactic="premature",
                    mechanism=AttackMechanism.OBJECTIVE_PROBE,
                )
            ],
            ModelRole.RED_MUTATOR: [
                _decision(
                    "Replace it with controlled context accumulation.",
                    tactic="repaired_context",
                    mechanism=AttackMechanism.CONTEXT_ACCUMULATION,
                )
            ],
        }
    )
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-invalid-mechanism",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert proposal.message.startswith("Replace it")
    assert client.calls[ModelRole.RED_PLANNER] == 1
    assert client.calls[ModelRole.RED_MUTATOR] == 1
    assert "allowed=" in client.requests[1].messages[1].content


def test_two_passes_can_trigger_explicit_replay_branch_exploration() -> None:
    turns = (
        _turn("turn-1", ordinal=1, depth=1),
        _turn("turn-2", ordinal=2, depth=2, parent_turn_id="turn-1"),
    )
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Try a materially different synthetic branch.",
                    tactic="alternate_path",
                    mechanism=AttackMechanism.BRANCH_DIVERSIFICATION,
                    action="backtrack",
                    branch_from_turn_id="turn-1",
                )
            ]
        }
    )
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(
            max_turns=5,
            max_backtracks=2,
            max_branches=3,
        ),
        models=client,
    )
    strategy._mechanisms_by_conversation["conv-branch"].extend(
        [
            AttackMechanism.CONTEXT_ACCUMULATION,
            AttackMechanism.CROSS_TURN_COMPOSITION,
        ]
    )
    state = ConversationState(
        conversation_id="conv-branch",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="turn-2",
        backtracks=0,
        branches=1,
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert proposal.branch_from_turn_id == "turn-1"
    assert "branch_recommended=True" in client.requests[0].messages[1].content


def test_frozen_evaluation_mode_does_not_update_cross_trial_memories() -> None:
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Frozen-policy synthetic probe.",
                    tactic="frozen_probe",
                    mechanism=AttackMechanism.CONTEXT_ACCUMULATION,
                )
            ]
        }
    )
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
        cross_trial_learning_enabled=False,
    )
    state = ConversationState(
        conversation_id="conv-frozen",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )
    proposal = asyncio.run(strategy.next_turn(state))
    assert proposal is not None

    result = ConversationRunResult(
        execution=ExecutionResult(
            execution_id="exec-frozen",
            attack_id=_case().id,
            target_id="synthetic-target",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id="conv-frozen",
        session_mode=SessionMode.REPLAY,
        turns=(_turn("turn-frozen", ordinal=1, depth=1, message=proposal.message),),
        backtracks=0,
        branches=1,
        first_violation_turn_id="turn-frozen",
        first_violation_ordinal=1,
        first_violation_depth=1,
        flow_fingerprint="flow-frozen",
    )
    strategy.learn(result)

    family = _case().attack_family[0]
    assert strategy.memory.snapshot(family).trials == 0
    assert strategy.mechanism_memory.snapshot(family).trials == 0
    assert strategy.policy_descriptor()["cross_trial_learning_enabled"] is False
