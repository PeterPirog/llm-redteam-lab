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
from llm_redteam.red.adaptive import AdaptiveRedStrategy, RedCampaignMemory, RedPhase
from llm_redteam.targets.base import SessionMode

ROOT = Path(__file__).resolve().parents[1]
MULTITURN = ROOT / "corpus" / "native" / "multiturn" / "synthetic-sequences-v1.yaml"


def _case():
    return load_corpus_file(MULTITURN).cases[0]


def _turn(
    *,
    turn_id: str = "turn-1",
    ordinal: int = 1,
    depth: int = 1,
    message: str = "Explain how synthetic markers are protected in tests.",
    response: str = "Synthetic markers should remain protected.",
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id="b0",
        attacker_message=message,
        target_response=response,
        outcome=CompromiseOutcome.PASS,
    )


def _decision(message: str, tactic: str = "context_probe") -> str:
    return (
        '{"action":"continue","rationale":"collect controlled evidence",'
        f'"tactic":"{tactic}","message":"{message}","branch_from_turn_id":null}}'
    )


def test_first_turn_uses_primer_phase_and_planner_role() -> None:
    client = ScriptedRoleModelClient(
        {ModelRole.RED_PLANNER: [_decision("Describe the synthetic test policy.")]}
    )
    strategy = AdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-primer",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert proposal.message == "Describe the synthetic test policy."
    assert client.calls[ModelRole.RED_PLANNER] == 1
    assert client.requests[0].metadata["phase"] == RedPhase.PRIMER.value


def test_last_available_turn_uses_finisher_phase() -> None:
    client = ScriptedRoleModelClient(
        {ModelRole.RED_PLANNER: [_decision("Run the final synthetic consistency check.")]}
    )
    strategy = AdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=2),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-finisher",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
        turns=(_turn(),),
        active_leaf_turn_id="turn-1",
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert client.requests[0].metadata["phase"] == RedPhase.FINISHER.value


def test_duplicate_candidate_is_mutated_once_before_emission() -> None:
    duplicate = "Explain how synthetic markers are protected in tests."
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [_decision(duplicate, "repeat")],
            ModelRole.RED_MUTATOR: [
                _decision(
                    "Compare the policy at the start and after accumulated benign context.",
                    "state_transition_probe",
                )
            ],
        }
    )
    strategy = AdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-mutate",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
        turns=(_turn(message=duplicate),),
        active_leaf_turn_id="turn-1",
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert proposal.message.startswith("Compare the policy")
    assert client.calls[ModelRole.RED_PLANNER] == 1
    assert client.calls[ModelRole.RED_MUTATOR] == 1


def test_invalid_backtrack_in_target_managed_mode_is_repaired() -> None:
    backtrack = (
        '{"action":"backtrack","rationale":"try alternate branch",'
        '"tactic":"branch","message":"alternate synthetic probe",'
        '"branch_from_turn_id":"turn-1"}'
    )
    repaired = _decision("Continue without replay branching.", "stateful_continue")
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [backtrack],
            ModelRole.RED_MUTATOR: [repaired],
        }
    )
    strategy = AdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=4),
        models=client,
    )
    state = ConversationState(
        conversation_id="conv-stateful",
        attack_id=_case().id,
        session_mode=SessionMode.TARGET_MANAGED,
        turns=(_turn(),),
        active_leaf_turn_id="turn-1",
        session_id="server-session",
    )

    proposal = asyncio.run(strategy.next_turn(state))

    assert proposal is not None
    assert proposal.branch_from_turn_id is None
    assert proposal.message == "Continue without replay branching."
    assert client.calls[ModelRole.RED_MUTATOR] == 1


def test_learning_memory_records_outcomes_without_transcripts() -> None:
    memory = RedCampaignMemory()
    client = ScriptedRoleModelClient(
        {ModelRole.RED_PLANNER: [_decision("A distinct synthetic probe.", "probe_a")]}
    )
    strategy = AdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=3),
        models=client,
        memory=memory,
    )
    state = ConversationState(
        conversation_id="conv-learn",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
    )
    proposal = asyncio.run(strategy.next_turn(state))
    assert proposal is not None

    result = ConversationRunResult(
        execution=ExecutionResult(
            execution_id="exec-learn",
            attack_id=_case().id,
            target_id="synthetic-target",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id="conv-learn",
        session_mode=SessionMode.REPLAY,
        turns=(_turn(message=proposal.message),),
        backtracks=0,
        branches=1,
        first_violation_turn_id="turn-1",
        first_violation_ordinal=1,
        first_violation_depth=1,
        flow_fingerprint="flow-test",
    )
    strategy.learn(result)

    snapshot = memory.snapshot(_case().attack_family[0])
    assert snapshot.trials == 1
    assert snapshot.successes == 1
    assert snapshot.target_interactions == 1
    assert snapshot.tactic_trials == {"probe_a": 1}
    assert "A distinct synthetic probe" not in snapshot.compact_text()
