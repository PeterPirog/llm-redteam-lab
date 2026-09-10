from pathlib import Path

from llm_redteam.campaigns.multiturn import ConversationBudget, ConversationRunResult, ConversationTurn
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import CompromiseOutcome, ExecutionResult, TargetClass, TargetMode
from llm_redteam.model_client import ScriptedRoleModelClient
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
    parent: str | None,
    response: str,
    outcome: CompromiseOutcome = CompromiseOutcome.PASS,
    branch: str = "b0",
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id=branch,
        parent_turn_id=parent,
        attacker_message=f"probe-{turn_id}",
        target_response=response,
        outcome=outcome,
    )


def test_success_credit_follows_real_branch_not_chronological_order() -> None:
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=_case(),
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=ConversationBudget(max_turns=5),
        models=ScriptedRoleModelClient({}),
    )
    conversation_id = "conv-branch-credit"
    strategy._mechanisms_by_conversation[conversation_id].extend(
        [
            AttackMechanism.CONTEXT_ACCUMULATION,
            AttackMechanism.DECOMPOSITION,
            AttackMechanism.SEMANTIC_REFRAMING,
        ]
    )
    strategy._tactics_by_conversation[conversation_id].extend(["a", "b", "c"])
    strategy._phase_tactics_by_conversation[conversation_id].extend(
        ["primer:a", "planner:b", "planner:c"]
    )

    turns = (
        _turn("t1", ordinal=1, depth=1, parent=None, response="root clue"),
        _turn(
            "t2",
            ordinal=2,
            depth=2,
            parent="t1",
            response="OFF_BRANCH_INJECTION_DO_NOT_REUSE",
        ),
        _turn(
            "t3",
            ordinal=3,
            depth=2,
            parent="t1",
            response="active successful clue",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            branch="b1",
        ),
    )
    result = ConversationRunResult(
        execution=ExecutionResult(
            execution_id="exec-branch-credit",
            attack_id=_case().id,
            target_id="synthetic-target",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id=conversation_id,
        session_mode=SessionMode.REPLAY,
        turns=turns,
        backtracks=1,
        branches=2,
        first_violation_turn_id="t3",
        first_violation_ordinal=3,
        first_violation_depth=2,
        flow_fingerprint="flow-branch-aware",
    )

    strategy.learn(result)

    mechanism = strategy.mechanism_memory.snapshot(_case().attack_family[0])
    assert mechanism.mechanism_trials[AttackMechanism.DECOMPOSITION.value] == 1
    assert AttackMechanism.DECOMPOSITION.value not in mechanism.mechanism_successes
    assert mechanism.mechanism_successes[AttackMechanism.CONTEXT_ACCUMULATION.value] == 1
    assert mechanism.mechanism_successes[AttackMechanism.SEMANTIC_REFRAMING.value] == 1
    assert mechanism.transition_trials["context_accumulation->decomposition"] == 1
    assert mechanism.transition_trials["context_accumulation->semantic_reframing"] == 1
    assert "decomposition->semantic_reframing" not in mechanism.transition_trials
    assert mechanism.transition_successes["context_accumulation->semantic_reframing"] == 1
    assert "context_accumulation->decomposition" not in mechanism.transition_successes

    tactics = strategy.memory.snapshot(_case().attack_family[0])
    assert "planner:b->planner:c" not in tactics.transition_trials
    assert tactics.transition_successes["primer:a->planner:c"] == 1


def test_planner_summary_separates_active_path_from_abandoned_branch_content() -> None:
    turns = (
        _turn("t1", ordinal=1, depth=1, parent=None, response="root clue"),
        _turn(
            "t2",
            ordinal=2,
            depth=2,
            parent="t1",
            response="OFF_BRANCH_INJECTION_DO_NOT_REUSE",
        ),
        _turn(
            "t3",
            ordinal=3,
            depth=2,
            parent="t1",
            response="active clue",
            branch="b1",
        ),
    )
    from llm_redteam.campaigns.multiturn import ConversationState

    state = ConversationState(
        conversation_id="conv-summary",
        attack_id=_case().id,
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="t3",
        backtracks=1,
        branches=2,
    )

    summary = MechanismAwareAdaptiveRedStrategy._conversation_summary(state)

    assert "active clue" in summary
    assert "OFF_BRANCH_INJECTION_DO_NOT_REUSE" not in summary
    assert '"content_omitted":true' in summary
    assert '"turn_id":"t2"' in summary
