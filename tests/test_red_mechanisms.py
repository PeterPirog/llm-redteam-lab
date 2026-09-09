from llm_redteam.campaigns.multiturn import (
    ConversationBudget,
    ConversationState,
    ConversationTurn,
)
from llm_redteam.domain import CompromiseOutcome
from llm_redteam.red.mechanisms import (
    AttackMechanism,
    MechanismCampaignMemory,
    MechanismLearningRecord,
    MechanismPolicy,
)
from llm_redteam.targets.base import SessionMode


def _turn(
    turn_id: str,
    *,
    ordinal: int,
    depth: int,
    parent_turn_id: str | None = None,
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id="b0",
        parent_turn_id=parent_turn_id,
        attacker_message=f"synthetic-probe-{ordinal}",
        target_response="Synthetic protected response.",
        outcome=CompromiseOutcome.PASS,
    )


def test_primer_policy_uses_only_abstract_context_mechanisms() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(conversation_budget=budget)
    state = ConversationState(
        conversation_id="conv-primer",
        attack_id="synthetic-case",
        session_mode=SessionMode.REPLAY,
    )

    guidance = policy.recommend(
        phase="primer",
        conversation=state,
        prior_mechanisms=(),
        historical_trials={},
        historical_successes={},
    )

    assert AttackMechanism.OBJECTIVE_PROBE not in guidance.allowed
    assert AttackMechanism.BRANCH_DIVERSIFICATION not in guidance.allowed
    assert guidance.stagnation_passes == 0
    assert guidance.preferred in guidance.allowed


def test_repeated_passes_recommend_branch_diversification_when_replay_budget_allows() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(conversation_budget=budget, stagnation_threshold=2)
    turns = (
        _turn("turn-1", ordinal=1, depth=1),
        _turn("turn-2", ordinal=2, depth=2, parent_turn_id="turn-1"),
    )
    state = ConversationState(
        conversation_id="conv-stagnant",
        attack_id="synthetic-case",
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="turn-2",
        backtracks=0,
        branches=1,
    )

    guidance = policy.recommend(
        phase="planner",
        conversation=state,
        prior_mechanisms=(
            AttackMechanism.CONTEXT_ACCUMULATION,
            AttackMechanism.CROSS_TURN_COMPOSITION,
        ),
        historical_trials={},
        historical_successes={},
    )

    assert guidance.stagnation_passes == 2
    assert guidance.must_change_mechanism is True
    assert guidance.branch_recommended is True
    assert guidance.preferred == AttackMechanism.BRANCH_DIVERSIFICATION


def test_target_managed_session_never_recommends_replay_branching() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(conversation_budget=budget, stagnation_threshold=2)
    turns = (
        _turn("turn-1", ordinal=1, depth=1),
        _turn("turn-2", ordinal=2, depth=2, parent_turn_id="turn-1"),
    )
    state = ConversationState(
        conversation_id="conv-target-managed",
        attack_id="synthetic-case",
        session_mode=SessionMode.TARGET_MANAGED,
        session_id="server-session",
        turns=turns,
        active_leaf_turn_id="turn-2",
    )

    guidance = policy.recommend(
        phase="planner",
        conversation=state,
        prior_mechanisms=(
            AttackMechanism.CONTEXT_ACCUMULATION,
            AttackMechanism.CROSS_TURN_COMPOSITION,
        ),
        historical_trials={},
        historical_successes={},
    )

    assert guidance.branch_recommended is False
    assert AttackMechanism.BRANCH_DIVERSIFICATION not in guidance.allowed


def test_historical_success_can_outweigh_novelty_without_extra_inference() -> None:
    budget = ConversationBudget(max_turns=5)
    policy = MechanismPolicy(conversation_budget=budget)
    state = ConversationState(
        conversation_id="conv-history",
        attack_id="synthetic-case",
        session_mode=SessionMode.REPLAY,
    )

    guidance = policy.recommend(
        phase="planner",
        conversation=state,
        prior_mechanisms=(),
        historical_trials={AttackMechanism.SEMANTIC_REFRAMING.value: 10},
        historical_successes={AttackMechanism.SEMANTIC_REFRAMING.value: 9},
    )

    assert guidance.preferred == AttackMechanism.SEMANTIC_REFRAMING


def test_mechanism_memory_tracks_sequences_without_transcript_content() -> None:
    memory = MechanismCampaignMemory()
    memory.record(
        MechanismLearningRecord(
            attack_family="synthetic-family",
            mechanisms=(
                AttackMechanism.CONTEXT_ACCUMULATION,
                AttackMechanism.CROSS_TURN_COMPOSITION,
                AttackMechanism.OBJECTIVE_PROBE,
            ),
            successful=True,
            error=False,
        )
    )

    snapshot = memory.snapshot("synthetic-family")

    assert snapshot.trials == 1
    assert snapshot.successes == 1
    assert snapshot.mechanism_successes[AttackMechanism.OBJECTIVE_PROBE.value] == 1
    assert (
        snapshot.transition_successes[
            "context_accumulation->cross_turn_composition"
        ]
        == 1
    )
    assert "synthetic-probe" not in snapshot.compact_text()
