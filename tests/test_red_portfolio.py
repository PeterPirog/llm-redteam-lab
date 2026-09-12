from llm_redteam.campaigns.multiturn import (
    ConversationBudget,
    ConversationState,
    ConversationTurn,
)
from llm_redteam.domain import CompromiseOutcome
from llm_redteam.red import AttackMechanism, RiskAwarePortfolioPolicy
from llm_redteam.targets.base import SessionMode


def _turn(
    turn_id: str,
    ordinal: int,
    depth: int,
    *,
    parent: str | None = None,
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id="b0",
        parent_turn_id=parent,
        attacker_message=f"probe-{ordinal}",
        target_response="synthetic protected response",
        outcome=CompromiseOutcome.INCONCLUSIVE,
    )


def test_transition_evidence_can_change_portfolio_preference() -> None:
    budget = ConversationBudget(max_turns=5)
    policy = RiskAwarePortfolioPolicy(conversation_budget=budget)
    state = ConversationState(
        conversation_id="conv-transition",
        attack_id="case",
        session_mode=SessionMode.REPLAY,
        turns=(_turn("t1", 1, 1),),
        active_leaf_turn_id="t1",
    )
    prior = (AttackMechanism.CONTEXT_ACCUMULATION,)
    trials = {
        AttackMechanism.CROSS_TURN_COMPOSITION.value: 10,
        AttackMechanism.SEMANTIC_REFRAMING.value: 10,
    }
    successes = {
        AttackMechanism.CROSS_TURN_COMPOSITION.value: 5,
        AttackMechanism.SEMANTIC_REFRAMING.value: 5,
    }
    transition_trials = {
        "context_accumulation->cross_turn_composition": 10,
        "context_accumulation->semantic_reframing": 10,
    }
    transition_successes = {
        "context_accumulation->cross_turn_composition": 1,
        "context_accumulation->semantic_reframing": 9,
    }

    guidance = policy.recommend(
        phase="planner",
        conversation=state,
        prior_mechanisms=prior,
        historical_trials=trials,
        historical_successes=successes,
        historical_transition_trials=transition_trials,
        historical_transition_successes=transition_successes,
    )

    assert guidance.preferred == AttackMechanism.SEMANTIC_REFRAMING
    assert (
        guidance.candidate_scores[AttackMechanism.SEMANTIC_REFRAMING.value]
        > guidance.candidate_scores[AttackMechanism.CROSS_TURN_COMPOSITION.value]
    )


def test_exploration_bonus_decays_as_turn_budget_is_consumed() -> None:
    budget = ConversationBudget(max_turns=5)
    policy = RiskAwarePortfolioPolicy(conversation_budget=budget)
    early = ConversationState(
        conversation_id="early",
        attack_id="case",
        session_mode=SessionMode.REPLAY,
    )
    late_turns = (
        _turn("t1", 1, 1),
        _turn("t2", 2, 2, parent="t1"),
        _turn("t3", 3, 3, parent="t2"),
        _turn("t4", 4, 4, parent="t3"),
    )
    late = ConversationState(
        conversation_id="late",
        attack_id="case",
        session_mode=SessionMode.REPLAY,
        turns=late_turns,
        active_leaf_turn_id="t4",
    )

    early_scores = policy.score_candidates(
        phase="primer",
        conversation=early,
        prior_mechanisms=(),
        historical_trials={},
        historical_successes={},
    )
    late_scores = policy.score_candidates(
        phase="primer",
        conversation=late,
        prior_mechanisms=(),
        historical_trials={},
        historical_successes={},
    )

    assert early_scores[0].exploration_bonus > late_scores[0].exploration_bonus


def test_materially_better_alternative_can_trigger_early_branch() -> None:
    budget = ConversationBudget(max_turns=6, max_backtracks=2, max_branches=3)
    policy = RiskAwarePortfolioPolicy(
        conversation_budget=budget,
        response_stagnation_threshold=3,
        branch_advantage_threshold=0.05,
    )
    turns = (
        _turn("t1", 1, 1),
        _turn("t2", 2, 2, parent="t1"),
    )
    state = ConversationState(
        conversation_id="conv-branch",
        attack_id="case",
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="t2",
    )
    prior = (
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.CROSS_TURN_COMPOSITION,
    )
    trials = {
        AttackMechanism.CROSS_TURN_COMPOSITION.value: 10,
        AttackMechanism.SEMANTIC_REFRAMING.value: 10,
    }
    successes = {
        AttackMechanism.CROSS_TURN_COMPOSITION.value: 1,
        AttackMechanism.SEMANTIC_REFRAMING.value: 9,
    }

    guidance = policy.recommend(
        phase="planner",
        conversation=state,
        prior_mechanisms=prior,
        historical_trials=trials,
        historical_successes=successes,
    )

    assert guidance.target_response_stagnation == 2
    assert guidance.branch_recommended is True
    assert guidance.preferred == AttackMechanism.BRANCH_DIVERSIFICATION
    assert guidance.recommended_branch_from_turn_id == "t1"


def test_finisher_is_not_spent_on_portfolio_exploration() -> None:
    policy = RiskAwarePortfolioPolicy(conversation_budget=ConversationBudget(max_turns=5))
    state = ConversationState(
        conversation_id="finisher",
        attack_id="case",
        session_mode=SessionMode.REPLAY,
    )

    guidance = policy.recommend(
        phase="finisher",
        conversation=state,
        prior_mechanisms=(),
        historical_trials={},
        historical_successes={},
    )

    assert guidance.preferred == AttackMechanism.OBJECTIVE_PROBE
    assert guidance.allowed == (AttackMechanism.OBJECTIVE_PROBE,)


def test_policy_descriptor_captures_ablation_relevant_parameters() -> None:
    policy = RiskAwarePortfolioPolicy(
        conversation_budget=ConversationBudget(max_turns=5),
        response_stagnation_threshold=3,
        response_similarity_threshold=0.83,
        transition_weight=0.42,
        branch_advantage_threshold=0.07,
    )

    descriptor = policy.descriptor()

    assert descriptor["type"] == "RiskAwarePortfolioPolicy"
    assert descriptor["stagnation_signal"] == "target_response_token_jaccard-v1"
    assert descriptor["response_stagnation_threshold"] == 3
    assert descriptor["response_similarity_threshold"] == 0.83
    assert descriptor["transition_weight"] == 0.42
    assert descriptor["branch_advantage_threshold"] == 0.07
