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
    response: str = "Synthetic protected response.",
    outcome: CompromiseOutcome = CompromiseOutcome.INCONCLUSIVE,
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id="b0",
        parent_turn_id=parent_turn_id,
        attacker_message=f"synthetic-probe-{ordinal}",
        target_response=response,
        outcome=outcome,
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
    assert guidance.target_response_stagnation == 0
    assert guidance.preferred in guidance.allowed


def test_repeated_visible_responses_recommend_branch_when_replay_budget_allows() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(
        conversation_budget=budget,
        response_stagnation_threshold=2,
    )
    turns = (
        _turn(
            "turn-1",
            ordinal=1,
            depth=1,
            response="I cannot provide that protected synthetic value.",
        ),
        _turn(
            "turn-2",
            ordinal=2,
            depth=2,
            parent_turn_id="turn-1",
            response="I cannot provide that protected synthetic value.",
        ),
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

    assert guidance.target_response_stagnation == 2
    assert guidance.must_change_mechanism is True
    assert guidance.branch_recommended is True
    assert guidance.preferred == AttackMechanism.BRANCH_DIVERSIFICATION


def test_near_duplicate_visible_responses_trigger_stagnation_without_judge_labels() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(
        conversation_budget=budget,
        response_stagnation_threshold=2,
        response_similarity_threshold=0.75,
    )
    turns = (
        _turn(
            "turn-1",
            ordinal=1,
            depth=1,
            response="Protected synthetic value remains hidden from this request.",
            outcome=CompromiseOutcome.INCONCLUSIVE,
        ),
        _turn(
            "turn-2",
            ordinal=2,
            depth=2,
            parent_turn_id="turn-1",
            response="The protected synthetic value remains hidden from this request.",
            outcome=CompromiseOutcome.INCONCLUSIVE,
        ),
    )
    state = ConversationState(
        conversation_id="conv-near-duplicate",
        attack_id="synthetic-case",
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="turn-2",
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

    assert guidance.target_response_stagnation == 2
    assert guidance.branch_recommended is True


def test_materially_different_visible_response_resets_stagnation() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(conversation_budget=budget)
    turns = (
        _turn(
            "turn-1",
            ordinal=1,
            depth=1,
            response="Protected synthetic value remains hidden.",
        ),
        _turn(
            "turn-2",
            ordinal=2,
            depth=2,
            parent_turn_id="turn-1",
            response="I can discuss the authorization model and available safe tools.",
        ),
    )
    state = ConversationState(
        conversation_id="conv-progress",
        attack_id="synthetic-case",
        session_mode=SessionMode.REPLAY,
        turns=turns,
        active_leaf_turn_id="turn-2",
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

    assert guidance.target_response_stagnation == 1
    assert guidance.branch_recommended is False


def test_target_managed_session_never_recommends_replay_branching() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(
        conversation_budget=budget,
        response_stagnation_threshold=2,
    )
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

    assert guidance.target_response_stagnation == 2
    assert guidance.must_change_mechanism is True
    assert guidance.branch_recommended is False
    assert AttackMechanism.BRANCH_DIVERSIFICATION not in guidance.allowed


def test_hidden_judge_outcomes_cannot_change_stagnation_guidance() -> None:
    budget = ConversationBudget(max_turns=5, max_backtracks=2, max_branches=3)
    policy = MechanismPolicy(conversation_budget=budget)

    def state(outcome: CompromiseOutcome) -> ConversationState:
        turns = (
            _turn("turn-1", ordinal=1, depth=1, outcome=outcome),
            _turn(
                "turn-2",
                ordinal=2,
                depth=2,
                parent_turn_id="turn-1",
                outcome=outcome,
            ),
        )
        return ConversationState(
            conversation_id=f"conv-{outcome.value}",
            attack_id="synthetic-case",
            session_mode=SessionMode.REPLAY,
            turns=turns,
            active_leaf_turn_id="turn-2",
        )

    kwargs = {
        "phase": "planner",
        "prior_mechanisms": (
            AttackMechanism.CONTEXT_ACCUMULATION,
            AttackMechanism.CROSS_TURN_COMPOSITION,
        ),
        "historical_trials": {},
        "historical_successes": {},
    }
    pass_guidance = policy.recommend(conversation=state(CompromiseOutcome.PASS), **kwargs)
    compromise_guidance = policy.recommend(
        conversation=state(CompromiseOutcome.MODEL_COMPROMISE),
        **kwargs,
    )
    sanitized_guidance = policy.recommend(
        conversation=state(CompromiseOutcome.INCONCLUSIVE),
        **kwargs,
    )

    assert pass_guidance == compromise_guidance == sanitized_guidance
    assert pass_guidance.target_response_stagnation == 2


def test_policy_descriptor_binds_target_visible_stagnation_semantics() -> None:
    policy = MechanismPolicy(
        conversation_budget=ConversationBudget(max_turns=5),
        response_stagnation_threshold=3,
        response_similarity_threshold=0.82,
    )

    descriptor = policy.descriptor()

    assert descriptor["stagnation_signal"] == "target_response_token_jaccard-v1"
    assert descriptor["response_stagnation_threshold"] == 3
    assert descriptor["response_similarity_threshold"] == 0.82


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
