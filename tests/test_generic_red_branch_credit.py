from llm_redteam.campaigns.multiturn import ConversationRunResult, ConversationTurn
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.red.adaptive import RedCampaignMemory, RedLearningRecord
from llm_redteam.red.sequence_metrics import summarize_red_sequences


def _turn(
    turn_id: str,
    ordinal: int,
    depth: int,
    *,
    parent: str | None,
    branch: str,
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id=branch,
        parent_turn_id=parent,
        attacker_message=f"probe-{turn_id}",
        target_response="synthetic",
        outcome=(
            CompromiseOutcome.MODEL_COMPROMISE
            if turn_id == "t3"
            else CompromiseOutcome.PASS
        ),
    )


def _branch_record() -> RedLearningRecord:
    return RedLearningRecord(
        attack_family="multi_turn_escalation",
        tactics=("a", "b", "c"),
        phase_tactics=("primer:a", "planner:b", "planner:c"),
        logical_tactics=("a", "c"),
        logical_phase_tactics=("primer:a", "planner:c"),
        successful_tactics=("a", "c"),
        attempted_transitions=(
            "primer:a->planner:b",
            "primer:a->planner:c",
        ),
        successful_transitions=("primer:a->planner:c",),
        successful=True,
        error=False,
        target_interactions=3,
        backtracks=1,
        first_violation_ordinal=3,
        first_violation_depth=2,
    )


def test_memory_counts_abandoned_tactic_as_trial_but_not_success() -> None:
    memory = RedCampaignMemory()
    memory.record(_branch_record())

    snapshot = memory.snapshot("multi_turn_escalation")

    assert snapshot.tactic_trials == {"a": 1, "b": 1, "c": 1}
    assert snapshot.tactic_successes == {"a": 1, "c": 1}
    assert "b" not in snapshot.tactic_successes
    assert snapshot.transition_trials == {
        "primer:a->planner:b": 1,
        "primer:a->planner:c": 1,
    }
    assert snapshot.transition_successes == {"primer:a->planner:c": 1}
    assert "planner:b->planner:c" not in snapshot.transition_trials
    assert snapshot.sequence_successes == {"primer:a>planner:c": 1}


def test_sequence_metrics_do_not_fabricate_sibling_transition() -> None:
    metrics = summarize_red_sequences((_branch_record(),))

    transitions = {row.signature: row for row in metrics.transition_summaries}
    assert set(transitions) == {
        "primer:a->planner:b",
        "primer:a->planner:c",
    }
    assert "planner:b->planner:c" not in transitions
    assert transitions["primer:a->planner:b"].successes == 0
    assert transitions["primer:a->planner:c"].successes == 1
    assert metrics.sequence_summaries[0].signature == "primer:a>planner:c"
    assert metrics.median_turn_to_success == 3.0
    assert metrics.median_depth_to_success == 2.0


def test_branch_result_represents_cost_ordinal_separately_from_depth() -> None:
    turns = (
        _turn("t1", 1, 1, parent=None, branch="b0"),
        _turn("t2", 2, 2, parent="t1", branch="b0"),
        _turn("t3", 3, 2, parent="t1", branch="b1"),
    )
    result = ConversationRunResult(
        execution=ExecutionResult(
            execution_id="exec-branch",
            attack_id="case",
            target_id="target",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        ),
        conversation_id="conv",
        session_mode="replay",
        turns=turns,
        backtracks=1,
        branches=2,
        first_violation_turn_id="t3",
        first_violation_ordinal=3,
        first_violation_depth=2,
        flow_fingerprint="branch-flow",
    )

    assert result.first_violation_ordinal == 3
    assert result.first_violation_depth == 2
    assert len(result.turns) == 3
