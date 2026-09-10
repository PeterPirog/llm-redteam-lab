import pytest

from llm_redteam.campaigns.multiturn import ConversationTurn
from llm_redteam.domain import CompromiseOutcome
from llm_redteam.red.lineage import (
    branch_transition_turn_ids,
    logical_path_turn_ids,
    path_transition_turn_ids,
)


def _turn(
    turn_id: str,
    ordinal: int,
    depth: int,
    *,
    parent: str | None = None,
    branch: str = "b0",
) -> ConversationTurn:
    return ConversationTurn(
        turn_id=turn_id,
        ordinal=ordinal,
        depth=depth,
        branch_id=branch,
        parent_turn_id=parent,
        attacker_message=f"probe-{turn_id}",
        target_response="synthetic response",
        outcome=CompromiseOutcome.PASS,
    )


def test_backtracking_reconstructs_real_logical_path_not_chronology() -> None:
    turns = (
        _turn("t1", 1, 1),
        _turn("t2", 2, 2, parent="t1"),
        _turn("t3", 3, 2, parent="t1", branch="b1"),
    )

    path = logical_path_turn_ids(turns, endpoint_turn_id="t3")

    assert path == ("t1", "t3")
    assert branch_transition_turn_ids(turns) == (("t1", "t2"), ("t1", "t3"))
    assert path_transition_turn_ids(path) == (("t1", "t3"),)
    assert ("t2", "t3") not in branch_transition_turn_ids(turns)


def test_lineage_rejects_unknown_parent_instead_of_fabricating_sequence() -> None:
    turns = (_turn("t1", 1, 1, parent="missing"),)

    with pytest.raises(ValueError, match="unknown parent"):
        logical_path_turn_ids(turns, endpoint_turn_id="t1")


def test_lineage_rejects_cycles() -> None:
    turns = (
        _turn("t1", 1, 1, parent="t2"),
        _turn("t2", 2, 2, parent="t1"),
    )

    with pytest.raises(ValueError, match="cycle"):
        logical_path_turn_ids(turns, endpoint_turn_id="t2")
