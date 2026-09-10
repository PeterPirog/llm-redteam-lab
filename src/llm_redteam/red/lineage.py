"""Branch-aware lineage helpers for multi-turn Red learning and metrics.

Chronological turn order is an execution-cost trace, not necessarily a logical
conversation path after backtracking. These helpers reconstruct parent/child
lineage so adaptive learning never invents transitions across sibling branches.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..campaigns.multiturn import ConversationTurn


def logical_path_turn_ids(
    turns: Sequence[ConversationTurn],
    *,
    endpoint_turn_id: str | None = None,
) -> tuple[str, ...]:
    """Return root-to-endpoint turn IDs for one logical branch.

    If no endpoint is supplied, the most recently executed turn is treated as the
    active leaf. Malformed/cyclic lineage fails closed with ``ValueError`` rather
    than silently producing a fabricated sequence.
    """

    if not turns:
        if endpoint_turn_id is not None:
            raise ValueError("cannot resolve an endpoint in an empty conversation")
        return ()

    by_id = {turn.turn_id: turn for turn in turns}
    if len(by_id) != len(turns):
        raise ValueError("conversation turn IDs must be unique")

    endpoint = endpoint_turn_id or turns[-1].turn_id
    if endpoint not in by_id:
        raise ValueError(f"unknown lineage endpoint: {endpoint}")

    reversed_path: list[str] = []
    seen: set[str] = set()
    current: str | None = endpoint
    while current is not None:
        if current in seen:
            raise ValueError("conversation lineage contains a cycle")
        seen.add(current)
        turn = by_id.get(current)
        if turn is None:
            raise ValueError(f"conversation lineage references unknown parent: {current}")
        reversed_path.append(current)
        current = turn.parent_turn_id

    reversed_path.reverse()
    return tuple(reversed_path)


def branch_transition_turn_ids(
    turns: Sequence[ConversationTurn],
) -> tuple[tuple[str, str], ...]:
    """Return every real parent->child edge in chronological child order."""

    if not turns:
        return ()
    by_id = {turn.turn_id: turn for turn in turns}
    if len(by_id) != len(turns):
        raise ValueError("conversation turn IDs must be unique")

    edges: list[tuple[str, str]] = []
    for turn in turns:
        parent = turn.parent_turn_id
        if parent is None:
            continue
        if parent not in by_id:
            raise ValueError(f"conversation lineage references unknown parent: {parent}")
        edges.append((parent, turn.turn_id))
    return tuple(edges)


def path_transition_turn_ids(path_turn_ids: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """Return adjacent edges on one already reconstructed logical path."""

    return tuple(zip(path_turn_ids, path_turn_ids[1:], strict=False))
