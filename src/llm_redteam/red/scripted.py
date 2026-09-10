"""Deterministic Red strategy for explicit multi-turn corpus trajectories."""

from __future__ import annotations

from ..campaigns.multiturn import ConversationState, TurnProposal
from ..domain import AttackCase, PayloadTurnRole


class ScriptedPayloadStrategy:
    """Replay a declared user-turn sequence as one bounded jailbreak trajectory.

    Explicit sequences are useful as cheap baseline/regression attacks. External
    content and tool-output turns require an environment-aware fixture runner and
    are deliberately rejected here instead of being silently impersonated as user
    messages.
    """

    def __init__(self, case: AttackCase) -> None:
        if case.interaction_mode != "multi_turn" or case.payload.turns is None:
            raise ValueError("ScriptedPayloadStrategy requires a multi_turn turns payload")
        unsupported = {
            turn.role
            for turn in case.payload.turns
            if turn.role != PayloadTurnRole.USER
        }
        if unsupported:
            roles = ", ".join(sorted(role.value for role in unsupported))
            raise ValueError(
                f"environment-aware payload roles require a fixture runner: {roles}"
            )
        self.case = case

    async def next_turn(self, state: ConversationState) -> TurnProposal | None:
        index = len(state.turns)
        turns = self.case.payload.turns or ()
        if index >= len(turns):
            return None
        content = self._render(turns[index].content)
        return TurnProposal(
            message=content,
            rationale=f"scripted corpus trajectory turn {index + 1}/{len(turns)}",
        )

    def _render(self, template: str) -> str:
        rendered = template
        for name, value in self.case.variables.items():
            rendered = rendered.replace("{{" + name + "}}", str(value))
        if "{{" in rendered or "}}" in rendered:
            raise ValueError(f"case {self.case.id} contains unresolved turn variables")
        return rendered
