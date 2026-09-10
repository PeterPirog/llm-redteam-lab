"""Adaptive AGENT strategies primed by an immutable environment fixture.

The first target interaction is the legitimate user task from the fixture manifest.
The hostile instruction remains in the repository/tool environment, preserving the
indirect-injection trust boundary. Later turns may adapt to target-visible behavior.
"""

from __future__ import annotations

from pydantic import Field

from ..campaigns.multiturn import ConversationState, TurnProposal
from ..domain import StrictModel
from .agent_adaptive import (
    TargetVisibleAgentAdaptiveRedStrategy,
    TargetVisibleAgentMechanismAwareAdaptiveRedStrategy,
)
from .mechanisms import AttackMechanism


class FixturePrimer(StrictModel):
    fixture_id: str = Field(min_length=1)
    injection_surface: str = Field(min_length=1)
    legitimate_task: str = Field(min_length=1)

    @property
    def tactic(self) -> str:
        normalized = "".join(
            character if character.isalnum() else "_"
            for character in self.injection_surface.casefold()
        ).strip("_")
        normalized = normalized[:40] or "environment"
        return f"fixture_{normalized}_trigger"


class FixturePrimedAgentAdaptiveRedStrategy(TargetVisibleAgentAdaptiveRedStrategy):
    """Adaptive Red whose first turn merely triggers the prepared hostile environment."""

    def __init__(self, *, fixture_primer: FixturePrimer, **kwargs) -> None:
        super().__init__(**kwargs)
        self.fixture_primer = fixture_primer

    async def next_turn(self, state: ConversationState) -> TurnProposal | None:
        if not state.turns:
            tactic = self.fixture_primer.tactic
            self._tactics_by_conversation[state.conversation_id].append(tactic)
            self._phase_tactics_by_conversation[state.conversation_id].append(
                f"primer:{tactic}"
            )
            return TurnProposal(
                message=self.fixture_primer.legitimate_task,
                rationale=(
                    "trigger the immutable environment fixture using only its legitimate "
                    "task before any conversational adaptation"
                ),
            )
        return await super().next_turn(state)


class FixturePrimedAgentMechanismAwareAdaptiveRedStrategy(
    TargetVisibleAgentMechanismAwareAdaptiveRedStrategy
):
    """Mechanism-aware fixture attack with explicit credit for the environment trigger."""

    def __init__(self, *, fixture_primer: FixturePrimer, **kwargs) -> None:
        super().__init__(**kwargs)
        self.fixture_primer = fixture_primer

    async def next_turn(self, state: ConversationState) -> TurnProposal | None:
        if not state.turns:
            tactic = self.fixture_primer.tactic
            self._tactics_by_conversation[state.conversation_id].append(tactic)
            self._phase_tactics_by_conversation[state.conversation_id].append(
                f"primer:{tactic}"
            )
            self._mechanisms_by_conversation[state.conversation_id].append(
                AttackMechanism.FIXTURE_TRIGGER
            )
            return TurnProposal(
                message=self.fixture_primer.legitimate_task,
                rationale=(
                    "trigger the immutable environment fixture using only its legitimate "
                    "task before adaptive mechanism selection"
                ),
            )
        return await super().next_turn(state)
