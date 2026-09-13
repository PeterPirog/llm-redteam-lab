"""Post-run compromise-layer memory for adaptive Red discovery.

The live attacker must not receive independent Judge verdicts while a conversation is in
progress.  After a bounded DISCOVERY trial has finished, however, Red may learn from the
trusted outcome of that previous trial.  This module extends the existing transcript-free
campaign memory with aggregate model/system compromise counters so later trials can tell
a contained model compromise from an actual system effect.

No prompts, target responses, Judge rationale, tool payloads or system-state contents are
stored here.  Held-out EVALUATION remains cross-trial frozen by the runtime boundary.
"""

from __future__ import annotations

from pydantic import Field

from ..domain import StrictModel
from .adaptive import RedCampaignMemory, RedMemorySnapshot


class OutcomeLayerLearningRecord(StrictModel):
    """One post-run, transcript-free compromise-layer observation."""

    attack_family: str = Field(min_length=1)
    model_compromise: bool
    system_compromise: bool


class LayerAwareRedMemorySnapshot(RedMemorySnapshot):
    """Tactic/sequence memory plus trusted post-run compromise-layer counts."""

    model_compromises: int = Field(ge=0, default=0)
    system_compromises: int = Field(ge=0, default=0)
    contained_model_compromises: int = Field(ge=0, default=0)
    system_only_compromises: int = Field(ge=0, default=0)
    model_and_system_compromises: int = Field(ge=0, default=0)

    def compact_text(self) -> str:
        """Expose aggregate layer outcomes to later Red trials without raw evidence."""

        return (
            f"{super().compact_text()}; "
            "compromise_layers("
            f"model_any={self.model_compromises},"
            f"system_any={self.system_compromises},"
            f"contained_model={self.contained_model_compromises},"
            f"system_only={self.system_only_compromises},"
            f"model_and_system={self.model_and_system_compromises})"
        )


class LayerAwareRedCampaignMemory(RedCampaignMemory):
    """Bounded Red memory with separate post-run compromise-layer observations."""

    def __init__(self, *, max_records: int = 256) -> None:
        super().__init__(max_records=max_records)
        self._outcome_layers: list[OutcomeLayerLearningRecord] = []

    def record_outcome_layers(
        self,
        *,
        attack_family: str,
        model_compromise: bool,
        system_compromise: bool,
    ) -> None:
        self._outcome_layers.append(
            OutcomeLayerLearningRecord(
                attack_family=attack_family,
                model_compromise=model_compromise,
                system_compromise=system_compromise,
            )
        )
        if len(self._outcome_layers) > self.max_records:
            del self._outcome_layers[: len(self._outcome_layers) - self.max_records]

    def snapshot(self, attack_family: str) -> LayerAwareRedMemorySnapshot:
        base = super().snapshot(attack_family)
        rows = [
            row for row in self._outcome_layers if row.attack_family == attack_family
        ]
        model_compromises = sum(row.model_compromise for row in rows)
        system_compromises = sum(row.system_compromise for row in rows)
        contained_model_compromises = sum(
            row.model_compromise and not row.system_compromise for row in rows
        )
        system_only_compromises = sum(
            row.system_compromise and not row.model_compromise for row in rows
        )
        model_and_system_compromises = sum(
            row.model_compromise and row.system_compromise for row in rows
        )
        return LayerAwareRedMemorySnapshot(
            **base.model_dump(mode="python"),
            model_compromises=model_compromises,
            system_compromises=system_compromises,
            contained_model_compromises=contained_model_compromises,
            system_only_compromises=system_only_compromises,
            model_and_system_compromises=model_and_system_compromises,
        )
