"""Provider-independent abstractions for adaptive Red Team planning."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import Field

from ..domain import AttackTier, StrictModel, TargetClass, TargetMode


class AttackHypothesis(StrictModel):
    id: str = Field(min_length=1)
    security_objective_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    expected_failure_signal: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    complexity_tier: AttackTier


class AttackObservation(StrictModel):
    attack_id: str = Field(min_length=1)
    parent_attack_id: str | None = None
    hypothesis_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    generation: int = Field(ge=0)
    objective_violated: bool | None
    model_compromise: bool
    system_compromise: bool
    refused: bool = False
    error: bool = False
    novelty_score: float = Field(ge=0.0, le=1.0, default=1.0)
    notes: str | None = None


class RedPlan(StrictModel):
    hypothesis: AttackHypothesis
    parent_attack_id: str | None = None
    generation: int = Field(ge=0)
    strategy: str = Field(min_length=1)
    stop_reason: str | None = None


@runtime_checkable
class RedPlanner(Protocol):
    """Choose the next hypothesis/strategy from target state and prior evidence."""

    def next_plan(
        self,
        *,
        target_class: TargetClass,
        target_mode: TargetMode,
        security_objective_id: str,
        history: tuple[AttackObservation, ...],
    ) -> RedPlan | None: ...
