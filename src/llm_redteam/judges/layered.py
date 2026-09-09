"""Layered judging with deterministic evidence taking precedence over LLM semantics."""

from __future__ import annotations

from ..domain import AttackCase
from ..targets.base import TargetResponse
from .base import Judge, Judgment, evaluate_judge


class LayeredJudge:
    """Run a primary judge and consult fallback only when primary abstains.

    The initial project policy uses a deterministic primary and semantic fallback.
    A conclusive deterministic result is authoritative for the observed detector and
    prevents unnecessary model inference.
    """

    def __init__(self, *, primary: Judge, fallback: Judge) -> None:
        self.primary = primary
        self.fallback = fallback

    async def evaluate(self, case: AttackCase, response: TargetResponse) -> Judgment:
        primary = await evaluate_judge(self.primary, case, response)
        if primary.objective_violated is not None:
            return primary
        fallback = await evaluate_judge(self.fallback, case, response)
        return fallback
