"""Deterministic campaign budget enforcement outside model control."""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic

from .domain import CampaignBudget


class BudgetExceeded(RuntimeError):
    """Raised before an operation that would exceed an authorized campaign budget."""


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    attacks: int
    generations: int
    turns: int
    model_calls: int
    output_tokens: int
    image_generations: int
    non_progress_attempts: int
    elapsed_seconds: float


class BudgetLedger:
    """Fail-closed resource ledger that attacker-controlled content cannot expand."""

    def __init__(self, budget: CampaignBudget) -> None:
        self.budget = budget
        self._started = monotonic()
        self._attacks = 0
        self._generations = 0
        self._turns = 0
        self._model_calls = 0
        self._output_tokens = 0
        self._image_generations = 0
        self._non_progress_attempts = 0

    def reserve_attack(self, count: int = 1) -> None:
        self._reserve("attacks", count, self.budget.max_attacks)
        self._attacks += count

    def reserve_generation(self, count: int = 1) -> None:
        self._reserve("generations", count, self.budget.max_generations)
        self._generations += count

    def reserve_turn(self, count: int = 1) -> None:
        self._reserve("turns", count, self.budget.max_turns_per_attack)
        self._turns += count

    def reserve_model_call(self, *, expected_output_tokens: int = 0) -> None:
        self._reserve("model_calls", 1, self.budget.max_model_calls)
        self._reserve(
            "output_tokens",
            expected_output_tokens,
            self.budget.max_total_output_tokens,
        )
        self._model_calls += 1
        self._output_tokens += expected_output_tokens

    def record_actual_output_tokens(self, *, reserved: int, actual: int) -> None:
        if reserved < 0 or actual < 0:
            raise ValueError("token counts cannot be negative")
        delta = actual - reserved
        if delta > 0:
            self._reserve("output_tokens", delta, self.budget.max_total_output_tokens)
        self._output_tokens += delta
        if self._output_tokens < 0:
            self._output_tokens = 0

    def reserve_image_generation(self, count: int = 1) -> None:
        self._reserve(
            "image_generations",
            count,
            self.budget.max_image_generations,
        )
        self._image_generations += count

    def record_progress(self, *, made_progress: bool) -> None:
        if made_progress:
            self._non_progress_attempts = 0
            return
        next_value = self._non_progress_attempts + 1
        if next_value > self.budget.max_non_progress_attempts:
            raise BudgetExceeded("non-progress attempt limit exceeded")
        self._non_progress_attempts = next_value

    def check_wall_clock(self) -> None:
        if self.elapsed_seconds > self.budget.wall_clock_seconds:
            raise BudgetExceeded("wall-clock campaign budget exceeded")

    @property
    def elapsed_seconds(self) -> float:
        return monotonic() - self._started

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            attacks=self._attacks,
            generations=self._generations,
            turns=self._turns,
            model_calls=self._model_calls,
            output_tokens=self._output_tokens,
            image_generations=self._image_generations,
            non_progress_attempts=self._non_progress_attempts,
            elapsed_seconds=self.elapsed_seconds,
        )

    def _reserve(self, resource: str, count: int, maximum: int) -> None:
        if count < 0:
            raise ValueError(f"{resource} reservation cannot be negative")
        current = self._current(resource)
        if current + count > maximum:
            raise BudgetExceeded(
                f"{resource} budget exceeded: requested={count}, current={current}, max={maximum}"
            )
        self.check_wall_clock()

    def _current(self, resource: str) -> int:
        return {
            "attacks": self._attacks,
            "generations": self._generations,
            "turns": self._turns,
            "model_calls": self._model_calls,
            "output_tokens": self._output_tokens,
            "image_generations": self._image_generations,
        }[resource]
