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
    turns_by_attack: tuple[tuple[str, int], ...]
    model_calls: int
    model_calls_by_role: tuple[tuple[str, int], ...]
    output_tokens: int
    output_tokens_by_role: tuple[tuple[str, int], ...]
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
        self._turns_by_attack: dict[str, int] = {}
        self._model_calls = 0
        self._model_calls_by_role: dict[str, int] = {}
        self._output_tokens = 0
        self._output_tokens_by_role: dict[str, int] = {}
        self._image_generations = 0
        self._non_progress_attempts = 0

    def reserve_attack(self, count: int = 1) -> None:
        self._reserve("attacks", count, self.budget.max_attacks)
        self._attacks += count

    def reserve_generation(self, count: int = 1) -> None:
        self._reserve("generations", count, self.budget.max_generations)
        self._generations += count

    def reserve_turn(self, *, attack_id: str = "__default__", count: int = 1) -> None:
        """Reserve target interaction turns for one attack conversation.

        ``max_turns_per_attack`` is deliberately enforced per attack rather than
        globally. A global implementation would make later attacks inherit the
        turn consumption of earlier attacks and would bias multi-turn metrics.
        """

        if not attack_id:
            raise ValueError("attack_id cannot be empty")
        if count < 0:
            raise ValueError("turn reservation cannot be negative")
        current = self._turns_by_attack.get(attack_id, 0)
        maximum = self.budget.max_turns_per_attack
        self._check_reservation(
            resource=f"turns[{attack_id}]",
            current=current,
            count=count,
            maximum=maximum,
        )
        self.check_wall_clock()
        self._turns_by_attack[attack_id] = current + count
        self._turns += count

    def reserve_model_call(
        self,
        *,
        role: str = "__default__",
        expected_output_tokens: int = 0,
    ) -> None:
        """Atomically reserve one inference call and its expected output budget."""

        if not role:
            raise ValueError("role cannot be empty")
        if expected_output_tokens < 0:
            raise ValueError("expected_output_tokens cannot be negative")

        self._reserve("model_calls", 1, self.budget.max_model_calls)
        self._reserve(
            "output_tokens",
            expected_output_tokens,
            self.budget.max_total_output_tokens,
        )

        role_calls = self._model_calls_by_role.get(role, 0)
        role_call_limit = self.budget.max_model_calls_by_role.get(role)
        if role_call_limit is not None:
            self._check_reservation(
                resource=f"model_calls[{role}]",
                current=role_calls,
                count=1,
                maximum=role_call_limit,
            )

        role_tokens = self._output_tokens_by_role.get(role, 0)
        role_token_limit = self.budget.max_output_tokens_by_role.get(role)
        if role_token_limit is not None:
            self._check_reservation(
                resource=f"output_tokens[{role}]",
                current=role_tokens,
                count=expected_output_tokens,
                maximum=role_token_limit,
            )

        self.check_wall_clock()
        self._model_calls += 1
        self._model_calls_by_role[role] = role_calls + 1
        self._output_tokens += expected_output_tokens
        self._output_tokens_by_role[role] = role_tokens + expected_output_tokens

    def record_actual_output_tokens(
        self,
        *,
        reserved: int,
        actual: int,
        role: str = "__default__",
    ) -> None:
        if not role:
            raise ValueError("role cannot be empty")
        if reserved < 0 or actual < 0:
            raise ValueError("token counts cannot be negative")
        delta = actual - reserved
        if delta > 0:
            self._reserve("output_tokens", delta, self.budget.max_total_output_tokens)
            role_limit = self.budget.max_output_tokens_by_role.get(role)
            if role_limit is not None:
                self._check_reservation(
                    resource=f"output_tokens[{role}]",
                    current=self._output_tokens_by_role.get(role, 0),
                    count=delta,
                    maximum=role_limit,
                )
            self.check_wall_clock()

        self._output_tokens = max(0, self._output_tokens + delta)
        current_role_tokens = self._output_tokens_by_role.get(role, 0)
        self._output_tokens_by_role[role] = max(0, current_role_tokens + delta)

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
            turns_by_attack=tuple(sorted(self._turns_by_attack.items())),
            model_calls=self._model_calls,
            model_calls_by_role=tuple(sorted(self._model_calls_by_role.items())),
            output_tokens=self._output_tokens,
            output_tokens_by_role=tuple(sorted(self._output_tokens_by_role.items())),
            image_generations=self._image_generations,
            non_progress_attempts=self._non_progress_attempts,
            elapsed_seconds=self.elapsed_seconds,
        )

    def _reserve(self, resource: str, count: int, maximum: int) -> None:
        if count < 0:
            raise ValueError(f"{resource} reservation cannot be negative")
        current = self._current(resource)
        self._check_reservation(
            resource=resource,
            current=current,
            count=count,
            maximum=maximum,
        )
        self.check_wall_clock()

    @staticmethod
    def _check_reservation(
        *,
        resource: str,
        current: int,
        count: int,
        maximum: int,
    ) -> None:
        if current + count > maximum:
            raise BudgetExceeded(
                f"{resource} budget exceeded: requested={count}, current={current}, max={maximum}"
            )

    def _current(self, resource: str) -> int:
        return {
            "attacks": self._attacks,
            "generations": self._generations,
            "turns": self._turns,
            "model_calls": self._model_calls,
            "output_tokens": self._output_tokens,
            "image_generations": self._image_generations,
        }[resource]
