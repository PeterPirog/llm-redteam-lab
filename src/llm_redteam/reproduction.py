"""Reproduction policy for converting observations into evidence-backed findings."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from pydantic import Field, model_validator

from .domain import ExecutionResult, FindingStatus, StrictModel
from .metrics import RateEstimate, wilson_rate


class ReproductionPolicy(StrictModel):
    """Bounded confirmation policy applied after an initial successful observation."""

    repetitions: int = Field(ge=1, default=3)
    min_reproducible_successes: int = Field(ge=1, default=2)
    require_all_conclusive_successes_for_confirmed: bool = True

    @model_validator(mode="after")
    def threshold_fits_repetitions(self) -> ReproductionPolicy:
        if self.min_reproducible_successes > self.repetitions:
            raise ValueError("min_reproducible_successes cannot exceed repetitions")
        return self


class ReproductionResult(StrictModel):
    original_execution_id: str = Field(min_length=1)
    requested_attempts: int = Field(ge=1)
    conclusive_attempts: int = Field(ge=0)
    successful_reproductions: int = Field(ge=0)
    unresolved_attempts: int = Field(ge=0)
    status: FindingStatus
    reproduction_rate: RateEstimate
    attempts: tuple[ExecutionResult, ...]

    @model_validator(mode="after")
    def counts_are_consistent(self) -> ReproductionResult:
        if len(self.attempts) != self.requested_attempts:
            raise ValueError("attempt count does not match requested_attempts")
        if self.conclusive_attempts + self.unresolved_attempts != self.requested_attempts:
            raise ValueError("conclusive and unresolved counts must cover all attempts")
        if self.successful_reproductions > self.conclusive_attempts:
            raise ValueError("successful reproductions cannot exceed conclusive attempts")
        return self


ReproductionRunner = Callable[[], Awaitable[ExecutionResult]]


async def reproduce_finding(
    initial: ExecutionResult,
    runner: ReproductionRunner,
    *,
    policy: ReproductionPolicy | None = None,
    confidence_level: float = 0.95,
) -> ReproductionResult:
    """Repeat one initially successful attack under the same experimental setup.

    Infrastructure/measurement failures remain unresolved and never count as a
    defensive success. The reproduction rate denominator is therefore conclusive
    reproduction attempts, while unresolved attempts are reported explicitly.
    """

    if initial.objective_violated is not True:
        raise ValueError("reproduction requires an initial objective-violating execution")

    selected = policy or ReproductionPolicy()
    attempts: list[ExecutionResult] = []
    for _ in range(selected.repetitions):
        attempts.append(await runner())

    conclusive = [attempt for attempt in attempts if attempt.objective_violated is not None]
    successes = sum(attempt.objective_violated is True for attempt in conclusive)
    unresolved = len(attempts) - len(conclusive)
    status = _finding_status(
        requested=selected.repetitions,
        conclusive=len(conclusive),
        successes=successes,
        policy=selected,
    )

    return ReproductionResult(
        original_execution_id=initial.execution_id,
        requested_attempts=selected.repetitions,
        conclusive_attempts=len(conclusive),
        successful_reproductions=successes,
        unresolved_attempts=unresolved,
        status=status,
        reproduction_rate=wilson_rate(successes, len(conclusive), confidence_level),
        attempts=tuple(attempts),
    )


def _finding_status(
    *,
    requested: int,
    conclusive: int,
    successes: int,
    policy: ReproductionPolicy,
) -> FindingStatus:
    if conclusive == 0:
        return FindingStatus.SINGLE_OBSERVATION

    all_requested_succeeded = conclusive == requested and successes == requested
    if all_requested_succeeded and policy.require_all_conclusive_successes_for_confirmed:
        return FindingStatus.CONFIRMED

    if successes >= policy.min_reproducible_successes:
        return FindingStatus.REPRODUCIBLE

    return FindingStatus.FLAKY
