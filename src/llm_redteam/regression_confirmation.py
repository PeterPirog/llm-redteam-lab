"""Repeated regression replay for stochastic target configurations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from pydantic import Field, model_validator

from .domain import StrictModel, TargetIdentity
from .metrics import RateEstimate, wilson_rate
from .regression import (
    RegressionArtifact,
    RegressionChange,
    RegressionComparison,
    RegressionRunner,
    run_regression,
)


class RegressionConfirmationStatus(StrEnum):
    NO_CONCLUSIVE_EVIDENCE = "NO_CONCLUSIVE_EVIDENCE"
    FLAKY = "FLAKY"
    MIXED = "MIXED"
    REPRODUCIBLE = "REPRODUCIBLE"
    CONFIRMED = "CONFIRMED"
    INCOMPARABLE = "INCOMPARABLE"


class RegressionConfirmationPolicy(StrictModel):
    repetitions: int = Field(ge=1, default=3)
    min_reproducible_observations: int = Field(ge=1, default=2)

    @model_validator(mode="after")
    def threshold_fits_repetitions(self) -> RegressionConfirmationPolicy:
        if self.min_reproducible_observations > self.repetitions:
            raise ValueError("min_reproducible_observations cannot exceed repetitions")
        return self


@dataclass(frozen=True, slots=True)
class RegressionConfirmationResult:
    artifact_id: str
    status: RegressionConfirmationStatus
    requested_replays: int
    executed_replays: int
    conclusive_replays: int
    unresolved_replays: int
    dominant_change: RegressionChange | None
    change_counts: dict[RegressionChange, int]
    dominant_change_rate: RateEstimate
    comparisons: tuple[RegressionComparison, ...]


async def confirm_regression(
    *,
    artifact: RegressionArtifact,
    target: TargetIdentity,
    runner: RegressionRunner,
    policy: RegressionConfirmationPolicy | None = None,
    confidence_level: float = 0.95,
) -> RegressionConfirmationResult:
    """Repeat a regression artifact and quantify stability of the observed change.

    Each replay must produce a distinct execution ID. This prevents accidental reuse of
    cached evidence from masquerading as independent repeated observation. The target
    adapter remains responsible for creating a fresh session/workspace where required.
    """

    selected = policy or RegressionConfirmationPolicy()
    if not _compatible_target(artifact, target):
        return RegressionConfirmationResult(
            artifact_id=artifact.artifact_id,
            status=RegressionConfirmationStatus.INCOMPARABLE,
            requested_replays=selected.repetitions,
            executed_replays=0,
            conclusive_replays=0,
            unresolved_replays=0,
            dominant_change=None,
            change_counts={},
            dominant_change_rate=wilson_rate(0, 0, confidence_level),
            comparisons=(),
        )

    comparisons: list[RegressionComparison] = []
    execution_ids: set[str] = set()
    for _ in range(selected.repetitions):
        comparison = await run_regression(artifact, target, runner)
        if comparison.change == RegressionChange.INCOMPARABLE:
            return _incomparable_after_execution(
                artifact,
                selected,
                comparisons + [comparison],
                confidence_level,
            )
        if comparison.current_execution_id is None:
            raise RuntimeError("executed regression replay did not return execution_id")
        if comparison.current_execution_id in execution_ids:
            raise ValueError("regression replay reused an execution_id")
        execution_ids.add(comparison.current_execution_id)
        comparisons.append(comparison)

    conclusive = tuple(
        item for item in comparisons if item.change != RegressionChange.INCONCLUSIVE
    )
    unresolved = len(comparisons) - len(conclusive)
    counts = Counter(item.change for item in conclusive)
    dominant = _unique_dominant(counts)
    dominant_count = counts[dominant] if dominant is not None else 0

    if not conclusive:
        status = RegressionConfirmationStatus.NO_CONCLUSIVE_EVIDENCE
    elif len(conclusive) == selected.repetitions and len(counts) == 1:
        status = RegressionConfirmationStatus.CONFIRMED
    elif dominant is not None and dominant_count >= selected.min_reproducible_observations:
        status = RegressionConfirmationStatus.REPRODUCIBLE
    elif len(counts) > 1:
        status = RegressionConfirmationStatus.MIXED
    else:
        status = RegressionConfirmationStatus.FLAKY

    return RegressionConfirmationResult(
        artifact_id=artifact.artifact_id,
        status=status,
        requested_replays=selected.repetitions,
        executed_replays=len(comparisons),
        conclusive_replays=len(conclusive),
        unresolved_replays=unresolved,
        dominant_change=dominant,
        change_counts=dict(counts),
        dominant_change_rate=wilson_rate(
            dominant_count,
            len(conclusive),
            confidence_level,
        ),
        comparisons=tuple(comparisons),
    )


def _unique_dominant(
    counts: Counter[RegressionChange],
) -> RegressionChange | None:
    if not counts:
        return None
    maximum = max(counts.values())
    leaders = [change for change, count in counts.items() if count == maximum]
    return leaders[0] if len(leaders) == 1 else None


def _compatible_target(artifact: RegressionArtifact, target: TargetIdentity) -> bool:
    return (
        target.id == artifact.source_target_id
        and target.target_class == artifact.source_target_class
        and target.target_mode == artifact.source_target_mode
    )


def _incomparable_after_execution(
    artifact: RegressionArtifact,
    policy: RegressionConfirmationPolicy,
    comparisons: list[RegressionComparison],
    confidence_level: float,
) -> RegressionConfirmationResult:
    return RegressionConfirmationResult(
        artifact_id=artifact.artifact_id,
        status=RegressionConfirmationStatus.INCOMPARABLE,
        requested_replays=policy.repetitions,
        executed_replays=len(comparisons),
        conclusive_replays=0,
        unresolved_replays=len(comparisons),
        dominant_change=None,
        change_counts={},
        dominant_change_rate=wilson_rate(0, 0, confidence_level),
        comparisons=tuple(comparisons),
    )
