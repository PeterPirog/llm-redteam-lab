"""Metrics describing attacker search quality separately from Blue vulnerability."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import fmean

from ..metrics import RateEstimate, wilson_rate
from .base import AttackObservation


@dataclass(frozen=True, slots=True)
class FamilyEffectiveness:
    family: str
    attempts: int
    conclusive_attempts: int
    objective_violations: int
    attack_success_rate: RateEstimate
    refusal_rate: RateEstimate
    error_rate: RateEstimate
    mean_novelty: float


@dataclass(frozen=True, slots=True)
class RedEffectiveness:
    total_attempts: int
    unique_families_tried: int
    successful_families: int
    first_violation_attempt: int | None
    family_summaries: tuple[FamilyEffectiveness, ...]


def summarize_red_history(
    history: tuple[AttackObservation, ...], confidence_level: float = 0.95
) -> RedEffectiveness:
    """Summarize Red search behavior without conflating it with Blue risk."""

    families = sorted({observation.attack_family for observation in history})
    summaries: list[FamilyEffectiveness] = []

    for family in families:
        rows = [observation for observation in history if observation.attack_family == family]
        conclusive = [row for row in rows if row.objective_violated is not None and not row.error]
        violations = sum(row.objective_violated is True for row in conclusive)
        refusals = sum(row.refused for row in rows)
        errors = sum(row.error for row in rows)
        summaries.append(
            FamilyEffectiveness(
                family=family,
                attempts=len(rows),
                conclusive_attempts=len(conclusive),
                objective_violations=violations,
                attack_success_rate=wilson_rate(
                    violations,
                    len(conclusive),
                    confidence_level,
                ),
                refusal_rate=wilson_rate(refusals, len(rows), confidence_level),
                error_rate=wilson_rate(errors, len(rows), confidence_level),
                mean_novelty=fmean(row.novelty_score for row in rows),
            )
        )

    first_violation = next(
        (
            index
            for index, observation in enumerate(history, start=1)
            if observation.objective_violated is True
        ),
        None,
    )
    successful_families = sum(summary.objective_violations > 0 for summary in summaries)

    return RedEffectiveness(
        total_attempts=len(history),
        unique_families_tried=len(families),
        successful_families=successful_families,
        first_violation_attempt=first_violation,
        family_summaries=tuple(summaries),
    )
