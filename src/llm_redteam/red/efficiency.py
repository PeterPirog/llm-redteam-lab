"""Cost-aware metrics for adaptive Red, separate from Blue vulnerability metrics."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import fmean, median

from ..budget import BudgetSnapshot
from ..campaigns.multiturn import ConversationRunResult
from .metrics import RedEffectiveness


@dataclass(frozen=True, slots=True)
class AdaptiveRedEfficiency:
    """Describe attacker search efficiency without reinterpreting Blue ASR."""

    conversations: int
    conclusive_conversations: int
    successful_conversations: int
    target_interactions: int
    backtracks: int
    branches_created: int
    successes_per_100_target_interactions: float | None
    mean_target_interactions_per_conversation: float | None
    median_target_interactions_to_success: float | None
    median_first_violation_depth: float | None
    planner_calls: int
    mutator_calls: int
    planner_output_tokens: int
    mutator_output_tokens: int


def summarize_adaptive_red(
    results: tuple[ConversationRunResult, ...],
    budget: BudgetSnapshot,
) -> AdaptiveRedEfficiency:
    """Summarize multi-turn Red efficiency under the observed campaign budget.

    This function intentionally does not calculate Blue ASR. Use campaign security
    metrics for ASR/MCR/SCR. Here, a successful conversation only provides a cost
    numerator for attacker-efficiency measures.
    """

    conclusive = [
        result
        for result in results
        if result.execution.objective_violated is not None
    ]
    successful = [
        result
        for result in conclusive
        if result.execution.objective_violated is True
    ]
    target_interactions = sum(len(result.turns) for result in results)
    interactions_to_success = [
        result.first_violation_ordinal
        for result in successful
        if result.first_violation_ordinal is not None
    ]
    violation_depths = [
        result.first_violation_depth
        for result in successful
        if result.first_violation_depth is not None
    ]
    calls = dict(budget.model_calls_by_role)
    tokens = dict(budget.output_tokens_by_role)

    return AdaptiveRedEfficiency(
        conversations=len(results),
        conclusive_conversations=len(conclusive),
        successful_conversations=len(successful),
        target_interactions=target_interactions,
        backtracks=sum(result.backtracks for result in results),
        branches_created=sum(max(0, result.branches - 1) for result in results),
        successes_per_100_target_interactions=(
            100.0 * len(successful) / target_interactions
            if target_interactions
            else None
        ),
        mean_target_interactions_per_conversation=(
            fmean(len(result.turns) for result in results) if results else None
        ),
        median_target_interactions_to_success=(
            float(median(interactions_to_success))
            if interactions_to_success
            else None
        ),
        median_first_violation_depth=(
            float(median(violation_depths)) if violation_depths else None
        ),
        planner_calls=calls.get("red_planner", 0),
        mutator_calls=calls.get("red_mutator", 0),
        planner_output_tokens=tokens.get("red_planner", 0),
        mutator_output_tokens=tokens.get("red_mutator", 0),
    )


def effectiveness_and_cost_are_separate(
    effectiveness: RedEffectiveness,
    efficiency: AdaptiveRedEfficiency,
) -> tuple[RedEffectiveness, AdaptiveRedEfficiency]:
    """Explicit helper preventing accidental collapse into an opaque composite score."""

    return effectiveness, efficiency
