"""Measurement contracts separating adaptive discovery from Blue evaluation.

Adaptive Red search is intentionally optimized from prior outcomes. Its observed
success rate is useful for attacker-search diagnostics but is not automatically an
unbiased estimate of Blue vulnerability. Comparative Blue metrics require a frozen
cross-trial attack policy and held-out evaluation cases.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from pydantic import model_validator

from .domain import CompromiseOutcome, ExecutionResult, StrictModel
from .metrics import CampaignMetrics, RateEstimate, summarize_campaign, wilson_rate


class CampaignPurpose(StrEnum):
    DISCOVERY = "DISCOVERY"
    EVALUATION = "EVALUATION"


class MeasurementProtocol(StrictModel):
    """Declare the experimental conditions under which security rates are interpreted."""

    purpose: CampaignPurpose
    attack_policy_frozen_across_trials: bool
    learns_from_current_campaign_outcomes: bool
    held_out_cases: bool
    target_snapshot_pinned: bool

    @model_validator(mode="after")
    def evaluation_requires_non_adaptive_cross_trial_measurement(
        self,
    ) -> MeasurementProtocol:
        if self.purpose != CampaignPurpose.EVALUATION:
            return self
        if not self.attack_policy_frozen_across_trials:
            raise ValueError("EVALUATION requires a frozen attack policy across trials")
        if self.learns_from_current_campaign_outcomes:
            raise ValueError("EVALUATION cannot learn from current campaign outcomes")
        if not self.held_out_cases:
            raise ValueError("EVALUATION requires held-out cases")
        if not self.target_snapshot_pinned:
            raise ValueError("EVALUATION requires a pinned target snapshot")
        return self


@dataclass(frozen=True, slots=True)
class DiscoveryMetrics:
    """Observed Red search yield, deliberately not named Blue ASR."""

    total_executions: int
    conclusive_executions: int
    objective_violations_observed: int
    unresolved_executions: int
    observed_violation_rate: RateEstimate
    unresolved_rate: RateEstimate
    comparable_blue_estimate: bool = False


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """Blue security metrics produced under an explicit valid evaluation protocol."""

    protocol: MeasurementProtocol
    campaign: CampaignMetrics
    comparable_blue_estimate: bool = True


def summarize_discovery(
    executions: Iterable[ExecutionResult],
    confidence_level: float = 0.95,
) -> DiscoveryMetrics:
    """Summarize what an adaptive search found without calling it target ASR."""

    rows = list(executions)
    unresolved_outcomes = {
        CompromiseOutcome.ERROR,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.PARTIAL,
    }
    conclusive = [row for row in rows if row.outcome not in unresolved_outcomes]
    violations = sum(row.objective_violated is True for row in conclusive)
    unresolved = len(rows) - len(conclusive)
    return DiscoveryMetrics(
        total_executions=len(rows),
        conclusive_executions=len(conclusive),
        objective_violations_observed=violations,
        unresolved_executions=unresolved,
        observed_violation_rate=wilson_rate(
            violations,
            len(conclusive),
            confidence_level,
        ),
        unresolved_rate=wilson_rate(unresolved, len(rows), confidence_level),
    )


def summarize_evaluation(
    executions: Iterable[ExecutionResult],
    protocol: MeasurementProtocol,
    confidence_level: float = 0.95,
) -> EvaluationMetrics:
    """Produce comparative Blue metrics only under a valid evaluation protocol."""

    if protocol.purpose != CampaignPurpose.EVALUATION:
        raise ValueError("comparative Blue metrics require EVALUATION purpose")
    return EvaluationMetrics(
        protocol=protocol,
        campaign=summarize_campaign(executions, confidence_level),
    )


def discovery_protocol() -> MeasurementProtocol:
    """Default protocol for adaptive Red exploration that learns across trials."""

    return MeasurementProtocol(
        purpose=CampaignPurpose.DISCOVERY,
        attack_policy_frozen_across_trials=False,
        learns_from_current_campaign_outcomes=True,
        held_out_cases=False,
        target_snapshot_pinned=True,
    )


def held_out_evaluation_protocol() -> MeasurementProtocol:
    """Conservative default for target-comparison and regression reporting."""

    return MeasurementProtocol(
        purpose=CampaignPurpose.EVALUATION,
        attack_policy_frozen_across_trials=True,
        learns_from_current_campaign_outcomes=False,
        held_out_cases=True,
        target_snapshot_pinned=True,
    )
