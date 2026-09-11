"""Metrics for multi-turn attacks with conversation-level denominators.

Conversation-level ASR remains the primary Blue vulnerability rate. Layer-specific
model/system compromise rates remain separate. Time-to-event summaries use
right-censoring-aware Kaplan-Meier estimates so early-stopped or budget-exhausted
conversations are not reduced to success-only latency statistics.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import exp, log, sqrt
from statistics import NormalDist, mean, median
from typing import Literal

from .campaigns.multiturn import ConversationRunResult
from .domain import CompromiseOutcome
from .metrics import RateEstimate, summarize_campaign, wilson_rate

ExposureAxis = Literal["target_calls", "path_depth"]
CompromiseLayer = Literal["model", "system"]


@dataclass(frozen=True, slots=True)
class ViolationCurvePoint:
    exposure: int
    at_risk: int
    events: int
    censored: int
    cumulative_violation: float
    ci_low: float
    ci_high: float


@dataclass(frozen=True, slots=True)
class TimeToViolationEstimate:
    axis: ExposureAxis
    observations: int
    events: int
    censored: int
    curve: tuple[ViolationCurvePoint, ...]
    median_exposure_to_violation: float | None
    confidence_level: float
    method: str = "kaplan_meier_greenwood_loglog"
    censoring_assumption: str = "non_informative_right_censoring"


@dataclass(frozen=True, slots=True)
class LayerTimeToCompromiseEstimate:
    """Censoring-aware first-compromise estimate for one security layer.

    ``unresolved`` is intentionally separate from right-censoring. A conclusive
    layer-negative conversation is censored at its final observed exposure. A
    conversation whose layer state is unresolved contributes neither an event nor
    a containment censoring observation.
    """

    layer: CompromiseLayer
    axis: ExposureAxis
    total_conversations: int
    observations: int
    events: int
    censored: int
    unresolved: int
    curve: tuple[ViolationCurvePoint, ...]
    median_exposure_to_compromise: float | None
    confidence_level: float
    method: str = "kaplan_meier_greenwood_loglog"
    censoring_assumption: str = "non_informative_right_censoring"


@dataclass(frozen=True, slots=True)
class MultiTurnMetrics:
    total_conversations: int
    valid_conversations: int
    total_turns: int
    total_backtracks: int
    branching_conversations: int
    attack_success_rate: RateEstimate
    model_compromise_rate: RateEstimate
    system_compromise_rate: RateEstimate
    model_to_system_escalation_rate: RateEstimate
    backtracked_attack_success_rate: RateEstimate
    mean_turns_per_conversation: float | None
    median_turns_per_conversation: float | None
    median_turns_to_first_violation: float | None
    median_depth_to_first_violation: float | None
    successes_per_100_turns: float | None
    unresolved_conversations: int
    target_call_time_to_violation: TimeToViolationEstimate
    path_depth_time_to_violation: TimeToViolationEstimate
    model_target_call_time_to_compromise: LayerTimeToCompromiseEstimate
    model_path_depth_time_to_compromise: LayerTimeToCompromiseEstimate
    system_target_call_time_to_compromise: LayerTimeToCompromiseEstimate
    system_path_depth_time_to_compromise: LayerTimeToCompromiseEstimate


def summarize_multi_turn(
    runs: tuple[ConversationRunResult, ...],
    confidence_level: float = 0.95,
) -> MultiTurnMetrics:
    """Summarize multi-turn security without turn-count denominator bias.

    One bounded attack conversation contributes at most one security-rate trial.
    Turns, branches and backtracks are resource/attacker-efficiency observations,
    not additional Blue vulnerability trials.

    Objective-violation timing remains available for compatibility. Layer-specific
    first-model and first-system compromise curves expose the system-containment
    trajectory added by layer-aware AGENT stopping.
    """

    valid = tuple(run for run in runs if _is_conclusive(run))
    successes = sum(run.execution.objective_violated is True for run in valid)
    backtracked = tuple(run for run in valid if run.backtracks > 0)
    backtracked_successes = sum(
        run.execution.objective_violated is True for run in backtracked
    )
    turn_counts = [len(run.turns) for run in runs]
    success_ordinals = [
        run.first_violation_ordinal
        for run in valid
        if run.first_violation_ordinal is not None
    ]
    success_depths = [
        run.first_violation_depth
        for run in valid
        if run.first_violation_depth is not None
    ]
    total_turns = sum(turn_counts)
    campaign = summarize_campaign(
        (run.execution for run in runs),
        confidence_level=confidence_level,
    )

    return MultiTurnMetrics(
        total_conversations=len(runs),
        valid_conversations=len(valid),
        total_turns=total_turns,
        total_backtracks=sum(run.backtracks for run in runs),
        branching_conversations=sum(run.branches > 1 for run in runs),
        attack_success_rate=campaign.attack_success_rate,
        model_compromise_rate=campaign.model_compromise_rate,
        system_compromise_rate=campaign.system_compromise_rate,
        model_to_system_escalation_rate=campaign.model_to_system_escalation_rate,
        backtracked_attack_success_rate=wilson_rate(
            backtracked_successes,
            len(backtracked),
            confidence_level,
        ),
        mean_turns_per_conversation=mean(turn_counts) if turn_counts else None,
        median_turns_per_conversation=median(turn_counts) if turn_counts else None,
        median_turns_to_first_violation=(
            median(success_ordinals) if success_ordinals else None
        ),
        median_depth_to_first_violation=(
            median(success_depths) if success_depths else None
        ),
        successes_per_100_turns=(
            100.0 * successes / total_turns if total_turns else None
        ),
        unresolved_conversations=len(runs) - len(valid),
        target_call_time_to_violation=summarize_time_to_violation(
            valid,
            axis="target_calls",
            confidence_level=confidence_level,
        ),
        path_depth_time_to_violation=summarize_time_to_violation(
            valid,
            axis="path_depth",
            confidence_level=confidence_level,
        ),
        model_target_call_time_to_compromise=summarize_layer_time_to_compromise(
            runs,
            layer="model",
            axis="target_calls",
            confidence_level=confidence_level,
        ),
        model_path_depth_time_to_compromise=summarize_layer_time_to_compromise(
            runs,
            layer="model",
            axis="path_depth",
            confidence_level=confidence_level,
        ),
        system_target_call_time_to_compromise=summarize_layer_time_to_compromise(
            runs,
            layer="system",
            axis="target_calls",
            confidence_level=confidence_level,
        ),
        system_path_depth_time_to_compromise=summarize_layer_time_to_compromise(
            runs,
            layer="system",
            axis="path_depth",
            confidence_level=confidence_level,
        ),
    )


def summarize_time_to_violation(
    runs: tuple[ConversationRunResult, ...],
    *,
    axis: ExposureAxis,
    confidence_level: float = 0.95,
) -> TimeToViolationEstimate:
    """Estimate cumulative objective violation versus attack exposure.

    Successful conversations contribute an event at the first objective violation.
    Conclusive unsuccessful conversations are right-censored at their last observed
    target call or maximum explored logical path depth.

    Kaplan-Meier estimates assume non-informative right censoring. Evaluation runs
    should therefore prefer predeclared fixed stopping rules; adaptive early stopping
    can make the curve descriptive rather than population-generalizable.
    """

    _validate_axis_and_confidence(axis, confidence_level)

    observations: list[tuple[int, bool]] = []
    for run in runs:
        if not _is_conclusive(run):
            raise ValueError("time-to-violation estimates require conclusive conversations")

        successful = run.execution.objective_violated is True
        exposure = _objective_exposure_for_run(
            run,
            axis=axis,
            successful=successful,
        )
        observations.append((exposure, successful))

    curve = _kaplan_meier_curve(
        tuple(observations),
        confidence_level=confidence_level,
    )
    median_exposure = _median_event_exposure(curve)

    return TimeToViolationEstimate(
        axis=axis,
        observations=len(observations),
        events=sum(success for _, success in observations),
        censored=sum(not success for _, success in observations),
        curve=curve,
        median_exposure_to_violation=median_exposure,
        confidence_level=confidence_level,
    )


def summarize_layer_time_to_compromise(
    runs: tuple[ConversationRunResult, ...],
    *,
    layer: CompromiseLayer,
    axis: ExposureAxis,
    confidence_level: float = 0.95,
) -> LayerTimeToCompromiseEstimate:
    """Estimate cumulative first compromise for one security layer.

    A known positive layer flag is an event even when the overall conversation is
    ``PARTIAL`` because positive evidence is monotonic. A conclusive layer-negative
    conversation is right-censored at its final observed exposure. If the layer is
    not known positive and the conversation is ``ERROR``, ``INCONCLUSIVE`` or
    ``PARTIAL``, its layer state is unresolved and it is excluded from the
    Kaplan-Meier risk set rather than misreported as successful containment.
    """

    if layer not in {"model", "system"}:
        raise ValueError("layer must be 'model' or 'system'")
    _validate_axis_and_confidence(axis, confidence_level)

    observations: list[tuple[int, bool]] = []
    unresolved = 0
    for run in runs:
        positive = (
            run.execution.model_compromise
            if layer == "model"
            else run.execution.system_compromise
        )
        if positive:
            observations.append(
                (
                    _layer_event_exposure(run, layer=layer, axis=axis),
                    True,
                )
            )
            continue

        if _is_conclusive(run):
            observations.append((_final_exposure(run, axis=axis), False))
        else:
            unresolved += 1

    curve = _kaplan_meier_curve(
        tuple(observations),
        confidence_level=confidence_level,
    )
    return LayerTimeToCompromiseEstimate(
        layer=layer,
        axis=axis,
        total_conversations=len(runs),
        observations=len(observations),
        events=sum(event for _, event in observations),
        censored=sum(not event for _, event in observations),
        unresolved=unresolved,
        curve=curve,
        median_exposure_to_compromise=_median_event_exposure(curve),
        confidence_level=confidence_level,
    )


def _objective_exposure_for_run(
    run: ConversationRunResult,
    *,
    axis: ExposureAxis,
    successful: bool,
) -> int:
    if successful:
        exposure = (
            run.first_violation_ordinal
            if axis == "target_calls"
            else run.first_violation_depth
        )
        if exposure is None:
            raise ValueError(
                "successful conversation is missing first-violation exposure metadata"
            )
        return exposure
    return _final_exposure(run, axis=axis)


def _layer_event_exposure(
    run: ConversationRunResult,
    *,
    layer: CompromiseLayer,
    axis: ExposureAxis,
) -> int:
    if layer == "model":
        exposure = (
            run.first_model_compromise_ordinal
            if axis == "target_calls"
            else run.first_model_compromise_depth
        )
    else:
        exposure = (
            run.first_system_compromise_ordinal
            if axis == "target_calls"
            else run.first_system_compromise_depth
        )
    if exposure is None:
        raise ValueError(
            f"{layer}-compromised conversation is missing first-{layer}-compromise "
            "exposure metadata"
        )
    if exposure <= 0:
        raise ValueError("layer compromise exposure must be positive")
    return exposure


def _final_exposure(
    run: ConversationRunResult,
    *,
    axis: ExposureAxis,
) -> int:
    if axis == "target_calls":
        exposure = len(run.turns)
    else:
        exposure = max((turn.depth for turn in run.turns), default=0)
    if exposure <= 0:
        raise ValueError("conclusive layer-negative conversation has no observed exposure")
    return exposure


def _validate_axis_and_confidence(
    axis: ExposureAxis,
    confidence_level: float,
) -> None:
    if axis not in {"target_calls", "path_depth"}:
        raise ValueError("axis must be 'target_calls' or 'path_depth'")
    if not 0.0 < confidence_level < 1.0:
        raise ValueError("confidence_level must be between 0 and 1")


def _median_event_exposure(
    curve: tuple[ViolationCurvePoint, ...],
) -> float | None:
    return next(
        (
            float(point.exposure)
            for point in curve
            if point.cumulative_violation >= 0.5
        ),
        None,
    )


def _kaplan_meier_curve(
    observations: tuple[tuple[int, bool], ...],
    *,
    confidence_level: float,
) -> tuple[ViolationCurvePoint, ...]:
    """Return a discrete Kaplan-Meier cumulative-event curve."""

    if not observations:
        return ()
    if any(exposure <= 0 for exposure, _ in observations):
        raise ValueError("Kaplan-Meier exposure values must be positive")

    z = NormalDist().inv_cdf(0.5 + confidence_level / 2.0)
    survival = 1.0
    greenwood_sum = 0.0
    points: list[ViolationCurvePoint] = []

    for exposure in sorted({value for value, _ in observations}):
        at_risk = sum(value >= exposure for value, _ in observations)
        events = sum(value == exposure and event for value, event in observations)
        censored = sum(
            value == exposure and not event for value, event in observations
        )

        if events:
            survival *= 1.0 - events / at_risk
            if at_risk > events:
                greenwood_sum += events / (at_risk * (at_risk - events))

        survival_low, survival_high = _survival_interval(
            survival,
            greenwood_sum=greenwood_sum,
            z=z,
        )
        points.append(
            ViolationCurvePoint(
                exposure=exposure,
                at_risk=at_risk,
                events=events,
                censored=censored,
                cumulative_violation=1.0 - survival,
                ci_low=max(0.0, 1.0 - survival_high),
                ci_high=min(1.0, 1.0 - survival_low),
            )
        )

    return tuple(points)


def _survival_interval(
    survival: float,
    *,
    greenwood_sum: float,
    z: float,
) -> tuple[float, float]:
    if survival <= 0.0:
        return 0.0, 0.0
    if survival >= 1.0:
        return 1.0, 1.0

    log_survival = log(survival)
    standard_error = sqrt(greenwood_sum) / abs(log_survival)
    transformed = log(-log_survival)
    lower = exp(-exp(transformed + z * standard_error))
    upper = exp(-exp(transformed - z * standard_error))
    return max(0.0, lower), min(1.0, upper)


def _is_conclusive(run: ConversationRunResult) -> bool:
    return run.execution.outcome not in {
        CompromiseOutcome.ERROR,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.PARTIAL,
    }
