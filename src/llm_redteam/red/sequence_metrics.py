"""Sequence-level metrics for adaptive Red search, never Blue vulnerability ASR."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from statistics import median

from ..metrics import RateEstimate, wilson_rate
from .adaptive import RedLearningRecord


@dataclass(frozen=True, slots=True)
class SequenceRate:
    signature: str
    attempts: int
    successes: int
    observed_success_rate: RateEstimate


@dataclass(frozen=True, slots=True)
class RedSequenceMetrics:
    records: int
    successful_records: int
    sequence_summaries: tuple[SequenceRate, ...]
    transition_summaries: tuple[SequenceRate, ...]
    median_turn_to_success: float | None
    median_depth_to_success: float | None
    comparable_blue_estimate: bool = False


def summarize_red_sequences(
    records: tuple[RedLearningRecord, ...],
    confidence_level: float = 0.95,
) -> RedSequenceMetrics:
    """Measure branch-aware search-path yield under the observed adaptive policy.

    Chronological attempts are a cost trace. Sequence and transition statistics use
    explicit logical-lineage fields when available so a backtrack cannot fabricate a
    sibling transition such as ``B -> C`` when the real tree is ``A -> B`` and
    ``A -> C``. Legacy records without lineage fields retain their previous behavior.

    These rates describe Red search behavior and must never be used as comparative
    Blue ASR because the sequence distribution itself may be adaptively selected.
    """

    sequence_trials: Counter[str] = Counter()
    sequence_successes: Counter[str] = Counter()
    transition_trials: Counter[str] = Counter()
    transition_successes: Counter[str] = Counter()
    success_ordinals: list[int] = []
    success_depths: list[int] = []

    for record in records:
        path_steps = (
            record.logical_phase_tactics
            or record.logical_tactics
            or record.phase_tactics
            or record.tactics
        )
        if path_steps:
            sequence = ">".join(path_steps)
            sequence_trials[sequence] += 1
            if record.successful:
                sequence_successes[sequence] += 1

        attempted_transitions = record.attempted_transitions
        if not attempted_transitions:
            chronological = record.phase_tactics or record.tactics
            attempted_transitions = tuple(
                f"{left}->{right}"
                for left, right in zip(chronological, chronological[1:], strict=False)
            )
        transition_trials.update(attempted_transitions)

        successful_transitions = record.successful_transitions
        if record.successful and not successful_transitions:
            successful_transitions = tuple(
                f"{left}->{right}"
                for left, right in zip(path_steps, path_steps[1:], strict=False)
            )
        transition_successes.update(successful_transitions)

        if record.successful and record.first_violation_ordinal is not None:
            success_ordinals.append(record.first_violation_ordinal)
        if record.successful and record.first_violation_depth is not None:
            success_depths.append(record.first_violation_depth)

    return RedSequenceMetrics(
        records=len(records),
        successful_records=sum(record.successful for record in records),
        sequence_summaries=_summaries(
            sequence_trials,
            sequence_successes,
            confidence_level,
        ),
        transition_summaries=_summaries(
            transition_trials,
            transition_successes,
            confidence_level,
        ),
        median_turn_to_success=(
            float(median(success_ordinals)) if success_ordinals else None
        ),
        median_depth_to_success=(
            float(median(success_depths)) if success_depths else None
        ),
    )


def _summaries(
    trials: Counter[str],
    successes: Counter[str],
    confidence_level: float,
) -> tuple[SequenceRate, ...]:
    rows = [
        SequenceRate(
            signature=signature,
            attempts=attempts,
            successes=successes[signature],
            observed_success_rate=wilson_rate(
                successes[signature],
                attempts,
                confidence_level,
            ),
        )
        for signature, attempts in trials.items()
    ]
    rows.sort(
        key=lambda row: (
            row.observed_success_rate.value or 0.0,
            row.successes,
            row.attempts,
            row.signature,
        ),
        reverse=True,
    )
    return tuple(rows)
