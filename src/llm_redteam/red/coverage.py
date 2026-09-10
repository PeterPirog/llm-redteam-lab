"""Mechanism exploration coverage for adaptive multi-turn Red discovery.

These diagnostics answer whether Red explored the mechanism space it was configured
and able to use. They are deliberately separate from Blue vulnerability metrics:
coverage can reveal search collapse or blind spots, but high coverage is not evidence
that a target is vulnerable or safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import exp, log
from typing import Iterable

from pydantic import Field

from ..campaigns.multiturn import ConversationBudget
from ..domain import StrictModel
from ..metrics import RateEstimate, wilson_rate
from ..targets.base import SessionMode
from .mechanisms import AttackMechanism, MechanismMemorySnapshot


class MechanismCoverageState(StrEnum):
    UNOBSERVED = "UNOBSERVED"
    OBSERVED = "OBSERVED"
    SUCCESS_OBSERVED = "SUCCESS_OBSERVED"


class RedCoverageStatus(StrEnum):
    READY = "READY"
    INCOMPLETE = "INCOMPLETE"
    NO_EVIDENCE = "NO_EVIDENCE"


class MechanismCoverageCell(StrictModel):
    """Conversation-level exposure evidence for one eligible Red mechanism."""

    mechanism: AttackMechanism
    state: MechanismCoverageState
    conversation_exposures: int = Field(ge=0)
    successful_conversation_exposures: int = Field(ge=0)
    observed_success_rate: RateEstimate
    exposure_share: float = Field(ge=0.0, le=1.0)


class RedMechanismCoverage(StrictModel):
    """Transcript-free mechanism exploration summary.

    ``conversation_exposures`` count conversations in which a mechanism appeared at
    least once. A single conversation may expose several mechanisms, so these counts
    are intentionally not an ASR denominator and may sum above ``conversations``.
    """

    conversations: int = Field(ge=0)
    attack_families: int = Field(ge=0)
    eligible_mechanisms: tuple[AttackMechanism, ...]
    cells: tuple[MechanismCoverageCell, ...]
    observed_mechanisms: tuple[AttackMechanism, ...]
    successful_mechanisms: tuple[AttackMechanism, ...]
    unobserved_mechanisms: tuple[AttackMechanism, ...]
    mechanism_coverage_ratio: float = Field(ge=0.0, le=1.0)
    successful_mechanism_coverage_ratio: float = Field(ge=0.0, le=1.0)
    normalized_exposure_entropy: float = Field(ge=0.0, le=1.0)
    effective_mechanism_count: float = Field(ge=0.0)
    max_mechanism_exposure_share: float = Field(ge=0.0, le=1.0)
    unique_transition_signatures: int = Field(ge=0)
    unique_sequence_signatures: int = Field(ge=0)
    comparable_blue_estimate: bool = False


class RedCoveragePolicy(StrictModel):
    """Predeclared readiness criteria for Red exploration diagnostics.

    The policy is not a safety threshold. It answers whether the discovery search
    supplied enough mechanism diversity to support a later controlled evaluation.
    """

    required_mechanisms: tuple[AttackMechanism, ...] = Field(min_length=1)
    min_conversation_exposures_per_mechanism: int = Field(ge=1, default=1)
    max_single_mechanism_exposure_share: float | None = Field(
        default=None, gt=0.0, le=1.0
    )
    min_normalized_exposure_entropy: float | None = Field(
        default=None, ge=0.0, le=1.0
    )
    min_unique_transition_signatures: int | None = Field(default=None, ge=0)
    min_unique_sequence_signatures: int | None = Field(default=None, ge=0)


class RedCoverageAssessment(StrictModel):
    status: RedCoverageStatus
    policy: RedCoveragePolicy
    coverage: RedMechanismCoverage
    reasons: tuple[str, ...] = ()
    comparable_blue_estimate: bool = False


def eligible_mechanisms_for_runtime(
    *,
    session_mode: SessionMode,
    conversation_budget: ConversationBudget,
) -> tuple[AttackMechanism, ...]:
    """Return mechanisms structurally available to the current multi-turn runtime."""

    mechanisms = [
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.SEMANTIC_REFRAMING,
        AttackMechanism.CROSS_TURN_COMPOSITION,
        AttackMechanism.DECOMPOSITION,
        AttackMechanism.REFUSAL_FEEDBACK,
        AttackMechanism.OBJECTIVE_PROBE,
    ]
    if (
        session_mode == SessionMode.REPLAY
        and conversation_budget.max_backtracks > 0
        and conversation_budget.max_branches > 1
    ):
        mechanisms.append(AttackMechanism.BRANCH_DIVERSIFICATION)
    return tuple(mechanisms)


def summarize_mechanism_coverage(
    snapshots: Iterable[MechanismMemorySnapshot],
    *,
    eligible_mechanisms: tuple[AttackMechanism, ...],
    confidence_level: float = 0.95,
) -> RedMechanismCoverage:
    """Summarize discovery exploration without turning coverage into Blue ASR."""

    rows = tuple(snapshots)
    if not eligible_mechanisms:
        raise ValueError("eligible_mechanisms cannot be empty")
    if len(set(eligible_mechanisms)) != len(eligible_mechanisms):
        raise ValueError("eligible_mechanisms must be unique")

    eligible = set(eligible_mechanisms)
    exposures = {mechanism: 0 for mechanism in eligible_mechanisms}
    successes = {mechanism: 0 for mechanism in eligible_mechanisms}
    transition_signatures: set[str] = set()
    sequence_signatures: set[str] = set()

    for snapshot in rows:
        unknown = {
            AttackMechanism(name)
            for name in snapshot.mechanism_trials
            if name in AttackMechanism._value2member_map_ and AttackMechanism(name) not in eligible
        }
        # A snapshot may come from a runtime whose structural eligibility differs from
        # the report. Known-but-ineligible mechanisms make the report incomparable.
        if unknown:
            names = ", ".join(sorted(item.value for item in unknown))
            raise ValueError(f"snapshot contains mechanisms outside eligibility scope: {names}")
        invalid_names = {
            name
            for name in snapshot.mechanism_trials
            if name not in AttackMechanism._value2member_map_
        }
        if invalid_names:
            raise ValueError(
                "snapshot contains unknown mechanism identifiers: "
                + ", ".join(sorted(invalid_names))
            )

        for mechanism in eligible_mechanisms:
            trials = snapshot.mechanism_trials.get(mechanism.value, 0)
            wins = snapshot.mechanism_successes.get(mechanism.value, 0)
            if wins > trials:
                raise ValueError(
                    f"mechanism successes exceed exposures for {mechanism.value}"
                )
            exposures[mechanism] += trials
            successes[mechanism] += wins
        transition_signatures.update(
            name for name, count in snapshot.transition_trials.items() if count > 0
        )
        sequence_signatures.update(
            name for name, count in snapshot.sequence_trials.items() if count > 0
        )

    total_exposure_mass = sum(exposures.values())
    cells: list[MechanismCoverageCell] = []
    observed: list[AttackMechanism] = []
    successful: list[AttackMechanism] = []
    unobserved: list[AttackMechanism] = []

    for mechanism in eligible_mechanisms:
        trials = exposures[mechanism]
        wins = successes[mechanism]
        if wins > 0:
            state = MechanismCoverageState.SUCCESS_OBSERVED
            successful.append(mechanism)
            observed.append(mechanism)
        elif trials > 0:
            state = MechanismCoverageState.OBSERVED
            observed.append(mechanism)
        else:
            state = MechanismCoverageState.UNOBSERVED
            unobserved.append(mechanism)
        cells.append(
            MechanismCoverageCell(
                mechanism=mechanism,
                state=state,
                conversation_exposures=trials,
                successful_conversation_exposures=wins,
                observed_success_rate=wilson_rate(wins, trials, confidence_level),
                exposure_share=(trials / total_exposure_mass if total_exposure_mass else 0.0),
            )
        )

    entropy = _normalized_entropy(
        tuple(exposures[item] for item in eligible_mechanisms),
        len(eligible_mechanisms),
    )
    effective = _effective_mechanism_count(
        tuple(exposures[item] for item in eligible_mechanisms)
    )
    max_share = (
        max(exposures.values()) / total_exposure_mass if total_exposure_mass else 0.0
    )
    denominator = len(eligible_mechanisms)
    return RedMechanismCoverage(
        conversations=sum(snapshot.trials for snapshot in rows),
        attack_families=len(rows),
        eligible_mechanisms=eligible_mechanisms,
        cells=tuple(cells),
        observed_mechanisms=tuple(observed),
        successful_mechanisms=tuple(successful),
        unobserved_mechanisms=tuple(unobserved),
        mechanism_coverage_ratio=len(observed) / denominator,
        successful_mechanism_coverage_ratio=len(successful) / denominator,
        normalized_exposure_entropy=entropy,
        effective_mechanism_count=effective,
        max_mechanism_exposure_share=max_share,
        unique_transition_signatures=len(transition_signatures),
        unique_sequence_signatures=len(sequence_signatures),
    )


def assess_red_coverage(
    coverage: RedMechanismCoverage,
    *,
    policy: RedCoveragePolicy,
) -> RedCoverageAssessment:
    """Check whether discovery exploration met a predeclared coverage contract."""

    if not coverage.cells or coverage.conversations == 0:
        return RedCoverageAssessment(
            status=RedCoverageStatus.NO_EVIDENCE,
            policy=policy,
            coverage=coverage,
            reasons=("no discovery conversations are available",),
        )

    by_mechanism = {cell.mechanism: cell for cell in coverage.cells}
    reasons: list[str] = []
    for mechanism in policy.required_mechanisms:
        cell = by_mechanism.get(mechanism)
        if cell is None:
            reasons.append(f"required mechanism {mechanism.value} is outside coverage scope")
            continue
        if cell.conversation_exposures < policy.min_conversation_exposures_per_mechanism:
            reasons.append(
                f"{mechanism.value} exposures={cell.conversation_exposures} below "
                f"minimum={policy.min_conversation_exposures_per_mechanism}"
            )

    if (
        policy.max_single_mechanism_exposure_share is not None
        and coverage.max_mechanism_exposure_share
        > policy.max_single_mechanism_exposure_share
    ):
        reasons.append(
            "single-mechanism exposure concentration exceeds the predeclared maximum"
        )
    if (
        policy.min_normalized_exposure_entropy is not None
        and coverage.normalized_exposure_entropy < policy.min_normalized_exposure_entropy
    ):
        reasons.append("mechanism exposure entropy is below the predeclared minimum")
    if (
        policy.min_unique_transition_signatures is not None
        and coverage.unique_transition_signatures < policy.min_unique_transition_signatures
    ):
        reasons.append("observed transition diversity is below the predeclared minimum")
    if (
        policy.min_unique_sequence_signatures is not None
        and coverage.unique_sequence_signatures < policy.min_unique_sequence_signatures
    ):
        reasons.append("observed sequence diversity is below the predeclared minimum")

    return RedCoverageAssessment(
        status=(RedCoverageStatus.INCOMPLETE if reasons else RedCoverageStatus.READY),
        policy=policy,
        coverage=coverage,
        reasons=tuple(reasons),
    )


def _normalized_entropy(counts: tuple[int, ...], categories: int) -> float:
    total = sum(counts)
    if total <= 0 or categories <= 1:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * log(probability)
    return min(1.0, max(0.0, entropy / log(categories)))


def _effective_mechanism_count(counts: tuple[int, ...]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * log(probability)
    return exp(entropy)
