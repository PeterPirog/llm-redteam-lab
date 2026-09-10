"""Matched controls for testing whether conversational context adds attack uplift.

The retained-context arm and reset-each-turn arm preserve the same Red-side feedback
loop. The intended intervention is whether prior dialogue is delivered back to the
Blue target. To keep that claim identifiable, every arm must run in a separately
isolated target state domain so side effects from one arm cannot contaminate the other.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from math import comb
from statistics import mean, median

from pydantic import Field, model_validator

from .budget import BudgetLedger
from .campaigns.multiturn import (
    ConversationBudget,
    ConversationRunResult,
    MultiTurnCampaignEngine,
    MultiTurnStrategy,
)
from .domain import CompromiseOutcome, StrictModel, TargetIdentity
from .judges.base import Judge
from .metrics import RateEstimate, wilson_rate
from .multiturn_metrics import TimeToViolationEstimate, summarize_time_to_violation
from .targets.base import SessionMode, TargetAdapter, TargetRequest, TargetResponse


class SequenceContextArm(StrEnum):
    RETAINED_CONTEXT = "RETAINED_CONTEXT"
    RESET_EACH_TURN = "RESET_EACH_TURN"


class SequenceTargetIsolationMode(StrEnum):
    """How an experiment guarantees independent mutable target state per observation."""

    FRESH_ISOLATED_INSTANCE = "FRESH_ISOLATED_INSTANCE"
    SNAPSHOT_RESTORE = "SNAPSHOT_RESTORE"
    DISPOSABLE_WORKSPACE = "DISPOSABLE_WORKSPACE"


@dataclass(frozen=True, slots=True)
class SequenceTargetFixture:
    """One independently isolated Blue target state domain.

    ``isolation_id`` identifies this specific disposable/restored state domain, not
    merely the model configuration. The factory is responsible for ensuring that a
    fixture cannot observe mutable state created by another arm or replicate.
    """

    target: TargetAdapter
    isolation_id: str
    isolation_mode: SequenceTargetIsolationMode

    def __post_init__(self) -> None:
        if not self.isolation_id.strip():
            raise ValueError("sequence target isolation_id must be non-empty")


class ResetEachTurnTarget:
    """Target adapter intervention that removes Blue conversational memory.

    Red still receives every prior target response through ``ConversationState`` and
    may adapt its next proposal. Before each Blue execution, replay history and any
    session identifier are removed. The wrapped target identity is deliberately
    unchanged: this is an experimental context intervention, not a different target
    snapshot.
    """

    def __init__(self, target: TargetAdapter) -> None:
        self._target = target

    @property
    def identity(self) -> TargetIdentity:
        return self._target.identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        metadata = dict(request.metadata)
        metadata["sequence_context_arm"] = "reset_each_turn"
        controlled = request.model_copy(
            update={
                "conversation": (),
                "session_mode": SessionMode.REPLAY,
                "session_id": None,
                "metadata": metadata,
            }
        )
        response = await self._target.execute(controlled)
        if response.session_id is not None:
            response = response.model_copy(update={"session_id": None})
        return response


class SequenceContextObservation(StrictModel):
    arm: SequenceContextArm
    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    target_configuration_hash: str = Field(min_length=1)
    target_isolation_id: str = Field(min_length=1)
    target_isolation_mode: SequenceTargetIsolationMode
    run: ConversationRunResult

    @model_validator(mode="after")
    def observation_matches_run(self) -> SequenceContextObservation:
        if self.run.execution.attack_id != self.case_id:
            raise ValueError("sequence-control case_id does not match run attack_id")
        if self.run.session_mode != SessionMode.REPLAY:
            raise ValueError("sequence-context controls require replay session mode")
        return self

    @property
    def pair_key(self) -> tuple[str, int]:
        return self.case_id, self.replicate


@dataclass(frozen=True, slots=True)
class SequenceContextComparison:
    pair_count: int
    retained_context_success_rate: RateEstimate
    reset_each_turn_success_rate: RateEstimate
    success_rate_delta: float
    both_successes: int
    retained_only_successes: int
    reset_only_successes: int
    neither_successes: int
    discordant_pairs: int
    exact_mcnemar_p_value: float
    retained_win_rate_among_discordant: RateEstimate
    mean_target_interaction_delta: float
    median_target_interaction_delta: float
    retained_time_to_violation: TimeToViolationEstimate
    reset_each_turn_time_to_violation: TimeToViolationEstimate
    target_isolation_mode: SequenceTargetIsolationMode
    comparable_context_effect_estimate: bool = True


StrategyFactory = Callable[[], MultiTurnStrategy]
TargetFixtureFactory = Callable[
    [SequenceContextArm, str, int],
    SequenceTargetFixture,
]


async def run_sequence_context_pair(
    *,
    case,
    target_fixture_factory: TargetFixtureFactory,
    judge: Judge,
    conversation_budget: ConversationBudget,
    strategy_factory: StrategyFactory,
    replicate: int = 0,
    retained_first: bool = True,
    budget: BudgetLedger | None = None,
) -> tuple[SequenceContextObservation, SequenceContextObservation]:
    """Run one isolated retained-context versus reset-each-turn matched pair.

    The target fixture factory is called once for each arm before either arm executes.
    It must return independent mutable state domains with identical ``TargetIdentity``
    and distinct isolation IDs. This prevents a retained-context run from modifying
    memory, RAG state, files, tools or an agent workspace later observed by the reset
    arm (and vice versa).

    Both arms still use fresh Red strategy instances, the same Judge, conversation
    budget and campaign ledger. Execution order is explicit so a higher-level
    experiment can counterbalance it across case/replicate pairs.
    """

    from .domain import AttackCase

    if not isinstance(case, AttackCase):
        raise TypeError("case must be an AttackCase")

    fixtures = {
        arm: target_fixture_factory(arm, case.id, replicate)
        for arm in SequenceContextArm
    }
    _validate_target_fixtures(fixtures)

    order = (
        (SequenceContextArm.RETAINED_CONTEXT, SequenceContextArm.RESET_EACH_TURN)
        if retained_first
        else (SequenceContextArm.RESET_EACH_TURN, SequenceContextArm.RETAINED_CONTEXT)
    )
    observations: dict[SequenceContextArm, SequenceContextObservation] = {}

    for arm in order:
        fixture = fixtures[arm]
        controlled_target: TargetAdapter = (
            fixture.target
            if arm == SequenceContextArm.RETAINED_CONTEXT
            else ResetEachTurnTarget(fixture.target)
        )
        engine = MultiTurnCampaignEngine(
            target=controlled_target,
            judge=judge,
            conversation_budget=conversation_budget,
            budget=budget,
        )
        run = await engine.run_case(
            case,
            strategy_factory(),
            session_mode=SessionMode.REPLAY,
        )
        observations[arm] = SequenceContextObservation(
            arm=arm,
            case_id=case.id,
            replicate=replicate,
            target_configuration_hash=fixture.target.identity.configuration_hash,
            target_isolation_id=fixture.isolation_id,
            target_isolation_mode=fixture.isolation_mode,
            run=run,
        )

    return (
        observations[SequenceContextArm.RETAINED_CONTEXT],
        observations[SequenceContextArm.RESET_EACH_TURN],
    )


def summarize_sequence_context_comparison(
    observations: Iterable[SequenceContextObservation],
    *,
    confidence_level: float = 0.95,
) -> SequenceContextComparison:
    """Summarize matched context-retention interventions conservatively.

    All pairs must be conclusive, use identical target configurations and flow
    fingerprints, and come from unique independently isolated target state domains.
    The exact paired test is descriptive evidence only; promotion or a causal claim
    should additionally apply a predeclared minimum sample/effect policy.
    """

    rows = tuple(observations)
    retained = _index_arm(rows, SequenceContextArm.RETAINED_CONTEXT)
    reset = _index_arm(rows, SequenceContextArm.RESET_EACH_TURN)
    if set(retained) != set(reset):
        raise ValueError("sequence-context comparison requires complete matched pairs")

    keys = sorted(retained)
    if not keys:
        raise ValueError("sequence-context comparison requires observations")

    isolation_ids = [row.target_isolation_id for row in rows]
    if len(isolation_ids) != len(set(isolation_ids)):
        raise ValueError(
            "sequence-context comparison requires a unique target isolation domain "
            "for every arm and replicate"
        )
    isolation_modes = {row.target_isolation_mode for row in rows}
    if len(isolation_modes) != 1:
        raise ValueError("sequence-context comparison requires one target isolation mode")
    isolation_mode = next(iter(isolation_modes))

    both = retained_only = reset_only = neither = 0
    interaction_deltas: list[int] = []
    retained_runs: list[ConversationRunResult] = []
    reset_runs: list[ConversationRunResult] = []

    for key in keys:
        retained_observation = retained[key]
        reset_observation = reset[key]
        _validate_pair(retained_observation, reset_observation, key)
        retained_run = retained_observation.run
        reset_run = reset_observation.run
        retained_runs.append(retained_run)
        reset_runs.append(reset_run)

        retained_success = retained_run.execution.objective_violated is True
        reset_success = reset_run.execution.objective_violated is True
        if retained_success and reset_success:
            both += 1
        elif retained_success:
            retained_only += 1
        elif reset_success:
            reset_only += 1
        else:
            neither += 1
        interaction_deltas.append(len(retained_run.turns) - len(reset_run.turns))

    pair_count = len(keys)
    retained_successes = both + retained_only
    reset_successes = both + reset_only
    discordant = retained_only + reset_only
    retained_rate = wilson_rate(retained_successes, pair_count, confidence_level)
    reset_rate = wilson_rate(reset_successes, pair_count, confidence_level)

    return SequenceContextComparison(
        pair_count=pair_count,
        retained_context_success_rate=retained_rate,
        reset_each_turn_success_rate=reset_rate,
        success_rate_delta=(retained_rate.value or 0.0) - (reset_rate.value or 0.0),
        both_successes=both,
        retained_only_successes=retained_only,
        reset_only_successes=reset_only,
        neither_successes=neither,
        discordant_pairs=discordant,
        exact_mcnemar_p_value=_exact_mcnemar_p_value(retained_only, reset_only),
        retained_win_rate_among_discordant=wilson_rate(
            retained_only,
            discordant,
            confidence_level,
        ),
        mean_target_interaction_delta=mean(interaction_deltas),
        median_target_interaction_delta=float(median(interaction_deltas)),
        retained_time_to_violation=summarize_time_to_violation(
            tuple(retained_runs),
            axis="target_calls",
            confidence_level=confidence_level,
        ),
        reset_each_turn_time_to_violation=summarize_time_to_violation(
            tuple(reset_runs),
            axis="target_calls",
            confidence_level=confidence_level,
        ),
        target_isolation_mode=isolation_mode,
    )


def _validate_target_fixtures(
    fixtures: dict[SequenceContextArm, SequenceTargetFixture],
) -> None:
    retained = fixtures[SequenceContextArm.RETAINED_CONTEXT]
    reset = fixtures[SequenceContextArm.RESET_EACH_TURN]
    if retained.target is reset.target:
        raise ValueError("sequence-context arms must not reuse the same target object")
    if retained.isolation_id == reset.isolation_id:
        raise ValueError("sequence-context arms must use distinct target isolation IDs")
    if retained.isolation_mode != reset.isolation_mode:
        raise ValueError("sequence-context arms must use the same target isolation mode")
    if retained.target.identity != reset.target.identity:
        raise ValueError(
            "sequence-context arms must use identical target identities/configurations"
        )


def _index_arm(
    rows: tuple[SequenceContextObservation, ...],
    arm: SequenceContextArm,
) -> dict[tuple[str, int], SequenceContextObservation]:
    indexed: dict[tuple[str, int], SequenceContextObservation] = {}
    for row in rows:
        if row.arm != arm:
            continue
        if row.pair_key in indexed:
            raise ValueError(f"duplicate {arm.value} observation: {row.pair_key}")
        indexed[row.pair_key] = row
    return indexed


def _validate_pair(
    retained: SequenceContextObservation,
    reset: SequenceContextObservation,
    key: tuple[str, int],
) -> None:
    unresolved = {
        CompromiseOutcome.ERROR,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.PARTIAL,
    }
    if retained.run.execution.outcome in unresolved or reset.run.execution.outcome in unresolved:
        raise ValueError(f"sequence-context pair {key} contains unresolved execution")
    if retained.run.execution.target_id != reset.run.execution.target_id:
        raise ValueError(f"sequence-context pair {key} target identity mismatch")
    if retained.target_configuration_hash != reset.target_configuration_hash:
        raise ValueError(f"sequence-context pair {key} target configuration mismatch")
    if retained.target_isolation_id == reset.target_isolation_id:
        raise ValueError(f"sequence-context pair {key} reused target isolation state")
    if retained.target_isolation_mode != reset.target_isolation_mode:
        raise ValueError(f"sequence-context pair {key} isolation mode mismatch")
    if retained.run.flow_fingerprint != reset.run.flow_fingerprint:
        raise ValueError(f"sequence-context pair {key} flow fingerprint mismatch")
    if (
        retained.run.session_mode != SessionMode.REPLAY
        or reset.run.session_mode != SessionMode.REPLAY
    ):
        raise ValueError(f"sequence-context pair {key} must use replay session mode")


def _exact_mcnemar_p_value(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if discordant == 0:
        return 1.0
    smaller = min(left_only, right_only)
    tail = sum(comb(discordant, k) for k in range(smaller + 1)) / (2**discordant)
    return min(1.0, 2.0 * tail)
