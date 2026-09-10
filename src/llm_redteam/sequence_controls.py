"""Matched controls for testing whether conversational context adds attack uplift.

The retained-context arm and reset-each-turn arm preserve the same Red-side feedback
loop. The only intended intervention is whether prior dialogue is delivered back to
the Blue target. This separates context accumulation from simply receiving repeated
attempts and observing refusals.
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
    comparable_context_effect_estimate: bool = True


StrategyFactory = Callable[[], MultiTurnStrategy]


async def run_sequence_context_pair(
    *,
    case,
    target: TargetAdapter,
    judge: Judge,
    conversation_budget: ConversationBudget,
    strategy_factory: StrategyFactory,
    replicate: int = 0,
    retained_first: bool = True,
    budget: BudgetLedger | None = None,
) -> tuple[SequenceContextObservation, SequenceContextObservation]:
    """Run one matched retained-context versus reset-each-turn pair.

    Both arms use fresh Red strategy instances, the same target identity, Judge,
    conversation budget and campaign ledger. Execution order is explicit so a
    higher-level experiment can counterbalance it across case/replicate pairs.
    """

    from .domain import AttackCase

    if not isinstance(case, AttackCase):
        raise TypeError("case must be an AttackCase")

    order = (
        (SequenceContextArm.RETAINED_CONTEXT, SequenceContextArm.RESET_EACH_TURN)
        if retained_first
        else (SequenceContextArm.RESET_EACH_TURN, SequenceContextArm.RETAINED_CONTEXT)
    )
    observations: dict[SequenceContextArm, SequenceContextObservation] = {}

    for arm in order:
        controlled_target: TargetAdapter = (
            target
            if arm == SequenceContextArm.RETAINED_CONTEXT
            else ResetEachTurnTarget(target)
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

    All pairs must be conclusive and match on target identity and flow fingerprint.
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

    both = retained_only = reset_only = neither = 0
    interaction_deltas: list[int] = []
    retained_runs: list[ConversationRunResult] = []
    reset_runs: list[ConversationRunResult] = []

    for key in keys:
        retained_run = retained[key].run
        reset_run = reset[key].run
        _validate_pair(retained_run, reset_run, key)
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
    retained: ConversationRunResult,
    reset: ConversationRunResult,
    key: tuple[str, int],
) -> None:
    unresolved = {
        CompromiseOutcome.ERROR,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.PARTIAL,
    }
    if retained.execution.outcome in unresolved or reset.execution.outcome in unresolved:
        raise ValueError(f"sequence-context pair {key} contains unresolved execution")
    if retained.execution.target_id != reset.execution.target_id:
        raise ValueError(f"sequence-context pair {key} target identity mismatch")
    if retained.flow_fingerprint != reset.flow_fingerprint:
        raise ValueError(f"sequence-context pair {key} flow fingerprint mismatch")
    if retained.session_mode != SessionMode.REPLAY or reset.session_mode != SessionMode.REPLAY:
        raise ValueError(f"sequence-context pair {key} must use replay session mode")


def _exact_mcnemar_p_value(left_only: int, right_only: int) -> float:
    discordant = left_only + right_only
    if discordant == 0:
        return 1.0
    smaller = min(left_only, right_only)
    tail = sum(comb(discordant, k) for k in range(smaller + 1)) / (2**discordant)
    return min(1.0, 2.0 * tail)
