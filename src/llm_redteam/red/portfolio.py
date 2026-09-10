"""Risk-aware portfolio selection for bounded multi-turn Red campaigns.

The policy improves *which abstract mechanism to try next* without adding model
calls or changing attack permissions. It treats remaining turns as a scarce search
budget and combines mechanism yield, real branch-aware transition yield, uncertainty
and stagnation. The stable ``MechanismPolicy`` remains the baseline for paired
ablation; this policy must earn adoption through held-out measurements.
"""

from __future__ import annotations

from collections.abc import Mapping
from math import sqrt

from pydantic import Field

from ..campaigns.multiturn import ConversationBudget, ConversationState
from ..domain import StrictModel
from .mechanisms import AttackMechanism, MechanismGuidance, MechanismPolicy


class PortfolioCandidateScore(StrictModel):
    """Auditable deterministic score for one candidate mechanism."""

    mechanism: AttackMechanism
    mechanism_trials: int = Field(ge=0)
    mechanism_successes: int = Field(ge=0)
    transition_trials: int = Field(ge=0)
    transition_successes: int = Field(ge=0)
    mechanism_posterior_mean: float = Field(ge=0.0, le=1.0)
    transition_posterior_mean: float | None = Field(default=None, ge=0.0, le=1.0)
    exploration_bonus: float = Field(ge=0.0)
    repeat_penalty: float = Field(ge=0.0)
    stagnation_penalty: float = Field(ge=0.0)
    score: float


class RiskAwarePortfolioPolicy(MechanismPolicy):
    """Transition-aware mechanism portfolio under a fixed conversation budget.

    ``risk-aware`` means avoiding waste of the authorized attack budget: early turns
    can explore uncertain mechanisms, while later turns increasingly exploit observed
    yield. No score is a Blue-security metric and none is reported as ASR.
    """

    def __init__(
        self,
        *,
        conversation_budget: ConversationBudget,
        stagnation_threshold: int = 2,
        novelty_bonus: float = 0.18,
        transition_weight: float = 0.35,
        repeat_penalty: float = 0.18,
        stagnation_penalty: float = 0.08,
        late_exploration_floor: float = 0.20,
        branch_advantage_threshold: float = 0.12,
    ) -> None:
        super().__init__(
            conversation_budget=conversation_budget,
            stagnation_threshold=stagnation_threshold,
            novelty_bonus=novelty_bonus,
        )
        for name, value in (
            ("transition_weight", transition_weight),
            ("repeat_penalty", repeat_penalty),
            ("stagnation_penalty", stagnation_penalty),
            ("late_exploration_floor", late_exploration_floor),
            ("branch_advantage_threshold", branch_advantage_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        self.transition_weight = transition_weight
        self.repeat_penalty = repeat_penalty
        self.stagnation_penalty = stagnation_penalty
        self.late_exploration_floor = late_exploration_floor
        self.branch_advantage_threshold = branch_advantage_threshold

    def recommend(
        self,
        *,
        phase: str,
        conversation: ConversationState,
        prior_mechanisms: tuple[AttackMechanism, ...],
        historical_trials: Mapping[str, int],
        historical_successes: Mapping[str, int],
        historical_transition_trials: Mapping[str, int] | None = None,
        historical_transition_successes: Mapping[str, int] | None = None,
    ) -> MechanismGuidance:
        stagnation = self._trailing_passes(conversation)
        if phase == "finisher":
            return MechanismGuidance(
                preferred=AttackMechanism.OBJECTIVE_PROBE,
                allowed=(AttackMechanism.OBJECTIVE_PROBE,),
                stagnation_passes=stagnation,
                must_change_mechanism=False,
                candidate_scores={AttackMechanism.OBJECTIVE_PROBE.value: 1.0},
                rationale=(
                    "final authorized interaction is reserved for the strongest "
                    "objective probe rather than another exploratory portfolio step"
                ),
            )

        candidates = self._PRIMER if phase == "primer" else self._PLANNER
        transition_trials = historical_transition_trials or {}
        transition_successes = historical_transition_successes or {}
        last = prior_mechanisms[-1] if prior_mechanisms else None
        scores = tuple(
            self._score_candidate(
                mechanism=item,
                conversation=conversation,
                stagnation=stagnation,
                last=last,
                historical_trials=historical_trials,
                historical_successes=historical_successes,
                transition_trials=transition_trials,
                transition_successes=transition_successes,
            )
            for item in candidates
        )
        score_by_mechanism = {row.mechanism: row for row in scores}

        must_change = stagnation >= self.stagnation_threshold
        if len(prior_mechanisms) >= 2 and prior_mechanisms[-1] == prior_mechanisms[-2]:
            must_change = True

        eligible = candidates
        if must_change and last in candidates and len(candidates) > 1:
            eligible = tuple(item for item in candidates if item != last)
        ranked = tuple(
            sorted(
                eligible,
                key=lambda item: (
                    score_by_mechanism[item].score,
                    -score_by_mechanism[item].mechanism_trials,
                    item.value,
                ),
                reverse=True,
            )
        )

        branch_recommended = False
        if phase == "planner" and self._branch_available(conversation):
            if must_change:
                branch_recommended = True
            elif stagnation > 0 and last in score_by_mechanism and ranked:
                branch_recommended = (
                    score_by_mechanism[ranked[0]].score
                    - score_by_mechanism[last].score
                    >= self.branch_advantage_threshold
                )

        serialized_scores = {
            row.mechanism.value: round(row.score, 6) for row in scores
        }
        if branch_recommended:
            return MechanismGuidance(
                preferred=AttackMechanism.BRANCH_DIVERSIFICATION,
                allowed=(AttackMechanism.BRANCH_DIVERSIFICATION, *ranked),
                stagnation_passes=stagnation,
                must_change_mechanism=must_change,
                branch_recommended=True,
                recommended_branch_from_turn_id=self._branch_anchor(
                    conversation,
                    max(1, stagnation),
                ),
                candidate_scores=serialized_scores,
                rationale=(
                    "bounded portfolio favors a branch because the active path is "
                    "stagnant or an alternate mechanism has materially higher expected "
                    "yield under the remaining interaction budget"
                ),
            )

        return MechanismGuidance(
            preferred=ranked[0],
            allowed=ranked,
            stagnation_passes=stagnation,
            must_change_mechanism=must_change,
            branch_recommended=False,
            candidate_scores=serialized_scores,
            rationale=(
                "rank mechanisms by smoothed observed yield, branch-aware transition "
                "yield, uncertainty bonus and remaining-budget pressure"
            ),
        )

    def score_candidates(
        self,
        *,
        phase: str,
        conversation: ConversationState,
        prior_mechanisms: tuple[AttackMechanism, ...],
        historical_trials: Mapping[str, int],
        historical_successes: Mapping[str, int],
        historical_transition_trials: Mapping[str, int] | None = None,
        historical_transition_successes: Mapping[str, int] | None = None,
    ) -> tuple[PortfolioCandidateScore, ...]:
        """Expose deterministic candidate scores for diagnostics and ablation reports."""

        if phase == "finisher":
            return ()
        candidates = self._PRIMER if phase == "primer" else self._PLANNER
        last = prior_mechanisms[-1] if prior_mechanisms else None
        stagnation = self._trailing_passes(conversation)
        transition_trials = historical_transition_trials or {}
        transition_successes = historical_transition_successes or {}
        return tuple(
            self._score_candidate(
                mechanism=item,
                conversation=conversation,
                stagnation=stagnation,
                last=last,
                historical_trials=historical_trials,
                historical_successes=historical_successes,
                transition_trials=transition_trials,
                transition_successes=transition_successes,
            )
            for item in candidates
        )

    def descriptor(self) -> dict[str, object]:
        return {
            **super().descriptor(),
            "transition_weight": self.transition_weight,
            "repeat_penalty": self.repeat_penalty,
            "stagnation_penalty": self.stagnation_penalty,
            "late_exploration_floor": self.late_exploration_floor,
            "branch_advantage_threshold": self.branch_advantage_threshold,
        }

    def _score_candidate(
        self,
        *,
        mechanism: AttackMechanism,
        conversation: ConversationState,
        stagnation: int,
        last: AttackMechanism | None,
        historical_trials: Mapping[str, int],
        historical_successes: Mapping[str, int],
        transition_trials: Mapping[str, int],
        transition_successes: Mapping[str, int],
    ) -> PortfolioCandidateScore:
        trials = max(0, historical_trials.get(mechanism.value, 0))
        successes = min(trials, max(0, historical_successes.get(mechanism.value, 0)))
        mechanism_mean = _beta_mean(successes, trials)

        transition_count = 0
        transition_wins = 0
        transition_mean: float | None = None
        if last is not None:
            transition = f"{last.value}->{mechanism.value}"
            transition_count = max(0, transition_trials.get(transition, 0))
            transition_wins = min(
                transition_count,
                max(0, transition_successes.get(transition, 0)),
            )
            transition_mean = _beta_mean(transition_wins, transition_count)

        if transition_mean is None:
            exploitation = mechanism_mean
        else:
            exploitation = (
                (1.0 - self.transition_weight) * mechanism_mean
                + self.transition_weight * transition_mean
            )

        remaining = max(0, self.conversation_budget.max_turns - len(conversation.turns))
        remaining_fraction = remaining / self.conversation_budget.max_turns
        exploration_scale = self.late_exploration_floor + (
            1.0 - self.late_exploration_floor
        ) * remaining_fraction
        exploration = self.novelty_bonus * exploration_scale / sqrt(trials + 1.0)
        repeat = self.repeat_penalty if mechanism == last else 0.0
        stagnant_repeat = (
            self.stagnation_penalty * min(stagnation, 3)
            if mechanism == last
            else 0.0
        )

        return PortfolioCandidateScore(
            mechanism=mechanism,
            mechanism_trials=trials,
            mechanism_successes=successes,
            transition_trials=transition_count,
            transition_successes=transition_wins,
            mechanism_posterior_mean=mechanism_mean,
            transition_posterior_mean=transition_mean,
            exploration_bonus=exploration,
            repeat_penalty=repeat,
            stagnation_penalty=stagnant_repeat,
            score=exploitation + exploration - repeat - stagnant_repeat,
        )


def _beta_mean(successes: int, trials: int) -> float:
    """Uniform Beta(1,1) posterior mean for sparse bounded discovery evidence."""

    if successes < 0 or trials < 0 or successes > trials:
        raise ValueError("require 0 <= successes <= trials")
    return (successes + 1.0) / (trials + 2.0)
