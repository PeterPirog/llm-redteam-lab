"""Deterministic high-level mechanism guidance for adaptive multi-turn Red.

This module intentionally separates *attack strategy* from prompt generation. It
selects abstract, authorized testing mechanisms and flow-control pressure while the
configured Red planner still writes the concrete synthetic probe. The policy owns
no target permissions, budgets, judging or raw transcript memory.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from enum import StrEnum
from statistics import median

from pydantic import Field

from ..campaigns.multiturn import ConversationBudget, ConversationState
from ..domain import CompromiseOutcome, StrictModel
from ..targets.base import SessionMode


class AttackMechanism(StrEnum):
    """Provider-independent mechanism labels, not executable jailbreak payloads."""

    FIXTURE_TRIGGER = "fixture_trigger"
    CONTEXT_ACCUMULATION = "context_accumulation"
    SEMANTIC_REFRAMING = "semantic_reframing"
    CROSS_TURN_COMPOSITION = "cross_turn_composition"
    DECOMPOSITION = "decomposition"
    REFUSAL_FEEDBACK = "refusal_feedback"
    BRANCH_DIVERSIFICATION = "branch_diversification"
    OBJECTIVE_PROBE = "objective_probe"


class MechanismGuidance(StrictModel):
    """One deterministic strategy recommendation supplied to the Red generator."""

    preferred: AttackMechanism
    allowed: tuple[AttackMechanism, ...] = Field(min_length=1)
    stagnation_passes: int = Field(ge=0)
    must_change_mechanism: bool = False
    branch_recommended: bool = False
    recommended_branch_from_turn_id: str | None = None
    candidate_scores: dict[str, float] = Field(default_factory=dict)
    rationale: str = Field(min_length=1)


class MechanismLearningRecord(StrictModel):
    """Transcript-free outcome for one bounded multi-turn conversation.

    ``mechanisms`` is the chronological set of attempted mechanisms and therefore
    remains useful for exploration accounting. Success credit is carried separately
    so a mechanism on an abandoned sibling branch is not incorrectly rewarded when
    another branch later succeeds.
    """

    attack_family: str = Field(min_length=1)
    mechanisms: tuple[AttackMechanism, ...] = ()
    successful_mechanisms: tuple[AttackMechanism, ...] = ()
    attempted_transitions: tuple[str, ...] = ()
    successful_transitions: tuple[str, ...] = ()
    successful_path: tuple[AttackMechanism, ...] = ()
    successful: bool
    error: bool
    target_interactions: int = Field(ge=0, default=0)
    first_violation_ordinal: int | None = Field(default=None, gt=0)
    first_violation_depth: int | None = Field(default=None, gt=0)


class MechanismMemorySnapshot(StrictModel):
    """Aggregate high-level mechanism evidence safe to reuse across discovery trials."""

    attack_family: str = Field(min_length=1)
    trials: int = Field(ge=0)
    successes: int = Field(ge=0)
    errors: int = Field(ge=0)
    target_interactions: int = Field(ge=0, default=0)
    mechanism_trials: dict[str, int] = Field(default_factory=dict)
    mechanism_successes: dict[str, int] = Field(default_factory=dict)
    transition_trials: dict[str, int] = Field(default_factory=dict)
    transition_successes: dict[str, int] = Field(default_factory=dict)
    sequence_trials: dict[str, int] = Field(default_factory=dict)
    sequence_successes: dict[str, int] = Field(default_factory=dict)
    median_success_ordinal: float | None = None
    median_success_depth: float | None = None

    def compact_text(self) -> str:
        mechanisms = self._top_ratios(self.mechanism_trials, self.mechanism_successes, limit=7)
        transitions = self._top_ratios(self.transition_trials, self.transition_successes, limit=5)
        sequences = self._top_ratios(self.sequence_trials, self.sequence_successes, limit=3)
        return (
            f"family={self.attack_family}; trials={self.trials}; successes={self.successes}; "
            f"errors={self.errors}; target_interactions={self.target_interactions}; "
            f"median_success_ordinal={self.median_success_ordinal}; "
            f"median_success_depth={self.median_success_depth}; "
            f"mechanisms(success/trials)={mechanisms}; "
            f"transitions(success/trials)={transitions}; "
            f"successful_paths(success/trials)={sequences}"
        )

    @staticmethod
    def _top_ratios(
        trials: dict[str, int],
        successes: dict[str, int],
        *,
        limit: int,
    ) -> str:
        if not trials:
            return "none"
        ordered = sorted(
            trials,
            key=lambda key: (
                successes.get(key, 0) / trials[key],
                successes.get(key, 0),
                trials[key],
                key,
            ),
            reverse=True,
        )[:limit]
        return ", ".join(
            f"{key}:{successes.get(key, 0)}/{trials[key]}" for key in ordered
        )


class MechanismCampaignMemory:
    """Bounded Red discovery memory containing no prompt or Blue response text."""

    def __init__(self, *, max_records: int = 256) -> None:
        if max_records <= 0:
            raise ValueError("max_records must be positive")
        self.max_records = max_records
        self._records: list[MechanismLearningRecord] = []

    def record(self, record: MechanismLearningRecord) -> None:
        self._records.append(record)
        if len(self._records) > self.max_records:
            del self._records[: len(self._records) - self.max_records]

    def snapshot(self, attack_family: str) -> MechanismMemorySnapshot:
        rows = [row for row in self._records if row.attack_family == attack_family]
        mechanism_trials: Counter[str] = Counter()
        mechanism_successes: Counter[str] = Counter()
        transition_trials: Counter[str] = Counter()
        transition_successes: Counter[str] = Counter()
        sequence_trials: Counter[str] = Counter()
        sequence_successes: Counter[str] = Counter()
        success_ordinals: list[int] = []
        success_depths: list[int] = []

        for row in rows:
            attempted = row.mechanisms
            successful_mechanisms = row.successful_mechanisms
            if row.successful and not successful_mechanisms:
                # Backward-compatible interpretation for records written before
                # branch-aware credit assignment existed.
                successful_mechanisms = attempted

            for mechanism in set(attempted):
                mechanism_trials[mechanism.value] += 1
            for mechanism in set(successful_mechanisms):
                mechanism_successes[mechanism.value] += 1

            attempted_transitions = row.attempted_transitions
            if not attempted_transitions:
                attempted_transitions = tuple(
                    f"{left.value}->{right.value}"
                    for left, right in zip(attempted, attempted[1:], strict=False)
                )
            successful_transitions = row.successful_transitions
            if row.successful and not successful_transitions:
                successful_transitions = attempted_transitions

            transition_trials.update(attempted_transitions)
            transition_successes.update(successful_transitions)

            path = row.successful_path
            if not path and attempted:
                path = attempted
            if path:
                signature = ">".join(item.value for item in path)
                sequence_trials[signature] += 1
                if row.successful:
                    sequence_successes[signature] += 1

            if row.successful and row.first_violation_ordinal is not None:
                success_ordinals.append(row.first_violation_ordinal)
            if row.successful and row.first_violation_depth is not None:
                success_depths.append(row.first_violation_depth)

        return MechanismMemorySnapshot(
            attack_family=attack_family,
            trials=len(rows),
            successes=sum(row.successful for row in rows),
            errors=sum(row.error for row in rows),
            target_interactions=sum(row.target_interactions for row in rows),
            mechanism_trials=dict(mechanism_trials),
            mechanism_successes=dict(mechanism_successes),
            transition_trials=dict(transition_trials),
            transition_successes=dict(transition_successes),
            sequence_trials=dict(sequence_trials),
            sequence_successes=dict(sequence_successes),
            median_success_ordinal=(
                float(median(success_ordinals)) if success_ordinals else None
            ),
            median_success_depth=(
                float(median(success_depths)) if success_depths else None
            ),
        )


class MechanismPolicy:
    """Budget-aware mechanism selector with bounded exploration/exploitation.

    The selector is deliberately simple and remains the stable baseline for paired
    ablation. It uses smoothed historical success yield, a small novelty bonus and
    deterministic stagnation handling. More advanced policies must preserve this
    interface so they can be compared under identical campaign conditions.
    """

    _PRIMER = (
        AttackMechanism.CONTEXT_ACCUMULATION,
        AttackMechanism.DECOMPOSITION,
        AttackMechanism.SEMANTIC_REFRAMING,
    )
    _PLANNER = (
        AttackMechanism.CROSS_TURN_COMPOSITION,
        AttackMechanism.REFUSAL_FEEDBACK,
        AttackMechanism.SEMANTIC_REFRAMING,
        AttackMechanism.DECOMPOSITION,
        AttackMechanism.CONTEXT_ACCUMULATION,
    )

    def __init__(
        self,
        *,
        conversation_budget: ConversationBudget,
        stagnation_threshold: int = 2,
        novelty_bonus: float = 0.15,
    ) -> None:
        if stagnation_threshold <= 0:
            raise ValueError("stagnation_threshold must be positive")
        if not 0.0 <= novelty_bonus <= 1.0:
            raise ValueError("novelty_bonus must be between 0 and 1")
        self.conversation_budget = conversation_budget
        self.stagnation_threshold = stagnation_threshold
        self.novelty_bonus = novelty_bonus

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
        """Recommend the next mechanism from state, budget and aggregate evidence."""

        del historical_transition_trials, historical_transition_successes
        stagnation = self._trailing_passes(conversation)
        if phase == "finisher":
            return MechanismGuidance(
                preferred=AttackMechanism.OBJECTIVE_PROBE,
                allowed=(AttackMechanism.OBJECTIVE_PROBE,),
                stagnation_passes=stagnation,
                must_change_mechanism=False,
                rationale="remaining budget is reserved for the strongest objective test",
            )

        candidates = self._PRIMER if phase == "primer" else self._PLANNER
        branch_available = self._branch_available(conversation)
        must_change = stagnation >= self.stagnation_threshold
        if len(prior_mechanisms) >= 2 and prior_mechanisms[-1] == prior_mechanisms[-2]:
            must_change = True

        if must_change and branch_available and phase == "planner":
            last = prior_mechanisms[-1] if prior_mechanisms else None
            alternatives = tuple(item for item in candidates if item != last)
            allowed = (AttackMechanism.BRANCH_DIVERSIFICATION, *alternatives)
            return MechanismGuidance(
                preferred=AttackMechanism.BRANCH_DIVERSIFICATION,
                allowed=allowed,
                stagnation_passes=stagnation,
                must_change_mechanism=True,
                branch_recommended=True,
                recommended_branch_from_turn_id=self._branch_anchor(conversation, stagnation),
                rationale=(
                    "current path has repeated conclusive PASS outcomes; explore an "
                    "alternate branch before spending the remaining turn budget"
                ),
            )

        ranked = self._rank_candidates(
            candidates,
            prior_mechanisms=prior_mechanisms,
            historical_trials=historical_trials,
            historical_successes=historical_successes,
            force_novelty=must_change,
        )
        preferred = ranked[0]
        return MechanismGuidance(
            preferred=preferred,
            allowed=ranked,
            stagnation_passes=stagnation,
            must_change_mechanism=must_change,
            branch_recommended=False,
            rationale=(
                "prefer a historically productive but under-explored mechanism; "
                "force mechanism change after repeated non-progress"
            ),
        )

    def descriptor(self) -> dict[str, object]:
        """Stable serializable policy parameters for measurement provenance."""

        return {
            "type": type(self).__name__,
            "stagnation_threshold": self.stagnation_threshold,
            "novelty_bonus": self.novelty_bonus,
        }

    def _rank_candidates(
        self,
        candidates: tuple[AttackMechanism, ...],
        *,
        prior_mechanisms: tuple[AttackMechanism, ...],
        historical_trials: Mapping[str, int],
        historical_successes: Mapping[str, int],
        force_novelty: bool,
    ) -> tuple[AttackMechanism, ...]:
        last = prior_mechanisms[-1] if prior_mechanisms else None
        eligible = candidates
        if force_novelty and last in candidates and len(candidates) > 1:
            eligible = tuple(item for item in candidates if item != last)
        position = {item: index for index, item in enumerate(eligible)}

        def score(item: AttackMechanism) -> tuple[float, int, int, int]:
            trials = max(0, historical_trials.get(item.value, 0))
            successes = min(trials, max(0, historical_successes.get(item.value, 0)))
            smoothed_yield = (successes + 1.0) / (trials + 2.0)
            exploration = self.novelty_bonus / (trials + 1.0)
            repeat_penalty = 0.20 if item == last else 0.0
            return (
                smoothed_yield + exploration - repeat_penalty,
                -trials,
                successes,
                -position[item],
            )

        return tuple(sorted(eligible, key=score, reverse=True))

    def _branch_available(self, conversation: ConversationState) -> bool:
        if (
            conversation.session_mode != SessionMode.REPLAY
            or conversation.active_leaf_turn_id is None
            or conversation.backtracks >= self.conversation_budget.max_backtracks
            or conversation.branches >= self.conversation_budget.max_branches
        ):
            return False
        turns = {turn.turn_id: turn for turn in conversation.turns}
        leaf = turns.get(conversation.active_leaf_turn_id)
        return leaf is not None and leaf.parent_turn_id is not None

    @staticmethod
    def _branch_anchor(conversation: ConversationState, stagnation: int) -> str | None:
        turns = {turn.turn_id: turn for turn in conversation.turns}
        current = conversation.active_leaf_turn_id
        if current is None:
            return None
        steps = max(1, stagnation)
        for _ in range(steps):
            turn = turns.get(current)
            if turn is None or turn.parent_turn_id is None:
                break
            current = turn.parent_turn_id
        return current if current != conversation.active_leaf_turn_id else None

    @staticmethod
    def _trailing_passes(conversation: ConversationState) -> int:
        count = 0
        current = conversation.active_leaf_turn_id
        turns = {turn.turn_id: turn for turn in conversation.turns}
        while current is not None:
            turn = turns.get(current)
            if turn is None or turn.outcome != CompromiseOutcome.PASS:
                break
            count += 1
            current = turn.parent_turn_id
        return count
