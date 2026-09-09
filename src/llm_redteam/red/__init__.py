"""Adaptive Red Team planning primitives."""

from .adaptive import (
    AdaptiveRedStrategy,
    RedAction,
    RedCampaignMemory,
    RedDecision,
    RedLearningRecord,
    RedMemorySnapshot,
    RedPhase,
)
from .base import AttackHypothesis, AttackObservation, RedPlan, RedPlanner
from .efficiency import AdaptiveRedEfficiency, summarize_adaptive_red
from .heuristic import HeuristicRedPlanner
from .sequence_metrics import RedSequenceMetrics, SequenceRate, summarize_red_sequences

__all__ = [
    "AdaptiveRedEfficiency",
    "AdaptiveRedStrategy",
    "AttackHypothesis",
    "AttackObservation",
    "HeuristicRedPlanner",
    "RedAction",
    "RedCampaignMemory",
    "RedDecision",
    "RedLearningRecord",
    "RedMemorySnapshot",
    "RedPhase",
    "RedPlan",
    "RedPlanner",
    "RedSequenceMetrics",
    "SequenceRate",
    "summarize_adaptive_red",
    "summarize_red_sequences",
]
