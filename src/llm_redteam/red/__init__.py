"""Adaptive Red Team planning primitives."""

from .ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairedRedObservation,
    PairingMode,
    observation_from_run,
    summarize_paired_red_ablation,
)
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
from .mechanism_adaptive import MechanismAwareAdaptiveRedStrategy, MechanismRedDecision
from .mechanisms import (
    AttackMechanism,
    MechanismCampaignMemory,
    MechanismGuidance,
    MechanismLearningRecord,
    MechanismMemorySnapshot,
    MechanismPolicy,
)
from .sequence_metrics import RedSequenceMetrics, SequenceRate, summarize_red_sequences

__all__ = [
    "AblationArm",
    "AdaptiveRedEfficiency",
    "AdaptiveRedStrategy",
    "AttackHypothesis",
    "AttackMechanism",
    "AttackObservation",
    "HeuristicRedPlanner",
    "MechanismAwareAdaptiveRedStrategy",
    "MechanismCampaignMemory",
    "MechanismGuidance",
    "MechanismLearningRecord",
    "MechanismMemorySnapshot",
    "MechanismPolicy",
    "MechanismRedDecision",
    "PairedRedAblationContract",
    "PairedRedAblationReport",
    "PairedRedObservation",
    "PairingMode",
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
    "observation_from_run",
    "summarize_adaptive_red",
    "summarize_paired_red_ablation",
    "summarize_red_sequences",
]
