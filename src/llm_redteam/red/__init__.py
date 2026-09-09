"""Adaptive Red Team planning primitives."""

from .ablation import (
    AblationArm,
    AblationExecutionOrder,
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairedRedObservation,
    PairedTrialPlan,
    PairingMode,
    build_counterbalanced_pair_plan,
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
    "AblationExecutionOrder",
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
    "PairedTrialPlan",
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
    "build_counterbalanced_pair_plan",
    "observation_from_run",
    "summarize_adaptive_red",
    "summarize_paired_red_ablation",
    "summarize_red_sequences",
]
