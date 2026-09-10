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
from .ablation_runner import PairedTrialExecutor, execute_paired_red_ablation
from .adaptive import (
    AdaptiveRedStrategy,
    RedAction,
    RedCampaignMemory,
    RedDecision,
    RedLearningRecord,
    RedMemorySnapshot,
    RedPhase,
)
from .agent_adaptive import (
    TargetVisibleAgentAdaptiveRedStrategy,
    TargetVisibleAgentMechanismAwareAdaptiveRedStrategy,
)
from .base import AttackHypothesis, AttackObservation, RedPlan, RedPlanner
from .coverage import (
    MechanismCoverageCell,
    MechanismCoverageState,
    RedCoverageAssessment,
    RedCoveragePolicy,
    RedCoverageStatus,
    RedMechanismCoverage,
    assess_red_coverage,
    eligible_mechanisms_for_runtime,
    summarize_mechanism_coverage,
)
from .efficiency import AdaptiveRedEfficiency, summarize_adaptive_red
from .heuristic import HeuristicRedPlanner
from .live_feedback import (
    LIVE_FEEDBACK_SCOPE,
    TargetVisibleAdaptiveRedStrategy,
    TargetVisibleMechanismAwareAdaptiveRedStrategy,
    target_visible_conversation_state,
)
from .mechanism_adaptive import MechanismAwareAdaptiveRedStrategy, MechanismRedDecision
from .mechanisms import (
    AttackMechanism,
    MechanismCampaignMemory,
    MechanismGuidance,
    MechanismLearningRecord,
    MechanismMemorySnapshot,
    MechanismPolicy,
)
from .portfolio import PortfolioCandidateScore, RiskAwarePortfolioPolicy
from .qualification import (
    RedPolicyQualificationDecision,
    RedPolicyQualificationPolicy,
    RedPolicyQualificationStatus,
    qualify_red_policy,
)
from .scripted import ScriptedPayloadStrategy
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
    "LIVE_FEEDBACK_SCOPE",
    "MechanismAwareAdaptiveRedStrategy",
    "MechanismCampaignMemory",
    "MechanismCoverageCell",
    "MechanismCoverageState",
    "MechanismGuidance",
    "MechanismLearningRecord",
    "MechanismMemorySnapshot",
    "MechanismPolicy",
    "MechanismRedDecision",
    "PairedRedAblationContract",
    "PairedRedAblationReport",
    "PairedRedObservation",
    "PairedTrialExecutor",
    "PairedTrialPlan",
    "PairingMode",
    "PortfolioCandidateScore",
    "RedAction",
    "RedCampaignMemory",
    "RedCoverageAssessment",
    "RedCoveragePolicy",
    "RedCoverageStatus",
    "RedDecision",
    "RedLearningRecord",
    "RedMechanismCoverage",
    "RedMemorySnapshot",
    "RedPhase",
    "RedPlan",
    "RedPlanner",
    "RedPolicyQualificationDecision",
    "RedPolicyQualificationPolicy",
    "RedPolicyQualificationStatus",
    "RedSequenceMetrics",
    "RiskAwarePortfolioPolicy",
    "ScriptedPayloadStrategy",
    "SequenceRate",
    "TargetVisibleAdaptiveRedStrategy",
    "TargetVisibleAgentAdaptiveRedStrategy",
    "TargetVisibleAgentMechanismAwareAdaptiveRedStrategy",
    "TargetVisibleMechanismAwareAdaptiveRedStrategy",
    "assess_red_coverage",
    "build_counterbalanced_pair_plan",
    "eligible_mechanisms_for_runtime",
    "execute_paired_red_ablation",
    "observation_from_run",
    "qualify_red_policy",
    "summarize_adaptive_red",
    "summarize_mechanism_coverage",
    "summarize_paired_red_ablation",
    "summarize_red_sequences",
    "target_visible_conversation_state",
]
