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
from .ablation_runner import (
    PairedRedAblationExecution,
    PairedTrialExecutor,
    execute_paired_red_ablation,
    execute_paired_red_ablation_with_observations,
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
from .policy_experiment import (
    JudgeTrialBinding,
    MechanismPolicyTrialExecutor,
    RedModelDelegateFactory,
    TargetTrialBinding,
    build_mechanism_policy_ablation_contract,
    execute_mechanism_policy_ablation,
    fingerprint_campaign_budget,
    fingerprint_red_model_config,
)
from .portfolio import PortfolioCandidateScore, RiskAwarePortfolioPolicy
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
    "JudgeTrialBinding",
    "MechanismAwareAdaptiveRedStrategy",
    "MechanismCampaignMemory",
    "MechanismGuidance",
    "MechanismLearningRecord",
    "MechanismMemorySnapshot",
    "MechanismPolicy",
    "MechanismPolicyTrialExecutor",
    "MechanismRedDecision",
    "PairedRedAblationContract",
    "PairedRedAblationExecution",
    "PairedRedAblationReport",
    "PairedRedObservation",
    "PairedTrialExecutor",
    "PairedTrialPlan",
    "PairingMode",
    "PortfolioCandidateScore",
    "RedAction",
    "RedCampaignMemory",
    "RedDecision",
    "RedLearningRecord",
    "RedMemorySnapshot",
    "RedModelDelegateFactory",
    "RedPhase",
    "RedPlan",
    "RedPlanner",
    "RedSequenceMetrics",
    "RiskAwarePortfolioPolicy",
    "SequenceRate",
    "TargetTrialBinding",
    "build_counterbalanced_pair_plan",
    "build_mechanism_policy_ablation_contract",
    "execute_mechanism_policy_ablation",
    "execute_paired_red_ablation",
    "execute_paired_red_ablation_with_observations",
    "fingerprint_campaign_budget",
    "fingerprint_red_model_config",
    "observation_from_run",
    "summarize_adaptive_red",
    "summarize_paired_red_ablation",
    "summarize_red_sequences",
]
