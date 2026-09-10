"""Campaign-scoped runtime for model-backed adaptive multi-turn Red strategies.

The runtime is deliberately created inside the persisted campaign lifecycle. It
shares the campaign BudgetLedger with target execution, starts from empty
transcript-free learning memory, and freezes cross-trial learning for held-out
EVALUATION while preserving within-conversation adaptation.
"""

from __future__ import annotations

from hashlib import sha256

from pydantic import Field

from ..budget import BudgetLedger
from ..campaign_plan import RedPolicyKind
from ..campaigns.multiturn import ConversationBudget, ConversationRunResult, MultiTurnStrategy
from ..domain import AttackCase, CampaignBudget, StrictModel, TargetClass, TargetMode
from ..evaluation_protocol import CampaignPurpose
from ..model_client import BudgetedRoleModelClient, RoleModelClient
from ..model_roles import ModelRole, ModelRoleConfig, ModelsConfig
from ..targets.base import SessionMode
from .adaptive import AdaptiveRedStrategy, RedCampaignMemory, RedMemorySnapshot
from .mechanism_adaptive import MechanismAwareAdaptiveRedStrategy
from .mechanisms import MechanismCampaignMemory, MechanismMemorySnapshot, MechanismPolicy
from .portfolio import RiskAwarePortfolioPolicy

_RED_RUNTIME_VERSION = 1


class RedRuntimeDiagnostics(StrictModel):
    """Transcript-free adaptive-search diagnostics, never comparative Blue metrics."""

    tactic_memory: dict[str, RedMemorySnapshot] = Field(default_factory=dict)
    mechanism_memory: dict[str, MechanismMemorySnapshot] = Field(default_factory=dict)
    comparable_blue_estimate: bool = False


class RedStrategyRuntime:
    """Create and learn campaign-scoped Red strategies under one immutable contract."""

    def __init__(
        self,
        *,
        policy: RedPolicyKind,
        purpose: CampaignPurpose,
        target_class: TargetClass,
        target_mode: TargetMode,
        session_mode: SessionMode,
        campaign_budget: CampaignBudget,
        models: ModelsConfig,
        model_client: RoleModelClient,
        budget: BudgetLedger,
        duplicate_similarity_threshold: float = 0.92,
    ) -> None:
        if not policy.model_backed:
            raise ValueError("RedStrategyRuntime requires a model-backed Red policy")
        if not 0.0 <= duplicate_similarity_threshold <= 1.0:
            raise ValueError("duplicate_similarity_threshold must be between 0 and 1")

        models.role(
            ModelRole.RED_PLANNER,
            required_capabilities={"text", "reasoning"},
        )
        models.role(ModelRole.RED_MUTATOR, required_capabilities={"text"})

        self.policy = policy
        self.purpose = purpose
        self.target_class = target_class
        self.target_mode = target_mode
        self.session_mode = session_mode
        self.campaign_budget = campaign_budget
        self.models_config = models
        self.model_client = BudgetedRoleModelClient(
            model_client,
            models=models,
            budget=budget,
        )
        self.duplicate_similarity_threshold = duplicate_similarity_threshold
        self.tactic_memory = RedCampaignMemory()
        self.mechanism_memory = MechanismCampaignMemory()
        self._observed_families: set[str] = set()
        self.conversation_budget = _conversation_budget(campaign_budget, session_mode)

    @property
    def cross_trial_learning_enabled(self) -> bool:
        return self.purpose == CampaignPurpose.DISCOVERY

    def descriptor(self) -> dict[str, object]:
        """Return the exact starting Red policy identity used for measurement binding."""

        mechanism_policy: dict[str, object] | None = None
        if self.policy == RedPolicyKind.MECHANISM:
            mechanism_policy = MechanismPolicy(
                conversation_budget=self.conversation_budget
            ).descriptor()
        elif self.policy == RedPolicyKind.PORTFOLIO:
            mechanism_policy = RiskAwarePortfolioPolicy(
                conversation_budget=self.conversation_budget
            ).descriptor()

        return {
            "kind": self.policy.value,
            "runtime_version": _RED_RUNTIME_VERSION,
            "target_class": self.target_class.value,
            "target_mode": self.target_mode.value,
            "session_mode": self.session_mode.value,
            "within_conversation_adaptation": True,
            "cross_trial_learning_enabled": self.cross_trial_learning_enabled,
            "duplicate_similarity_threshold": self.duplicate_similarity_threshold,
            "conversation_budget": self.conversation_budget.model_dump(mode="json"),
            "red_planner": _model_role_descriptor(
                self.models_config.role(
                    ModelRole.RED_PLANNER,
                    required_capabilities={"text", "reasoning"},
                )
            ),
            "red_mutator": _model_role_descriptor(
                self.models_config.role(
                    ModelRole.RED_MUTATOR,
                    required_capabilities={"text"},
                )
            ),
            "mechanism_policy": mechanism_policy,
            "initial_learning_memory": "empty-v1",
        }

    def strategy_for(self, case: AttackCase) -> MultiTurnStrategy:
        """Create one per-conversation strategy sharing only transcript-free campaign memory."""

        if case.interaction_mode != "multi_turn":
            raise ValueError(
                f"model-backed Red currently requires multi_turn case, got {case.interaction_mode}"
            )
        common = {
            "case": case,
            "target_class": self.target_class,
            "target_mode": self.target_mode,
            "conversation_budget": self.conversation_budget,
            "models": self.model_client,
            "memory": self.tactic_memory,
            "duplicate_similarity_threshold": self.duplicate_similarity_threshold,
        }
        if self.policy == RedPolicyKind.ADAPTIVE:
            return AdaptiveRedStrategy(**common)
        if self.policy == RedPolicyKind.MECHANISM:
            return MechanismAwareAdaptiveRedStrategy(
                **common,
                mechanism_memory=self.mechanism_memory,
                mechanism_policy=MechanismPolicy(
                    conversation_budget=self.conversation_budget
                ),
                cross_trial_learning_enabled=self.cross_trial_learning_enabled,
            )
        if self.policy == RedPolicyKind.PORTFOLIO:
            return MechanismAwareAdaptiveRedStrategy(
                **common,
                mechanism_memory=self.mechanism_memory,
                mechanism_policy=RiskAwarePortfolioPolicy(
                    conversation_budget=self.conversation_budget
                ),
                cross_trial_learning_enabled=self.cross_trial_learning_enabled,
            )
        raise ValueError(f"unsupported model-backed Red policy: {self.policy.value}")

    def observe(
        self,
        *,
        case: AttackCase,
        strategy: MultiTurnStrategy,
        result: ConversationRunResult,
    ) -> None:
        """Learn only during DISCOVERY; held-out EVALUATION is cross-trial frozen."""

        if not self.cross_trial_learning_enabled:
            return
        learn = getattr(strategy, "learn", None)
        if not callable(learn):
            raise TypeError("model-backed Red strategy does not expose learn(result)")
        learn(result)
        self._observed_families.add(case.attack_family[0])

    def diagnostics(self) -> RedRuntimeDiagnostics | None:
        """Return learned search diagnostics only when discovery learning was enabled."""

        if not self.cross_trial_learning_enabled:
            return None
        families = sorted(self._observed_families)
        return RedRuntimeDiagnostics(
            tactic_memory={
                family: self.tactic_memory.snapshot(family) for family in families
            },
            mechanism_memory=(
                {
                    family: self.mechanism_memory.snapshot(family)
                    for family in families
                }
                if self.policy in {RedPolicyKind.MECHANISM, RedPolicyKind.PORTFOLIO}
                else {}
            ),
        )


def _conversation_budget(
    budget: CampaignBudget,
    session_mode: SessionMode,
) -> ConversationBudget:
    if session_mode == SessionMode.TARGET_MANAGED:
        return ConversationBudget(
            max_turns=budget.max_turns_per_attack,
            max_backtracks=0,
            max_branches=1,
            continue_after_success=False,
        )
    return ConversationBudget(
        max_turns=budget.max_turns_per_attack,
        max_backtracks=budget.max_backtracks_per_attack,
        max_branches=budget.max_branches_per_attack,
        continue_after_success=False,
    )


def _model_role_descriptor(config: ModelRoleConfig) -> dict[str, object]:
    endpoint_hash = sha256(config.endpoint.encode()).hexdigest() if config.endpoint else None
    return {
        "provider": config.provider,
        "model": config.model,
        "location": config.location.value,
        "capabilities": sorted(config.capabilities),
        "endpoint_sha256": endpoint_hash,
        "profile": config.profile,
        "temperature": config.temperature,
        "max_output_tokens": config.max_output_tokens,
        "context_tokens": config.context_tokens,
        "enabled": config.enabled,
        "invoke": config.invoke,
        "fallback": list(config.fallback),
    }
