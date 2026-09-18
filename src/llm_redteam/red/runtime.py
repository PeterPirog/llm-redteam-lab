"""Campaign-scoped runtime for model-backed adaptive multi-turn Red strategies.

The runtime is deliberately created inside the persisted campaign lifecycle. It
shares the campaign BudgetLedger with target execution, starts from empty
transcript-free learning memory, and freezes cross-trial learning for held-out
EVALUATION while preserving within-conversation adaptation.

Live within-conversation adaptation is restricted to target-visible evidence. The
independent Judge remains available only after a run for DISCOVERY learning, preventing
oracle leakage from the measurement layer into the attacker being measured.

Intentional multi-attacker execution uses explicit attacker variants. Each variant owns
separate transcript-free Red learning memory while every variant shares the same campaign
BudgetLedger. Provider fallback remains unrelated availability behavior.
"""

from __future__ import annotations

from hashlib import sha256

from pydantic import Field

from ..agent_actions import canonical_json_hash
from ..budget import BudgetLedger
from ..campaign_plan import RedPolicyKind
from ..campaigns.multiturn import ConversationBudget, ConversationRunResult, MultiTurnStrategy
from ..domain import AttackCase, CampaignBudget, StrictModel, TargetClass, TargetMode
from ..evaluation_protocol import CampaignPurpose
from ..model_client import (
    AttackerVariantRoleModelClient,
    BudgetedRoleModelClient,
    RoleModelClient,
)
from ..model_roles import ModelRole, ModelRoleConfig, ModelsConfig
from ..targets.base import SessionMode
from .adaptive import RedCampaignMemory, RedMemorySnapshot
from .agent_adaptive import (
    TargetVisibleAgentAdaptiveRedStrategy,
    TargetVisibleAgentMechanismAwareAdaptiveRedStrategy,
)
from .coverage import (
    RedMechanismCoverage,
    eligible_mechanisms_for_runtime,
    summarize_mechanism_coverage,
)
from .fixture_adaptive import (
    FixturePrimedAgentAdaptiveRedStrategy,
    FixturePrimedAgentMechanismAwareAdaptiveRedStrategy,
    FixturePrimer,
)
from .live_feedback import (
    LIVE_FEEDBACK_SCOPE,
    POST_RUN_DISCOVERY_FEEDBACK,
    TargetVisibleAdaptiveRedStrategy,
    TargetVisibleMechanismAwareAdaptiveRedStrategy,
)
from .mechanisms import (
    AttackMechanism,
    MechanismCampaignMemory,
    MechanismMemorySnapshot,
    MechanismPolicy,
)
from .portfolio import RiskAwarePortfolioPolicy

_RED_RUNTIME_VERSION = 2
_AGENT_RED_RUNTIME_VERSION = 3
_AGENT_FIXTURE_RED_RUNTIME_VERSION = 4
_MULTI_ATTACKER_VERSION_INCREMENT = 1


class RedRuntimeDiagnostics(StrictModel):
    """Transcript-free adaptive-search diagnostics, never comparative Blue metrics."""

    tactic_memory: dict[str, RedMemorySnapshot] = Field(default_factory=dict)
    mechanism_memory: dict[str, MechanismMemorySnapshot] = Field(default_factory=dict)
    mechanism_coverage: RedMechanismCoverage | None = None
    comparable_blue_estimate: bool = False


def build_model_backed_red_policy_descriptor(
    *,
    policy: RedPolicyKind,
    purpose: CampaignPurpose,
    target_class: TargetClass,
    target_mode: TargetMode,
    session_mode: SessionMode,
    campaign_budget: CampaignBudget,
    models: ModelsConfig,
    duplicate_similarity_threshold: float = 0.92,
    fixture_priming_enabled: bool = False,
    attacker_variant_id: str | None = None,
    red_measurement_binding_sha256: str | None = None,
) -> dict[str, object]:
    """Build the exact campaign-start Red identity without making an inference call."""

    if not policy.model_backed:
        raise ValueError("model-backed Red descriptor requires a model-backed policy")
    if not 0.0 <= duplicate_similarity_threshold <= 1.0:
        raise ValueError("duplicate_similarity_threshold must be between 0 and 1")
    if fixture_priming_enabled and target_mode != TargetMode.AGENT:
        raise ValueError("fixture-primed adaptive Red currently requires target_mode=AGENT")
    if red_measurement_binding_sha256 is not None and (
        len(red_measurement_binding_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in red_measurement_binding_sha256
        )
    ):
        raise ValueError("Red measurement binding must be a lowercase SHA-256")

    planner = models.resolve_role_config(
        ModelRole.RED_PLANNER,
        attacker_variant_id=attacker_variant_id,
        required_capabilities={"text", "reasoning"},
    )
    mutator = models.resolve_role_config(
        ModelRole.RED_MUTATOR,
        attacker_variant_id=attacker_variant_id,
        required_capabilities={"text"},
    )
    conversation_budget = _conversation_budget(
        campaign_budget,
        session_mode,
        target_mode,
    )

    mechanism_policy: dict[str, object] | None = None
    if policy == RedPolicyKind.MECHANISM:
        mechanism_policy = MechanismPolicy(
            conversation_budget=conversation_budget
        ).descriptor()
    elif policy == RedPolicyKind.PORTFOLIO:
        mechanism_policy = RiskAwarePortfolioPolicy(
            conversation_budget=conversation_budget
        ).descriptor()

    descriptor: dict[str, object] = {
        "kind": policy.value,
        "runtime_version": _RED_RUNTIME_VERSION,
        "target_class": target_class.value,
        "target_mode": target_mode.value,
        "session_mode": session_mode.value,
        "within_conversation_adaptation": True,
        "live_feedback_scope": LIVE_FEEDBACK_SCOPE,
        "post_run_discovery_feedback": (
            POST_RUN_DISCOVERY_FEEDBACK
            if purpose == CampaignPurpose.DISCOVERY
            else "disabled"
        ),
        "cross_trial_learning_enabled": purpose == CampaignPurpose.DISCOVERY,
        "duplicate_similarity_threshold": duplicate_similarity_threshold,
        "conversation_budget": conversation_budget.model_dump(mode="json"),
        "stopping_policy": conversation_budget.stopping_policy,
        "red_planner": _model_role_descriptor(planner),
        "red_mutator": _model_role_descriptor(mutator),
        "mechanism_policy": mechanism_policy,
        "initial_learning_memory": "empty-v1",
    }
    if red_measurement_binding_sha256 is not None:
        descriptor["red_measurement_binding_sha256"] = red_measurement_binding_sha256
    if target_mode == TargetMode.AGENT:
        descriptor["runtime_version"] = _AGENT_RED_RUNTIME_VERSION
        descriptor["threat_lens"] = "agent-system-v1"
        descriptor["layer_aware_stopping"] = "model-to-system-escalation-v1"
    if fixture_priming_enabled:
        descriptor["runtime_version"] = _AGENT_FIXTURE_RED_RUNTIME_VERSION
        descriptor["fixture_priming"] = "immutable-environment-fixture-v1"
        descriptor["first_turn_source"] = "fixture_legitimate_task"
    if attacker_variant_id is not None:
        variant = models.attacker_variant(attacker_variant_id)
        descriptor["runtime_version"] = (
            int(descriptor["runtime_version"]) + _MULTI_ATTACKER_VERSION_INCREMENT
        )
        descriptor["attacker_variant"] = {
            "id": variant.id,
            "configuration_fingerprint": variant.configuration_fingerprint,
        }
    return descriptor


class RedStrategyRuntime:
    """Create and learn one campaign-scoped Red attacker under an immutable contract."""

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
        fixture_priming_enabled: bool = False,
        attacker_variant_id: str | None = None,
        red_measurement_binding_sha256: str | None = None,
    ) -> None:
        self._descriptor = build_model_backed_red_policy_descriptor(
            policy=policy,
            purpose=purpose,
            target_class=target_class,
            target_mode=target_mode,
            session_mode=session_mode,
            campaign_budget=campaign_budget,
            models=models,
            duplicate_similarity_threshold=duplicate_similarity_threshold,
            fixture_priming_enabled=fixture_priming_enabled,
            attacker_variant_id=attacker_variant_id,
            red_measurement_binding_sha256=red_measurement_binding_sha256,
        )

        self.policy = policy
        self.purpose = purpose
        self.target_class = target_class
        self.target_mode = target_mode
        self.session_mode = session_mode
        self.campaign_budget = campaign_budget
        self.models_config = models
        self.attacker_variant_id = attacker_variant_id
        budgeted_client: RoleModelClient = BudgetedRoleModelClient(
            model_client,
            models=models,
            budget=budget,
        )
        self.model_client = (
            AttackerVariantRoleModelClient(
                budgeted_client,
                attacker_variant_id=attacker_variant_id,
            )
            if attacker_variant_id is not None
            else budgeted_client
        )
        self.duplicate_similarity_threshold = duplicate_similarity_threshold
        self.fixture_priming_enabled = fixture_priming_enabled
        self.red_measurement_binding_sha256 = red_measurement_binding_sha256
        self.tactic_memory = RedCampaignMemory()
        self.mechanism_memory = MechanismCampaignMemory()
        self._observed_families: set[str] = set()
        self.conversation_budget = _conversation_budget(
            campaign_budget,
            session_mode,
            target_mode,
        )

    @property
    def cross_trial_learning_enabled(self) -> bool:
        return self.purpose == CampaignPurpose.DISCOVERY

    def descriptor(self) -> dict[str, object]:
        """Return the exact immutable campaign-start Red identity."""

        return dict(self._descriptor)

    def strategy_for(
        self,
        case: AttackCase,
        *,
        fixture_primer: FixturePrimer | None = None,
    ) -> MultiTurnStrategy:
        """Create one strategy while sharing only this attacker's transcript-free memory."""

        if case.interaction_mode != "multi_turn":
            raise ValueError(
                f"model-backed Red currently requires multi_turn case, got {case.interaction_mode}"
            )
        if fixture_primer is not None and not self.fixture_priming_enabled:
            raise ValueError("fixture primer supplied to a runtime without fixture priming")
        if fixture_primer is not None and self.target_mode != TargetMode.AGENT:
            raise ValueError("fixture primer requires an AGENT target")

        common = {
            "case": case,
            "target_class": self.target_class,
            "target_mode": self.target_mode,
            "conversation_budget": self.conversation_budget,
            "models": self.model_client,
            "memory": self.tactic_memory,
            "duplicate_similarity_threshold": self.duplicate_similarity_threshold,
        }
        if fixture_primer is not None:
            adaptive_cls = FixturePrimedAgentAdaptiveRedStrategy
            mechanism_cls = FixturePrimedAgentMechanismAwareAdaptiveRedStrategy
        else:
            adaptive_cls = (
                TargetVisibleAgentAdaptiveRedStrategy
                if self.target_mode == TargetMode.AGENT
                else TargetVisibleAdaptiveRedStrategy
            )
            mechanism_cls = (
                TargetVisibleAgentMechanismAwareAdaptiveRedStrategy
                if self.target_mode == TargetMode.AGENT
                else TargetVisibleMechanismAwareAdaptiveRedStrategy
            )

        if self.policy == RedPolicyKind.ADAPTIVE:
            if fixture_primer is not None:
                return adaptive_cls(**common, fixture_primer=fixture_primer)
            return adaptive_cls(**common)
        if self.policy == RedPolicyKind.MECHANISM:
            mechanism_kwargs = {
                **common,
                "mechanism_memory": self.mechanism_memory,
                "mechanism_policy": MechanismPolicy(
                    conversation_budget=self.conversation_budget
                ),
                "cross_trial_learning_enabled": self.cross_trial_learning_enabled,
            }
            if fixture_primer is not None:
                mechanism_kwargs["fixture_primer"] = fixture_primer
            return mechanism_cls(**mechanism_kwargs)
        if self.policy == RedPolicyKind.PORTFOLIO:
            portfolio_kwargs = {
                **common,
                "mechanism_memory": self.mechanism_memory,
                "mechanism_policy": RiskAwarePortfolioPolicy(
                    conversation_budget=self.conversation_budget
                ),
                "cross_trial_learning_enabled": self.cross_trial_learning_enabled,
            }
            if fixture_primer is not None:
                portfolio_kwargs["fixture_primer"] = fixture_primer
            return mechanism_cls(**portfolio_kwargs)
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
        tactic_memory = {
            family: self.tactic_memory.snapshot(family) for family in families
        }
        mechanism_memory = (
            {
                family: self.mechanism_memory.snapshot(family)
                for family in families
            }
            if self.policy in {RedPolicyKind.MECHANISM, RedPolicyKind.PORTFOLIO}
            else {}
        )
        mechanism_coverage = None
        if mechanism_memory:
            eligible = eligible_mechanisms_for_runtime(
                session_mode=self.session_mode,
                conversation_budget=self.conversation_budget,
            )
            if self.fixture_priming_enabled:
                eligible = (AttackMechanism.FIXTURE_TRIGGER, *eligible)
            mechanism_coverage = summarize_mechanism_coverage(
                tuple(mechanism_memory.values()),
                eligible_mechanisms=eligible,
            )
        return RedRuntimeDiagnostics(
            tactic_memory=tactic_memory,
            mechanism_memory=mechanism_memory,
            mechanism_coverage=mechanism_coverage,
        )


class RedAttackerPoolRuntime:
    """Registry of explicit Red variants sharing one campaign inference budget."""

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
        fixture_priming_enabled: bool = False,
    ) -> None:
        variants = models.red_attacker_pool.enabled_variants
        if len(variants) < 2:
            raise ValueError("multi-attacker runtime requires an enabled attacker pool")
        self.models_config = models
        self.budget = budget
        self._runtimes = {
            variant.id: RedStrategyRuntime(
                policy=policy,
                purpose=purpose,
                target_class=target_class,
                target_mode=target_mode,
                session_mode=session_mode,
                campaign_budget=campaign_budget,
                models=models,
                model_client=model_client,
                budget=budget,
                duplicate_similarity_threshold=duplicate_similarity_threshold,
                fixture_priming_enabled=fixture_priming_enabled,
                attacker_variant_id=variant.id,
            )
            for variant in variants
        }

    @property
    def variant_ids(self) -> tuple[str, ...]:
        return tuple(self._runtimes)

    @property
    def pool_fingerprint(self) -> str:
        return canonical_json_hash(
            {
                variant_id: runtime.descriptor()
                for variant_id, runtime in self._runtimes.items()
            }
        )

    def runtime_for(self, variant_id: str) -> RedStrategyRuntime:
        try:
            return self._runtimes[variant_id]
        except KeyError as exc:
            raise ValueError(f"unknown Red attacker runtime variant: {variant_id}") from exc

    def descriptors(self) -> dict[str, dict[str, object]]:
        return {
            variant_id: runtime.descriptor()
            for variant_id, runtime in self._runtimes.items()
        }


def _conversation_budget(
    budget: CampaignBudget,
    session_mode: SessionMode,
    target_mode: TargetMode,
) -> ConversationBudget:
    layer_aware_agent = target_mode == TargetMode.AGENT
    if session_mode == SessionMode.TARGET_MANAGED:
        return ConversationBudget(
            max_turns=budget.max_turns_per_attack,
            max_backtracks=0,
            max_branches=1,
            continue_after_success=layer_aware_agent,
            stop_after_system_compromise=layer_aware_agent,
        )
    return ConversationBudget(
        max_turns=budget.max_turns_per_attack,
        max_backtracks=budget.max_backtracks_per_attack,
        max_branches=budget.max_branches_per_attack,
        continue_after_success=layer_aware_agent,
        stop_after_system_compromise=layer_aware_agent,
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
