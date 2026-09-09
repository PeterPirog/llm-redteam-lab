"""Paired component ablation for controlled multi-turn Red evaluation.

The module compares two Red policies under the same held-out Blue measurement
conditions. It deliberately keeps attacker effectiveness, model compromise,
system compromise and resource cost as separate outputs instead of collapsing them
into one score.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from math import comb
from statistics import fmean, median

from pydantic import Field, model_validator

from ..budget import BudgetSnapshot
from ..campaigns.multiturn import ConversationRunResult
from ..domain import ExecutionResult, StrictModel
from ..evaluation_protocol import (
    EvaluationMetrics,
    MeasurementProtocol,
    held_out_evaluation_protocol,
    summarize_evaluation,
)
from ..evaluation_sets import HeldOutEvaluationManifest
from ..metrics import RateEstimate, wilson_rate

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AblationArm(StrEnum):
    BASELINE = "BASELINE"
    TREATMENT = "TREATMENT"


class PairingMode(StrEnum):
    """Strength of the stochastic pairing used by the experiment."""

    CASE_REPLICATE = "CASE_REPLICATE"
    CASE_REPLICATE_SEED = "CASE_REPLICATE_SEED"


class AblationExecutionOrder(StrEnum):
    """Order policy used to limit systematic temporal/runtime bias."""

    COUNTERBALANCED = "COUNTERBALANCED"


class PairedTrialPlan(StrictModel):
    """Deterministic execution order and optional shared seed for one matched pair."""

    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    first_arm: AblationArm
    pair_seed: int | None = Field(default=None, ge=0)


class PairedRedAblationContract(StrictModel):
    """Controlled conditions that must be identical across both Red arms."""

    experiment_id: str = Field(min_length=1)
    target_snapshot_id: str = Field(min_length=1)
    judge_fingerprint: str = Field(pattern=_HASH_PATTERN)
    budget_fingerprint: str = Field(pattern=_HASH_PATTERN)
    evaluation_manifest_hash: str = Field(pattern=_HASH_PATTERN)
    metric_definition_version: str = Field(min_length=1)
    session_mode: str = Field(min_length=1)
    changed_component: str = Field(min_length=1)
    baseline_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    treatment_policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    pairing_mode: PairingMode = PairingMode.CASE_REPLICATE
    execution_order_policy: AblationExecutionOrder = AblationExecutionOrder.COUNTERBALANCED

    @model_validator(mode="after")
    def policies_must_differ(self) -> PairedRedAblationContract:
        if self.baseline_policy_fingerprint == self.treatment_policy_fingerprint:
            raise ValueError("paired ablation requires different Red policy fingerprints")
        return self


class PairedRedObservation(StrictModel):
    """One arm of one matched case/replicate pair."""

    arm: AblationArm
    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    policy_fingerprint: str = Field(pattern=_HASH_PATTERN)
    pair_seed: int | None = None
    execution: ExecutionResult
    target_interactions: int = Field(ge=0)
    backtracks: int = Field(ge=0)
    branches_created: int = Field(ge=0)
    first_violation_ordinal: int | None = Field(default=None, gt=0)
    first_violation_depth: int | None = Field(default=None, gt=0)
    planner_calls: int = Field(ge=0)
    mutator_calls: int = Field(ge=0)
    planner_output_tokens: int = Field(ge=0)
    mutator_output_tokens: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0.0)

    @model_validator(mode="after")
    def execution_matches_case(self) -> PairedRedObservation:
        if self.execution.attack_id != self.case_id:
            raise ValueError("observation case_id does not match execution attack_id")
        return self

    @property
    def pair_key(self) -> tuple[str, int]:
        return self.case_id, self.replicate


@dataclass(frozen=True, slots=True)
class PairedRedAblationReport:
    """Controlled effectiveness and cost comparison for two Red policies."""

    contract: PairedRedAblationContract
    pair_count: int
    baseline: EvaluationMetrics
    treatment: EvaluationMetrics
    objective_violation_rate_delta: float
    model_compromise_rate_delta: float
    system_compromise_rate_delta: float
    both_objective_successes: int
    baseline_only_objective_successes: int
    treatment_only_objective_successes: int
    neither_objective_successes: int
    discordant_pairs: int
    exact_mcnemar_p_value: float
    treatment_win_rate_among_discordant: RateEstimate
    mean_target_interaction_delta: float
    median_target_interaction_delta: float
    mean_planner_call_delta: float
    mean_mutator_call_delta: float
    mean_output_token_delta: float
    median_first_violation_ordinal_delta_on_joint_success: float | None
    comparable_red_component_estimate: bool = True


def build_counterbalanced_pair_plan(
    *,
    contract: PairedRedAblationContract,
    manifest: HeldOutEvaluationManifest,
    replicates_per_case: int,
) -> tuple[PairedTrialPlan, ...]:
    """Build a deterministic alternating execution schedule for matched pairs.

    The first arm alternates across sorted case/replicate keys. Which arm starts the
    sequence is derived from ``experiment_id`` so separate experiments do not always
    privilege the baseline. In seed-pairing mode, a stable per-pair seed is derived
    from the experiment and pair identity and must be reused by both arms.
    """

    if contract.evaluation_manifest_hash != manifest.content_hash:
        raise ValueError("ablation contract does not match held-out evaluation manifest")
    if replicates_per_case <= 0:
        raise ValueError("replicates_per_case must be positive")

    case_ids = sorted(item.case_id for item in manifest.evaluation_cases)
    pair_keys = [
        (case_id, replicate)
        for case_id in case_ids
        for replicate in range(replicates_per_case)
    ]
    experiment_parity = int(sha256(contract.experiment_id.encode()).hexdigest()[-1], 16) % 2

    plans: list[PairedTrialPlan] = []
    for index, (case_id, replicate) in enumerate(pair_keys):
        baseline_first = (index + experiment_parity) % 2 == 0
        pair_seed = None
        if contract.pairing_mode == PairingMode.CASE_REPLICATE_SEED:
            raw_seed = sha256(
                f"{contract.experiment_id}:{case_id}:{replicate}".encode()
            ).hexdigest()
            pair_seed = int(raw_seed[:8], 16)
        plans.append(
            PairedTrialPlan(
                case_id=case_id,
                replicate=replicate,
                first_arm=(
                    AblationArm.BASELINE if baseline_first else AblationArm.TREATMENT
                ),
                pair_seed=pair_seed,
            )
        )
    return tuple(plans)


def observation_from_run(
    *,
    arm: AblationArm,
    replicate: int,
    policy_fingerprint: str,
    result: ConversationRunResult,
    budget_before: BudgetSnapshot,
    budget_after: BudgetSnapshot,
    pair_seed: int | None = None,
) -> PairedRedObservation:
    """Build one ablation observation from a bounded conversation and ledger delta."""

    usage = _budget_delta(budget_before, budget_after)
    if usage["turns"] != len(result.turns):
        raise ValueError("budget turn delta does not match conversation target interactions")

    return PairedRedObservation(
        arm=arm,
        case_id=result.execution.attack_id,
        replicate=replicate,
        policy_fingerprint=policy_fingerprint,
        pair_seed=pair_seed,
        execution=result.execution,
        target_interactions=len(result.turns),
        backtracks=result.backtracks,
        branches_created=max(0, result.branches - 1),
        first_violation_ordinal=result.first_violation_ordinal,
        first_violation_depth=result.first_violation_depth,
        planner_calls=usage["planner_calls"],
        mutator_calls=usage["mutator_calls"],
        planner_output_tokens=usage["planner_output_tokens"],
        mutator_output_tokens=usage["mutator_output_tokens"],
        elapsed_seconds=usage["elapsed_seconds"],
    )


def summarize_paired_red_ablation(
    observations: Iterable[PairedRedObservation],
    *,
    contract: PairedRedAblationContract,
    manifest: HeldOutEvaluationManifest,
    protocol: MeasurementProtocol | None = None,
    confidence_level: float = 0.95,
) -> PairedRedAblationReport:
    """Compare two Red policies only after strict matched-pair and held-out gates."""

    if contract.evaluation_manifest_hash != manifest.content_hash:
        raise ValueError("ablation contract does not match held-out evaluation manifest")

    resolved_protocol = protocol or held_out_evaluation_protocol()
    rows = tuple(observations)
    if not rows:
        raise ValueError("paired Red ablation requires observations")

    baseline = _index_arm(rows, AblationArm.BASELINE, contract.baseline_policy_fingerprint)
    treatment = _index_arm(rows, AblationArm.TREATMENT, contract.treatment_policy_fingerprint)
    if set(baseline) != set(treatment):
        missing_baseline = sorted(set(treatment) - set(baseline))
        missing_treatment = sorted(set(baseline) - set(treatment))
        raise ValueError(
            "paired Red ablation requires identical case/replicate keys; "
            f"missing_baseline={missing_baseline}, missing_treatment={missing_treatment}"
        )

    keys = sorted(baseline)
    _validate_pairing(keys, baseline, treatment, contract.pairing_mode)

    baseline_metrics = summarize_evaluation(
        (baseline[key].execution for key in keys),
        resolved_protocol,
        manifest,
        confidence_level,
    )
    treatment_metrics = summarize_evaluation(
        (treatment[key].execution for key in keys),
        resolved_protocol,
        manifest,
        confidence_level,
    )

    both = baseline_only = treatment_only = neither = 0
    target_deltas: list[int] = []
    planner_deltas: list[int] = []
    mutator_deltas: list[int] = []
    token_deltas: list[int] = []
    ordinal_deltas: list[int] = []

    for key in keys:
        base = baseline[key]
        treat = treatment[key]
        base_success = base.execution.objective_violated is True
        treat_success = treat.execution.objective_violated is True
        if base_success and treat_success:
            both += 1
            if (
                base.first_violation_ordinal is not None
                and treat.first_violation_ordinal is not None
            ):
                ordinal_deltas.append(
                    treat.first_violation_ordinal - base.first_violation_ordinal
                )
        elif base_success:
            baseline_only += 1
        elif treat_success:
            treatment_only += 1
        else:
            neither += 1

        target_deltas.append(treat.target_interactions - base.target_interactions)
        planner_deltas.append(treat.planner_calls - base.planner_calls)
        mutator_deltas.append(treat.mutator_calls - base.mutator_calls)
        token_deltas.append(
            (treat.planner_output_tokens + treat.mutator_output_tokens)
            - (base.planner_output_tokens + base.mutator_output_tokens)
        )

    discordant = baseline_only + treatment_only
    baseline_campaign = baseline_metrics.campaign
    treatment_campaign = treatment_metrics.campaign

    return PairedRedAblationReport(
        contract=contract,
        pair_count=len(keys),
        baseline=baseline_metrics,
        treatment=treatment_metrics,
        objective_violation_rate_delta=_rate_delta(
            baseline_campaign.attack_success_rate,
            treatment_campaign.attack_success_rate,
        ),
        model_compromise_rate_delta=_rate_delta(
            baseline_campaign.model_compromise_rate,
            treatment_campaign.model_compromise_rate,
        ),
        system_compromise_rate_delta=_rate_delta(
            baseline_campaign.system_compromise_rate,
            treatment_campaign.system_compromise_rate,
        ),
        both_objective_successes=both,
        baseline_only_objective_successes=baseline_only,
        treatment_only_objective_successes=treatment_only,
        neither_objective_successes=neither,
        discordant_pairs=discordant,
        exact_mcnemar_p_value=_exact_mcnemar_p_value(
            baseline_only,
            treatment_only,
        ),
        treatment_win_rate_among_discordant=wilson_rate(
            treatment_only,
            discordant,
            confidence_level,
        ),
        mean_target_interaction_delta=fmean(target_deltas),
        median_target_interaction_delta=float(median(target_deltas)),
        mean_planner_call_delta=fmean(planner_deltas),
        mean_mutator_call_delta=fmean(mutator_deltas),
        mean_output_token_delta=fmean(token_deltas),
        median_first_violation_ordinal_delta_on_joint_success=(
            float(median(ordinal_deltas)) if ordinal_deltas else None
        ),
    )


def _index_arm(
    observations: tuple[PairedRedObservation, ...],
    arm: AblationArm,
    expected_policy_fingerprint: str,
) -> dict[tuple[str, int], PairedRedObservation]:
    indexed: dict[tuple[str, int], PairedRedObservation] = {}
    for row in observations:
        if row.arm != arm:
            continue
        if row.policy_fingerprint != expected_policy_fingerprint:
            raise ValueError(f"{arm.value} observation policy fingerprint mismatch")
        if row.pair_key in indexed:
            raise ValueError(f"duplicate {arm.value} paired observation: {row.pair_key}")
        indexed[row.pair_key] = row
    if not indexed:
        raise ValueError(f"paired Red ablation requires {arm.value} observations")
    return indexed


def _validate_pairing(
    keys: list[tuple[str, int]],
    baseline: dict[tuple[str, int], PairedRedObservation],
    treatment: dict[tuple[str, int], PairedRedObservation],
    pairing_mode: PairingMode,
) -> None:
    if pairing_mode != PairingMode.CASE_REPLICATE_SEED:
        return
    for key in keys:
        base_seed = baseline[key].pair_seed
        treat_seed = treatment[key].pair_seed
        if base_seed is None or treat_seed is None:
            raise ValueError("seed-paired ablation requires pair_seed in both arms")
        if base_seed != treat_seed:
            raise ValueError(f"seed mismatch for paired observation {key}")


def _budget_delta(before: BudgetSnapshot, after: BudgetSnapshot) -> dict[str, int | float]:
    def role_delta(
        left: tuple[tuple[str, int], ...],
        right: tuple[tuple[str, int], ...],
        role: str,
    ) -> int:
        before_roles = dict(left)
        after_roles = dict(right)
        delta = after_roles.get(role, 0) - before_roles.get(role, 0)
        if delta < 0:
            raise ValueError("budget counters must be monotonic")
        return delta

    turns = after.turns - before.turns
    elapsed = after.elapsed_seconds - before.elapsed_seconds
    if turns < 0 or elapsed < 0:
        raise ValueError("budget counters must be monotonic")

    return {
        "turns": turns,
        "planner_calls": role_delta(
            before.model_calls_by_role,
            after.model_calls_by_role,
            "red_planner",
        ),
        "mutator_calls": role_delta(
            before.model_calls_by_role,
            after.model_calls_by_role,
            "red_mutator",
        ),
        "planner_output_tokens": role_delta(
            before.output_tokens_by_role,
            after.output_tokens_by_role,
            "red_planner",
        ),
        "mutator_output_tokens": role_delta(
            before.output_tokens_by_role,
            after.output_tokens_by_role,
            "red_mutator",
        ),
        "elapsed_seconds": elapsed,
    }


def _rate_delta(baseline: RateEstimate, treatment: RateEstimate) -> float:
    if baseline.value is None or treatment.value is None:
        raise ValueError("paired Red ablation rates unexpectedly unavailable")
    return treatment.value - baseline.value


def _exact_mcnemar_p_value(baseline_only: int, treatment_only: int) -> float:
    """Two-sided exact McNemar/binomial p-value for discordant matched pairs."""

    if baseline_only < 0 or treatment_only < 0:
        raise ValueError("discordant counts cannot be negative")
    discordant = baseline_only + treatment_only
    if discordant == 0:
        return 1.0
    smaller = min(baseline_only, treatment_only)
    lower_tail = sum(comb(discordant, index) for index in range(smaller + 1))
    probability = lower_tail / (2**discordant)
    return min(1.0, 2.0 * probability)
