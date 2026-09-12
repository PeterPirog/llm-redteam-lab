"""Predeclared multi-attacker discovery estimands and overlap diagnostics.

A pool of attacker models can discover more vulnerabilities than one attacker, but
'pick the best result after the fact' is not a valid single-trial ASR estimate. This
module keeps those concepts separate. Every bounded conversation remains one security
trial. A fixed attacker pool is summarized both per attacker and as a predeclared
case/replicate opportunity in which all attacker variants receive the same opportunity.

Finding diversity is based on evidence-backed finding fingerprints supplied by the
minimization/forensics pipeline. Raw prompt hashes are deliberately not treated as
unique vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from pydantic import Field, model_validator

from ..agent_actions import canonical_json_hash
from ..domain import CompromiseOutcome, ExecutionResult, StrictModel
from ..evaluation_protocol import CampaignPurpose
from ..metrics import CampaignMetrics, RateEstimate, summarize_campaign, wilson_rate

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AttackerVariant(StrictModel):
    """Stable identity of one predeclared Red attacker configuration."""

    id: str = Field(min_length=1)
    planner_fingerprint: str = Field(pattern=_HASH_PATTERN)
    mutator_fingerprint: str = Field(pattern=_HASH_PATTERN)
    description: str = ""

    @property
    def fingerprint(self) -> str:
        return canonical_json_hash(
            {
                "id": self.id,
                "planner_fingerprint": self.planner_fingerprint,
                "mutator_fingerprint": self.mutator_fingerprint,
            }
        )


class AttackerPoolContract(StrictModel):
    """Fixed full-cross allocation for one multi-attacker experiment.

    Every variant must execute every declared ``(case_id, replicate)`` opportunity.
    This makes attacker comparisons and the pool opportunity estimand auditable instead
    of allowing adaptive post-hoc allocation to favorable scenarios.
    """

    version: int = Field(ge=1, default=1)
    experiment_id: str = Field(min_length=1)
    purpose: CampaignPurpose
    target_snapshot_id: str = Field(min_length=1)
    scope_manifest_hash: str = Field(pattern=_HASH_PATTERN)
    budget_fingerprint: str = Field(pattern=_HASH_PATTERN)
    metric_definition_version: str = Field(min_length=1, default="attacker-pool-v1")
    case_ids: tuple[str, ...] = Field(min_length=1)
    replicates_per_case: int = Field(gt=0)
    variants: tuple[AttackerVariant, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> AttackerPoolContract:
        if len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError("attacker pool contract requires unique case_ids")
        variant_ids = [variant.id for variant in self.variants]
        if len(set(variant_ids)) != len(variant_ids):
            raise ValueError("attacker pool contract requires unique variant IDs")
        variant_fingerprints = [variant.fingerprint for variant in self.variants]
        if len(set(variant_fingerprints)) != len(variant_fingerprints):
            raise ValueError("attacker pool variants must be distinct configurations")
        return self

    @property
    def expected_opportunities(self) -> tuple[tuple[str, int], ...]:
        return tuple(
            (case_id, replicate)
            for case_id in sorted(self.case_ids)
            for replicate in range(self.replicates_per_case)
        )

    @property
    def contract_fingerprint(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class AttackerPoolObservation(StrictModel):
    """One bounded conversation executed by one attacker variant."""

    variant_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    replicate: int = Field(ge=0)
    execution: ExecutionResult
    finding_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN)
    target_interactions: int = Field(ge=0)
    planner_calls: int = Field(ge=0)
    mutator_calls: int = Field(ge=0)
    planner_output_tokens: int = Field(ge=0)
    mutator_output_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def execution_and_finding_are_consistent(self) -> AttackerPoolObservation:
        if self.execution.attack_id != self.case_id:
            raise ValueError("attacker-pool case_id does not match execution attack_id")
        if self.execution.objective_violated is True and self.finding_fingerprint is None:
            raise ValueError(
                "successful attacker-pool observations require an evidence-backed "
                "finding_fingerprint"
            )
        if self.execution.objective_violated is not True and self.finding_fingerprint is not None:
            raise ValueError("only objective-violating observations may carry finding_fingerprint")
        return self

    @property
    def opportunity_key(self) -> tuple[str, int]:
        return self.case_id, self.replicate

    @property
    def model_calls(self) -> int:
        return self.planner_calls + self.mutator_calls

    @property
    def output_tokens(self) -> int:
        return self.planner_output_tokens + self.mutator_output_tokens


@dataclass(frozen=True, slots=True)
class AttackerVariantDiscoveryStats:
    variant_id: str
    campaign: CampaignMetrics
    successful_trials: int
    distinct_findings: int
    exclusive_findings: int
    target_interactions: int
    model_calls: int
    output_tokens: int
    distinct_findings_per_100_model_calls: float | None
    exclusive_findings_per_100_model_calls: float | None


@dataclass(frozen=True, slots=True)
class AttackerPairOverlap:
    left_variant_id: str
    right_variant_id: str
    shared_findings: int
    union_findings: int
    jaccard: float | None


@dataclass(frozen=True, slots=True)
class AttackerPoolDiscoveryReport:
    """Fixed-pool discovery report; deliberately not a single-attacker ASR."""

    contract: AttackerPoolContract
    opportunity_count: int
    conclusive_opportunities: int
    unresolved_opportunities: int
    portfolio_discovery_success_rate: RateEstimate
    unresolved_opportunity_rate: RateEstimate
    unique_finding_count: int
    variant_stats: tuple[AttackerVariantDiscoveryStats, ...]
    pairwise_overlap: tuple[AttackerPairOverlap, ...]
    comparable_blue_estimate: bool = False


def summarize_attacker_pool(
    observations: tuple[AttackerPoolObservation, ...] | list[AttackerPoolObservation],
    *,
    contract: AttackerPoolContract,
    confidence_level: float = 0.95,
) -> AttackerPoolDiscoveryReport:
    """Summarize a fixed attacker pool without cherry-picking trial outcomes.

    Per-attacker ASR remains the ordinary trial-level security estimate. The pool-level
    rate has a different denominator: each case/replicate is one *discovery opportunity*
    for the entire predeclared pool. It is therefore named explicitly and must not be
    relabeled as ordinary ASR.
    """

    rows = tuple(observations)
    if not rows:
        raise ValueError("attacker pool report requires observations")

    variant_ids = tuple(variant.id for variant in contract.variants)
    expected_opportunities = set(contract.expected_opportunities)
    expected_keys = {
        (variant_id, case_id, replicate)
        for variant_id in variant_ids
        for case_id, replicate in expected_opportunities
    }

    indexed: dict[tuple[str, str, int], AttackerPoolObservation] = {}
    for row in rows:
        key = (row.variant_id, row.case_id, row.replicate)
        if row.variant_id not in variant_ids:
            raise ValueError(f"observation uses undeclared attacker variant: {row.variant_id}")
        if row.opportunity_key not in expected_opportunities:
            raise ValueError(f"observation uses undeclared opportunity: {row.opportunity_key}")
        if key in indexed:
            raise ValueError(f"duplicate attacker-pool observation: {key}")
        indexed[key] = row

    missing = sorted(expected_keys - set(indexed))
    extra = sorted(set(indexed) - expected_keys)
    if missing or extra:
        raise ValueError(
            "attacker pool requires a complete fixed full-cross allocation; "
            f"missing={missing}, extra={extra}"
        )

    finding_sets = {
        variant_id: {
            row.finding_fingerprint
            for row in rows
            if row.variant_id == variant_id and row.finding_fingerprint is not None
        }
        for variant_id in variant_ids
    }
    all_findings = set().union(*finding_sets.values())

    variant_stats = tuple(
        _summarize_variant(
            variant_id,
            tuple(row for row in rows if row.variant_id == variant_id),
            finding_sets,
            confidence_level,
        )
        for variant_id in variant_ids
    )

    overlaps = tuple(
        _pair_overlap(left, right, finding_sets)
        for left, right in combinations(variant_ids, 2)
    )

    pool_successes = 0
    pool_unresolved = 0
    for case_id, replicate in contract.expected_opportunities:
        opportunity = tuple(indexed[(variant_id, case_id, replicate)] for variant_id in variant_ids)
        if any(row.execution.objective_violated is True for row in opportunity):
            pool_successes += 1
            continue
        if any(_execution_unresolved(row.execution) for row in opportunity):
            pool_unresolved += 1

    opportunity_count = len(contract.expected_opportunities)
    conclusive = opportunity_count - pool_unresolved
    return AttackerPoolDiscoveryReport(
        contract=contract,
        opportunity_count=opportunity_count,
        conclusive_opportunities=conclusive,
        unresolved_opportunities=pool_unresolved,
        portfolio_discovery_success_rate=wilson_rate(
            pool_successes,
            conclusive,
            confidence_level,
        ),
        unresolved_opportunity_rate=wilson_rate(
            pool_unresolved,
            opportunity_count,
            confidence_level,
        ),
        unique_finding_count=len(all_findings),
        variant_stats=variant_stats,
        pairwise_overlap=overlaps,
    )


def _summarize_variant(
    variant_id: str,
    rows: tuple[AttackerPoolObservation, ...],
    finding_sets: dict[str, set[str | None]],
    confidence_level: float,
) -> AttackerVariantDiscoveryStats:
    own_findings = {item for item in finding_sets[variant_id] if item is not None}
    other_findings: set[str] = set()
    for other_id, values in finding_sets.items():
        if other_id == variant_id:
            continue
        other_findings.update(item for item in values if item is not None)
    exclusive = own_findings - other_findings
    model_calls = sum(row.model_calls for row in rows)
    return AttackerVariantDiscoveryStats(
        variant_id=variant_id,
        campaign=summarize_campaign(
            (row.execution for row in rows),
            confidence_level,
        ),
        successful_trials=sum(row.execution.objective_violated is True for row in rows),
        distinct_findings=len(own_findings),
        exclusive_findings=len(exclusive),
        target_interactions=sum(row.target_interactions for row in rows),
        model_calls=model_calls,
        output_tokens=sum(row.output_tokens for row in rows),
        distinct_findings_per_100_model_calls=_per_100(len(own_findings), model_calls),
        exclusive_findings_per_100_model_calls=_per_100(len(exclusive), model_calls),
    )


def _pair_overlap(
    left: str,
    right: str,
    finding_sets: dict[str, set[str | None]],
) -> AttackerPairOverlap:
    left_set = {item for item in finding_sets[left] if item is not None}
    right_set = {item for item in finding_sets[right] if item is not None}
    union = left_set | right_set
    intersection = left_set & right_set
    return AttackerPairOverlap(
        left_variant_id=left,
        right_variant_id=right,
        shared_findings=len(intersection),
        union_findings=len(union),
        jaccard=(len(intersection) / len(union)) if union else None,
    )


def _execution_unresolved(execution: ExecutionResult) -> bool:
    return execution.outcome in {
        CompromiseOutcome.PARTIAL,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.ERROR,
    }


def _per_100(count: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return 100.0 * count / denominator
