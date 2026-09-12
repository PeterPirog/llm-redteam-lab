import pytest

from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.red.attacker_pool import (
    AttackerPoolContract,
    AttackerPoolObservation,
    AttackerVariant,
    summarize_attacker_pool,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64
_HASH_D = "d" * 64
_FINDING_X = "1" * 64
_FINDING_Y = "2" * 64


def _variant(identifier: str, planner: str, mutator: str) -> AttackerVariant:
    return AttackerVariant(
        id=identifier,
        planner_fingerprint=planner,
        mutator_fingerprint=mutator,
    )


def _contract(**updates: object) -> AttackerPoolContract:
    values: dict[str, object] = {
        "experiment_id": "multi-attacker-smoke-v1",
        "purpose": CampaignPurpose.DISCOVERY,
        "target_snapshot_id": "target-snapshot-1",
        "scope_manifest_hash": "e" * 64,
        "budget_fingerprint": "f" * 64,
        "case_ids": ("case-1", "case-2"),
        "replicates_per_case": 1,
        "variants": (
            _variant("attacker-a", _HASH_A, _HASH_B),
            _variant("attacker-b", _HASH_C, _HASH_D),
        ),
    }
    values.update(updates)
    return AttackerPoolContract.model_validate(values)


def _execution(
    case_id: str,
    suffix: str,
    *,
    outcome: CompromiseOutcome,
) -> ExecutionResult:
    if outcome == CompromiseOutcome.PASS:
        objective = False
        model = False
        system = False
        error_kind = None
    elif outcome == CompromiseOutcome.MODEL_COMPROMISE:
        objective = True
        model = True
        system = False
        error_kind = None
    elif outcome == CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE:
        objective = True
        model = True
        system = True
        error_kind = None
    elif outcome == CompromiseOutcome.INCONCLUSIVE:
        objective = None
        model = False
        system = False
        error_kind = None
    elif outcome == CompromiseOutcome.ERROR:
        objective = None
        model = False
        system = False
        error_kind = "synthetic:error"
    else:
        raise AssertionError(f"unsupported test outcome: {outcome}")
    return ExecutionResult(
        execution_id=f"exec-{case_id}-{suffix}",
        attack_id=case_id,
        target_id="blue-target",
        outcome=outcome,
        objective_violated=objective,
        model_compromise=model,
        system_compromise=system,
        confidence=1.0,
        error_kind=error_kind,
    )


def _observation(
    variant_id: str,
    case_id: str,
    *,
    outcome: CompromiseOutcome,
    finding: str | None = None,
    planner_calls: int = 2,
    mutator_calls: int = 1,
) -> AttackerPoolObservation:
    return AttackerPoolObservation(
        variant_id=variant_id,
        case_id=case_id,
        replicate=0,
        execution=_execution(case_id, variant_id, outcome=outcome),
        finding_fingerprint=finding,
        target_interactions=3,
        planner_calls=planner_calls,
        mutator_calls=mutator_calls,
        planner_output_tokens=30,
        mutator_output_tokens=10,
    )


def test_fixed_pool_separates_per_attacker_asr_from_portfolio_discovery_rate() -> None:
    rows = [
        _observation(
            "attacker-a",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_X,
        ),
        _observation("attacker-a", "case-2", outcome=CompromiseOutcome.PASS),
        _observation(
            "attacker-b",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_X,
        ),
        _observation(
            "attacker-b",
            "case-2",
            outcome=CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE,
            finding=_FINDING_Y,
        ),
    ]

    report = summarize_attacker_pool(rows, contract=_contract())

    stats = {row.variant_id: row for row in report.variant_stats}
    assert stats["attacker-a"].campaign.attack_success_rate.value == 0.5
    assert stats["attacker-b"].campaign.attack_success_rate.value == 1.0
    assert report.portfolio_discovery_success_rate.value == 1.0
    assert report.opportunity_count == 2
    assert report.conclusive_opportunities == 2
    assert report.unique_finding_count == 2
    assert report.comparable_blue_estimate is False


def test_unique_finding_contribution_and_pairwise_overlap_are_auditable() -> None:
    rows = [
        _observation(
            "attacker-a",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_X,
        ),
        _observation("attacker-a", "case-2", outcome=CompromiseOutcome.PASS),
        _observation(
            "attacker-b",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_X,
        ),
        _observation(
            "attacker-b",
            "case-2",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_Y,
        ),
    ]

    report = summarize_attacker_pool(rows, contract=_contract())
    stats = {row.variant_id: row for row in report.variant_stats}

    assert stats["attacker-a"].distinct_findings == 1
    assert stats["attacker-a"].exclusive_findings == 0
    assert stats["attacker-b"].distinct_findings == 2
    assert stats["attacker-b"].exclusive_findings == 1
    assert stats["attacker-a"].model_calls == 6
    assert stats["attacker-a"].distinct_findings_per_100_model_calls == pytest.approx(
        100 / 6
    )
    assert stats["attacker-b"].exclusive_findings_per_100_model_calls == pytest.approx(
        100 / 6
    )

    overlap = report.pairwise_overlap[0]
    assert overlap.shared_findings == 1
    assert overlap.union_findings == 2
    assert overlap.jaccard == 0.5


def test_unresolved_pool_opportunity_is_not_silently_counted_as_defense() -> None:
    rows = [
        _observation("attacker-a", "case-1", outcome=CompromiseOutcome.PASS),
        _observation("attacker-a", "case-2", outcome=CompromiseOutcome.INCONCLUSIVE),
        _observation("attacker-b", "case-1", outcome=CompromiseOutcome.PASS),
        _observation("attacker-b", "case-2", outcome=CompromiseOutcome.PASS),
    ]

    report = summarize_attacker_pool(rows, contract=_contract())

    assert report.opportunity_count == 2
    assert report.conclusive_opportunities == 1
    assert report.unresolved_opportunities == 1
    assert report.portfolio_discovery_success_rate.value == 0.0
    assert report.unresolved_opportunity_rate.value == 0.5


def test_success_dominates_unresolved_for_predeclared_pool_opportunity() -> None:
    rows = [
        _observation("attacker-a", "case-1", outcome=CompromiseOutcome.INCONCLUSIVE),
        _observation("attacker-a", "case-2", outcome=CompromiseOutcome.PASS),
        _observation(
            "attacker-b",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            finding=_FINDING_X,
        ),
        _observation("attacker-b", "case-2", outcome=CompromiseOutcome.PASS),
    ]

    report = summarize_attacker_pool(rows, contract=_contract())

    assert report.conclusive_opportunities == 2
    assert report.unresolved_opportunities == 0
    assert report.portfolio_discovery_success_rate.value == 0.5


def test_success_requires_evidence_backed_finding_fingerprint() -> None:
    with pytest.raises(ValueError, match="finding_fingerprint"):
        _observation(
            "attacker-a",
            "case-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
        )

    with pytest.raises(ValueError, match="only objective-violating"):
        _observation(
            "attacker-a",
            "case-1",
            outcome=CompromiseOutcome.PASS,
            finding=_FINDING_X,
        )


def test_pool_requires_complete_full_cross_allocation() -> None:
    rows = [
        _observation("attacker-a", "case-1", outcome=CompromiseOutcome.PASS),
        _observation("attacker-a", "case-2", outcome=CompromiseOutcome.PASS),
        _observation("attacker-b", "case-1", outcome=CompromiseOutcome.PASS),
    ]

    with pytest.raises(ValueError, match="complete fixed full-cross"):
        summarize_attacker_pool(rows, contract=_contract())


def test_pool_contract_rejects_duplicate_variants_or_case_ids() -> None:
    with pytest.raises(ValueError, match="unique case_ids"):
        _contract(case_ids=("case-1", "case-1"))

    duplicate_id = (
        _variant("same", _HASH_A, _HASH_B),
        _variant("same", _HASH_C, _HASH_D),
    )
    with pytest.raises(ValueError, match="unique variant IDs"):
        _contract(variants=duplicate_id)

    same_configuration = (
        _variant("attacker-a", _HASH_A, _HASH_B),
        _variant("attacker-a", _HASH_A, _HASH_B),
    )
    with pytest.raises(ValueError):
        _contract(variants=same_configuration)


def test_contract_fingerprint_binds_attacker_set_and_allocation() -> None:
    base = _contract()
    changed_variants = _contract(
        variants=(
            _variant("attacker-a", _HASH_A, _HASH_B),
            _variant("attacker-c", _HASH_C, "9" * 64),
        )
    )
    changed_replicates = _contract(replicates_per_case=2)

    assert base.contract_fingerprint != changed_variants.contract_fingerprint
    assert base.contract_fingerprint != changed_replicates.contract_fingerprint
