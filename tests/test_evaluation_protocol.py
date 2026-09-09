import pytest

from llm_redteam.domain import (
    AttackCase,
    AttackTier,
    CompromiseOutcome,
    ExecutionResult,
    GradingSpec,
    PayloadSpec,
    SecurityObjective,
    SourceMode,
    SourceRef,
    TargetClass,
    TargetMode,
)
from llm_redteam.evaluation_protocol import (
    CampaignPurpose,
    MeasurementProtocol,
    discovery_protocol,
    held_out_evaluation_protocol,
    summarize_discovery,
    summarize_evaluation,
)
from llm_redteam.evaluation_sets import build_held_out_evaluation_manifest

CORPUS_HASH = "a" * 64


def _case(case_id: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description=f"Held-out fixture for {case_id}.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test-suite"),
        security_objective=SecurityObjective(
            invariant="Synthetic policy remains intact.",
            expected_safe_behavior="Refuse the protected synthetic objective.",
            forbidden_effect="Protected synthetic objective is fulfilled.",
        ),
        payload=PayloadSpec(text=f"payload-{case_id}"),
        grading=GradingSpec(preferred=["semantic"], detectors=["synthetic-policy"]),
    )


def _manifest(*evaluation_ids: str):
    return build_held_out_evaluation_manifest(
        manifest_id="heldout-eval-v1",
        discovery_cases=(_case("DISC-001"),),
        evaluation_cases=tuple(_case(case_id) for case_id in evaluation_ids),
        corpus_snapshot_hash=CORPUS_HASH,
        split_strategy="explicit-test-split",
    )


def _execution(
    index: int,
    outcome: CompromiseOutcome,
    *,
    attack_id: str | None = None,
) -> ExecutionResult:
    compromised = outcome == CompromiseOutcome.MODEL_COMPROMISE
    if outcome == CompromiseOutcome.ERROR:
        return ExecutionResult(
            execution_id=f"exec-{index}",
            attack_id=attack_id or f"attack-{index}",
            target_id="target",
            outcome=outcome,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
            error_kind="synthetic_error",
        )
    if outcome in {CompromiseOutcome.INCONCLUSIVE, CompromiseOutcome.PARTIAL}:
        return ExecutionResult(
            execution_id=f"exec-{index}",
            attack_id=attack_id or f"attack-{index}",
            target_id="target",
            outcome=outcome,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=0.5,
        )
    return ExecutionResult(
        execution_id=f"exec-{index}",
        attack_id=attack_id or f"attack-{index}",
        target_id="target",
        outcome=outcome,
        objective_violated=compromised,
        model_compromise=compromised,
        system_compromise=False,
        confidence=1.0,
    )


def test_discovery_reports_observed_yield_without_claiming_comparable_blue_asr() -> None:
    rows = (
        _execution(1, CompromiseOutcome.PASS),
        _execution(2, CompromiseOutcome.MODEL_COMPROMISE),
        _execution(3, CompromiseOutcome.ERROR),
    )

    metrics = summarize_discovery(rows)

    assert metrics.total_executions == 3
    assert metrics.conclusive_executions == 2
    assert metrics.objective_violations_observed == 1
    assert metrics.observed_violation_rate.value == 0.5
    assert metrics.unresolved_rate.value == pytest.approx(1 / 3)
    assert metrics.comparable_blue_estimate is False


def test_evaluation_protocol_rejects_learning_from_same_campaign() -> None:
    with pytest.raises(ValueError, match="cannot learn"):
        MeasurementProtocol(
            purpose=CampaignPurpose.EVALUATION,
            attack_policy_frozen_across_trials=True,
            learns_from_current_campaign_outcomes=True,
            held_out_cases=True,
            target_snapshot_pinned=True,
        )


def test_evaluation_protocol_requires_frozen_held_out_pinned_conditions() -> None:
    invalid = (
        {
            "attack_policy_frozen_across_trials": False,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": True,
            "target_snapshot_pinned": True,
        },
        {
            "attack_policy_frozen_across_trials": True,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": False,
            "target_snapshot_pinned": True,
        },
        {
            "attack_policy_frozen_across_trials": True,
            "learns_from_current_campaign_outcomes": False,
            "held_out_cases": True,
            "target_snapshot_pinned": False,
        },
    )
    for values in invalid:
        with pytest.raises(ValueError):
            MeasurementProtocol(purpose=CampaignPurpose.EVALUATION, **values)


def test_held_out_evaluation_reports_comparable_blue_metrics_only_after_quality_gate() -> None:
    rows = (
        _execution(1, CompromiseOutcome.PASS, attack_id="EVAL-001"),
        _execution(2, CompromiseOutcome.MODEL_COMPROMISE, attack_id="EVAL-002"),
    )
    protocol = held_out_evaluation_protocol()
    manifest = _manifest("EVAL-001", "EVAL-002")

    report = summarize_evaluation(rows, protocol, manifest)

    assert report.comparable_blue_estimate is True
    assert report.protocol.purpose == CampaignPurpose.EVALUATION
    assert report.campaign.attack_success_rate.value == 0.5
    assert report.campaign.attack_success_rate.trials == 2
    assert report.evaluation_manifest_hash == manifest.content_hash
    assert report.evaluation_case_count == 2
    assert report.replicates_per_case == 1


def test_evaluation_rejects_missing_or_extra_cases() -> None:
    protocol = held_out_evaluation_protocol()
    manifest = _manifest("EVAL-001", "EVAL-002")

    with pytest.raises(ValueError, match="were not executed"):
        summarize_evaluation(
            (_execution(1, CompromiseOutcome.PASS, attack_id="EVAL-001"),),
            protocol,
            manifest,
        )

    with pytest.raises(ValueError, match="outside held-out"):
        summarize_evaluation(
            (
                _execution(1, CompromiseOutcome.PASS, attack_id="EVAL-001"),
                _execution(2, CompromiseOutcome.PASS, attack_id="EVAL-002"),
                _execution(3, CompromiseOutcome.PASS, attack_id="DISC-001"),
            ),
            protocol,
            manifest,
        )


def test_evaluation_rejects_unbalanced_replicates() -> None:
    protocol = held_out_evaluation_protocol()
    manifest = _manifest("EVAL-001", "EVAL-002")

    with pytest.raises(ValueError, match="balanced replicates"):
        summarize_evaluation(
            (
                _execution(1, CompromiseOutcome.PASS, attack_id="EVAL-001"),
                _execution(2, CompromiseOutcome.PASS, attack_id="EVAL-001"),
                _execution(3, CompromiseOutcome.PASS, attack_id="EVAL-002"),
            ),
            protocol,
            manifest,
        )


def test_evaluation_rejects_unresolved_trials_instead_of_dropping_them() -> None:
    protocol = held_out_evaluation_protocol()
    manifest = _manifest("EVAL-001", "EVAL-002")

    with pytest.raises(ValueError, match="conclusive executions"):
        summarize_evaluation(
            (
                _execution(1, CompromiseOutcome.PASS, attack_id="EVAL-001"),
                _execution(2, CompromiseOutcome.ERROR, attack_id="EVAL-002"),
            ),
            protocol,
            manifest,
        )


def test_discovery_protocol_cannot_be_used_for_comparative_blue_metrics() -> None:
    with pytest.raises(ValueError, match="EVALUATION"):
        summarize_evaluation(
            (_execution(1, CompromiseOutcome.MODEL_COMPROMISE, attack_id="EVAL-001"),),
            discovery_protocol(),
            _manifest("EVAL-001"),
        )
