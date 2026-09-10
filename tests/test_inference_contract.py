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
    held_out_evaluation_protocol,
    summarize_evaluation,
)
from llm_redteam.evaluation_sets import build_held_out_evaluation_manifest
from llm_redteam.inference_contract import (
    METRIC_CONTRACT_VERSION,
    InferenceScope,
    SecurityEstimand,
)


def _case(case_id: str) -> AttackCase:
    return AttackCase(
        id=case_id,
        name=case_id,
        description="Synthetic fixed-corpus inference fixture.",
        target_classes=[TargetClass.WRITING],
        target_modes=[TargetMode.MODEL],
        attack_family=["multi_turn_escalation"],
        complexity_tier=AttackTier.T3,
        interaction_mode="multi_turn",
        source=SourceRef(mode=SourceMode.NATIVE, name="test-suite"),
        security_objective=SecurityObjective(
            invariant="Synthetic protected objective remains intact.",
            expected_safe_behavior="Do not satisfy the synthetic protected objective.",
            forbidden_effect="Synthetic protected objective is satisfied.",
        ),
        payload=PayloadSpec(text=f"synthetic-{case_id}"),
        grading=GradingSpec(preferred=["deterministic"], detectors=["synthetic"]),
    )


def _manifest():
    return build_held_out_evaluation_manifest(
        manifest_id="inference-contract-v1",
        discovery_cases=(_case("DISC-001"),),
        evaluation_cases=(_case("EVAL-A"), _case("EVAL-B")),
        corpus_snapshot_hash="a" * 64,
        split_strategy="explicit-test-split",
    )


def _execution(index: int, case_id: str, compromised: bool) -> ExecutionResult:
    return ExecutionResult(
        execution_id=f"exec-{index}",
        attack_id=case_id,
        target_id="target",
        outcome=(
            CompromiseOutcome.MODEL_COMPROMISE
            if compromised
            else CompromiseOutcome.PASS
        ),
        objective_violated=compromised,
        model_compromise=compromised,
        system_compromise=False,
        confidence=1.0,
    )


def _balanced_rows() -> tuple[ExecutionResult, ...]:
    return (
        _execution(1, "EVAL-A", True),
        _execution(2, "EVAL-A", True),
        _execution(3, "EVAL-B", False),
        _execution(4, "EVAL-B", False),
    )


def test_evaluation_is_explicitly_fixed_corpus_by_default() -> None:
    report = summarize_evaluation(
        _balanced_rows(),
        held_out_evaluation_protocol(),
        _manifest(),
    )

    contract = report.inference_contract
    assert contract.metric_contract_version == METRIC_CONTRACT_VERSION
    assert contract.scope == InferenceScope.FIXED_CORPUS
    assert contract.statistical_unit == "case_replicate"
    assert contract.aggregation_unit == "evaluation_case"
    assert contract.generalized_claim_supported is False
    assert "exact held-out evaluation manifest" in contract.interpretation


def test_fixed_corpus_contract_exposes_case_heterogeneity() -> None:
    report = summarize_evaluation(
        _balanced_rows(),
        held_out_evaluation_protocol(),
        _manifest(),
    )
    by_metric = {
        item.estimand: item for item in report.inference_contract.fixed_corpus_diagnostics
    }

    asr = by_metric[SecurityEstimand.OBJECTIVE_VIOLATION_RATE]
    assert asr.case_count == 2
    assert asr.replicates_per_case == 2
    assert asr.macro_case_mean == 0.5
    assert asr.min_case_rate == 0.0
    assert asr.max_case_rate == 1.0
    assert asr.between_case_observed_variance == 0.25
    assert [item.rate.value for item in asr.case_estimates] == [1.0, 0.0]

    scr = by_metric[SecurityEstimand.SYSTEM_COMPROMISE_RATE]
    assert scr.macro_case_mean == 0.0
    assert scr.between_case_observed_variance == 0.0


def test_standard_summarizer_rejects_generalized_population_claim() -> None:
    with pytest.raises(ValueError, match="GENERALIZED_POPULATION inference is not implemented"):
        summarize_evaluation(
            _balanced_rows(),
            held_out_evaluation_protocol(),
            _manifest(),
            inference_scope=InferenceScope.GENERALIZED_POPULATION,
        )
