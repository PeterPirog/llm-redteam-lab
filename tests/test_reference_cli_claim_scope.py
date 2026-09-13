from types import SimpleNamespace

import llm_redteam.cli as cli_module
from llm_redteam.campaigns.lifecycle import METRIC_DEFINITION_VERSION
from llm_redteam.inference_contract import InferenceScope
from llm_redteam.reference_evaluation import ReferenceEvaluationStage


def _rate(value: float) -> SimpleNamespace:
    return SimpleNamespace(value=value)


def _campaign(*, attack: float, model: float, system: float) -> SimpleNamespace:
    return SimpleNamespace(
        attack_success_rate=_rate(attack),
        model_compromise_rate=_rate(model),
        system_compromise_rate=_rate(system),
    )


def test_reference_payload_labels_fixed_corpus_claim_scope() -> None:
    report = SimpleNamespace(
        contract=SimpleNamespace(
            experiment_id="synthetic-reference",
            target_snapshot_id="target-snapshot",
        ),
        pair_count=4,
        baseline=SimpleNamespace(campaign=_campaign(attack=0.25, model=0.25, system=0.0)),
        treatment=SimpleNamespace(campaign=_campaign(attack=0.5, model=0.5, system=0.0)),
        objective_violation_rate_delta=0.25,
        exact_mcnemar_p_value=0.5,
        discordant_pairs=2,
        mean_target_interaction_delta=1.0,
        mean_output_token_delta=4.0,
    )
    result = SimpleNamespace(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        report=report,
        manifest=SimpleNamespace(content_hash="a" * 64),
        qualification=None,
    )

    payload = cli_module._reference_result_payload(result)

    claim = payload["measurement_claim"]
    assert isinstance(claim, dict)
    assert claim["inference_scope"] == InferenceScope.FIXED_CORPUS.value
    assert claim["generalized_claim_supported"] is False
    assert claim["metric_definition_version"] == METRIC_DEFINITION_VERSION
    assert claim["statistical_unit"] == "case_replicate_pair"
    assert "exact held-out evaluation manifest" in str(claim["interpretation"])


def test_human_reference_output_surfaces_claim_limit(capsys) -> None:
    payload = {
        "stage": "INSTRUMENTATION_SMOKE",
        "experiment_id": "synthetic-reference",
        "pair_count": 4,
        "measurement_claim": {
            "inference_scope": InferenceScope.FIXED_CORPUS.value,
            "generalized_claim_supported": False,
        },
        "paired": {
            "objective_violation_rate_delta": 0.25,
            "exact_mcnemar_p_value": 0.5,
        },
        "qualification": None,
    }

    cli_module._print_reference_result(payload)

    output = capsys.readouterr().out
    assert "FIXED_CORPUS" in output
    assert "not supported" in output
