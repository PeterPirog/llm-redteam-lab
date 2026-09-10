from pathlib import Path

from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.reference_evaluation import (
    ReferenceEvaluationStage,
    build_reference_evaluation_manifest,
    load_reference_evaluation_spec,
    preflight_reference_evaluation,
)
from llm_redteam.runtime_config import load_budget_config

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "config" / "reference-evaluation-v1.yaml"
BUDGETS = ROOT / "config" / "budgets.yaml"
DISCOVERY = ROOT / "corpus" / "native" / "multiturn" / "reference-discovery-v1.yaml"
EVALUATION = ROOT / "corpus" / "native" / "multiturn" / "synthetic-sequences-v1.yaml"


def _cases():
    return tuple((*load_corpus_file(DISCOVERY).cases, *load_corpus_file(EVALUATION).cases))


def _target(provider: str = "ollama") -> TargetIdentity:
    return TargetIdentity(
        id="reference-local-target",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="operator-selected-local-model",
        provider=provider,
        runtime="local-reference-runtime",
        model_digest="sha256:synthetic-reference",
        configuration_hash="reference-config-hash-v1",
        capabilities=frozenset({"text", "reasoning"}),
    )


def test_reference_spec_declares_disjoint_discovery_and_evaluation_partitions() -> None:
    spec = load_reference_evaluation_spec(SPEC)

    assert set(spec.discovery_case_ids).isdisjoint(spec.evaluation_case_ids)
    assert spec.baseline_policy.value == "mechanism"
    assert spec.treatment_policy.value == "portfolio"
    assert spec.inference_scope.value == "FIXED_CORPUS"


def test_reference_preflight_builds_non_promoting_smoke_and_qualified_size_stage() -> None:
    preflight = preflight_reference_evaluation(
        spec=load_reference_evaluation_spec(SPEC),
        cases=_cases(),
        budgets=load_budget_config(BUDGETS),
        target=_target(),
    )

    assert preflight.ready is True
    assert preflight.issues == ()
    assert preflight.target_configuration_hash == "reference-config-hash-v1"
    assert preflight.smoke.stage == ReferenceEvaluationStage.INSTRUMENTATION_SMOKE
    assert preflight.smoke.pair_count == 6
    assert preflight.smoke.total_trials_across_arms == 12
    assert preflight.smoke.may_issue_policy_qualification is False
    assert preflight.qualification.stage == ReferenceEvaluationStage.POLICY_QUALIFICATION
    assert preflight.qualification.pair_count == 21
    assert preflight.qualification.total_trials_across_arms == 42
    assert preflight.qualification.may_issue_policy_qualification is True


def test_reference_manifest_is_hash_bound_and_content_disjoint() -> None:
    manifest = build_reference_evaluation_manifest(
        spec=load_reference_evaluation_spec(SPEC),
        cases=_cases(),
        corpus_snapshot_hash="a" * 64,
    )

    discovery_hashes = {item.content_hash for item in manifest.discovery_cases}
    evaluation_hashes = {item.content_hash for item in manifest.evaluation_cases}
    assert discovery_hashes.isdisjoint(evaluation_hashes)
    assert manifest.red_can_access_evaluation_content is False
    assert manifest.split_strategy == "reference-v1-predeclared-disjoint-native-cases"
    assert len(manifest.discovery_cases) == 3
    assert len(manifest.evaluation_cases) == 3


def test_reference_preflight_fails_closed_on_wrong_target_provider() -> None:
    preflight = preflight_reference_evaluation(
        spec=load_reference_evaluation_spec(SPEC),
        cases=_cases(),
        budgets=load_budget_config(BUDGETS),
        target=_target(provider="openai-compatible-remote"),
    )

    assert preflight.ready is False
    assert any("target provider" in issue for issue in preflight.issues)


def test_reference_preflight_fails_when_qualification_has_too_few_pairs() -> None:
    spec = load_reference_evaluation_spec(SPEC).model_copy(
        update={"qualification_replicates": 6}
    )
    preflight = preflight_reference_evaluation(
        spec=spec,
        cases=_cases(),
        budgets=load_budget_config(BUDGETS),
        target=_target(),
    )

    assert preflight.qualification.pair_count == 18
    assert preflight.ready is False
    assert any("pair count" in issue for issue in preflight.issues)
