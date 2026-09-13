from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from llm_redteam.domain import CampaignBudget, TargetClass, TargetIdentity, TargetMode
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.red.qualification import RedPolicyQualificationPolicy
from llm_redteam.reference_evaluation import ReferenceEvaluationSpec, ReferenceEvaluationStage
from llm_redteam.reference_target_qualification import (
    ArtifactQualifiedReferenceRunResult,
    build_reference_blue_artifact_admission,
    run_artifact_qualified_reference_evaluation_stage,
)
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.artifact_qualified import ArtifactQualifiedTarget
from llm_redteam.targets.base import SessionMode, TargetRequest, TargetResponse


def _spec(*, provider: str = "ollama") -> ReferenceEvaluationSpec:
    return ReferenceEvaluationSpec(
        version=1,
        experiment_id="reference-blue-artifact-v1",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        session_mode=SessionMode.REPLAY,
        required_target_provider=provider,
        discovery_case_ids=("DISC-1",),
        evaluation_case_ids=("EVAL-1",),
        baseline_policy="mechanism",
        treatment_policy="portfolio",
        smoke_replicates=1,
        qualification_replicates=1,
        smoke_budget_profile="reference_test",
        qualification_budget_profile="reference_test",
        qualification_policy=RedPolicyQualificationPolicy(min_pair_count=1),
        require_deterministic_canary_judge=True,
    )


def _base_identity(*, provider: str = "ollama") -> TargetIdentity:
    return TargetIdentity(
        id="qualified-reference-blue",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="blue:latest",
        provider=provider,
        runtime="http://localhost:11434",
        application="direct-model-api",
        application_version="v1",
        configuration_hash="base-reference-blue-v1",
        capabilities=frozenset({"text", "reasoning"}),
    )


def _artifact(*, local: bool = True, digest_char: str = "a") -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id="blue:latest",
        artifact_digest="sha256:" + digest_char * 64,
        artifact_size_bytes=4096,
        local_artifact=local,
        format="gguf",
        family="synthetic-blue",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


class _Target:
    def __init__(self, *, provider: str = "ollama") -> None:
        self._identity = _base_identity(provider=provider)
        self.calls = 0

    @property
    def identity(self) -> TargetIdentity:
        return self._identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        self.calls += 1
        return TargetResponse(text="synthetic")


def _qualified_target(
    *,
    local: bool = True,
    require_local: bool = True,
) -> ArtifactQualifiedTarget:
    return ArtifactQualifiedTarget(
        _Target(),
        _artifact(local=local),
        require_local=require_local,
    )


def _budgets() -> BudgetConfigDocument:
    budget = CampaignBudget(
        max_attacks=1,
        max_generations=1,
        max_turns_per_attack=2,
        max_backtracks_per_attack=0,
        max_branches_per_attack=1,
        max_model_calls=4,
        max_model_calls_by_role={"red_planner": 2, "red_mutator": 2},
        max_total_output_tokens=512,
        max_output_tokens_by_role={"red_planner": 256, "red_mutator": 256},
        max_image_generations=0,
        wall_clock_seconds=60,
        max_non_progress_attempts=2,
    )
    return BudgetConfigDocument(
        version=1,
        default_profile="reference_test",
        profiles={"reference_test": budget},
        policy=RuntimePolicy(),
    )


def _models() -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner-local",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": 0.0,
                    "max_output_tokens": 128,
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": 0.0,
                    "max_output_tokens": 128,
                },
            },
        }
    )


def test_reference_blue_admission_binds_exact_local_artifact() -> None:
    target = _qualified_target()

    admission = build_reference_blue_artifact_admission(spec=_spec(), target=target)

    assert admission.experiment_id == "reference-blue-artifact-v1"
    assert admission.target_configuration_hash == target.identity.configuration_hash
    assert admission.model_artifact_digest == "sha256:" + "a" * 64
    assert (
        admission.model_artifact_identity_sha256
        == target.binding.artifact_identity_sha256
    )
    assert admission.model_artifact_binding_sha256 == target.binding.binding_sha256
    assert admission.local_artifact is True
    assert admission.require_local is True
    assert len(admission.admission_sha256) == 64


def test_reference_blue_admission_rejects_unqualified_target() -> None:
    ordinary = _Target()

    with pytest.raises(TypeError, match="artifact-qualified Blue target"):
        build_reference_blue_artifact_admission(  # type: ignore[arg-type]
            spec=_spec(),
            target=ordinary,
        )

    assert ordinary.calls == 0


def test_reference_blue_admission_rejects_explicit_remote_artifact_opt_in() -> None:
    target = _qualified_target(local=False, require_local=False)

    with pytest.raises(ValueError, match="verified local Blue artifact"):
        build_reference_blue_artifact_admission(spec=_spec(), target=target)


def test_reference_blue_admission_rejects_reference_provider_mismatch() -> None:
    target = _qualified_target()

    with pytest.raises(ValueError, match="provider"):
        build_reference_blue_artifact_admission(
            spec=_spec(provider="other-provider"),
            target=target,
        )


def test_mutable_blue_tag_weight_change_changes_reference_admission_identity() -> None:
    first = ArtifactQualifiedTarget(_Target(), _artifact(digest_char="a"))
    second = ArtifactQualifiedTarget(_Target(), _artifact(digest_char="b"))

    first_admission = build_reference_blue_artifact_admission(spec=_spec(), target=first)
    second_admission = build_reference_blue_artifact_admission(spec=_spec(), target=second)

    assert first.identity.model == second.identity.model == "blue:latest"
    assert first_admission.model_artifact_digest != second_admission.model_artifact_digest
    assert (
        first_admission.target_configuration_hash
        != second_admission.target_configuration_hash
    )
    assert first_admission.admission_sha256 != second_admission.admission_sha256


def test_reference_wrapper_admits_blue_before_delegating_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import llm_redteam.reference_target_qualification as module

    target = _qualified_target()
    delegated = []

    async def fake_runner(**kwargs):
        delegated.append(kwargs)
        return SimpleNamespace(
            preflight=SimpleNamespace(
                target_configuration_hash=target.identity.configuration_hash,
            )
        )

    monkeypatch.setattr(module, "run_reference_evaluation_stage", fake_runner)

    result = asyncio.run(
        run_artifact_qualified_reference_evaluation_stage(
            stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
            spec=_spec(),
            cases=(),
            budgets=_budgets(),
            models=_models(),
            target=target,
            judge=object(),  # type: ignore[arg-type]
            judge_policy_descriptor={"kind": "deterministic"},
            red_model_client=object(),  # type: ignore[arg-type]
            repository=ExperimentRepository.from_url("sqlite+pysqlite:///:memory:"),
            run_id="offline-admission",
        )
    )

    assert isinstance(result, ArtifactQualifiedReferenceRunResult)
    assert (
        result.blue_admission.target_configuration_hash
        == target.identity.configuration_hash
    )
    assert len(delegated) == 1
    assert delegated[0]["target"] is target
    assert target.base_identity.configuration_hash == "base-reference-blue-v1"


def test_reference_wrapper_rejects_runner_target_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import llm_redteam.reference_target_qualification as module

    target = _qualified_target()

    async def fake_runner(**kwargs):
        return SimpleNamespace(
            preflight=SimpleNamespace(target_configuration_hash="f" * 64)
        )

    monkeypatch.setattr(module, "run_reference_evaluation_stage", fake_runner)

    with pytest.raises(RuntimeError, match="target identity changed"):
        asyncio.run(
            run_artifact_qualified_reference_evaluation_stage(
                stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
                spec=_spec(),
                cases=(),
                budgets=_budgets(),
                models=_models(),
                target=target,
                judge=object(),  # type: ignore[arg-type]
                judge_policy_descriptor={"kind": "deterministic"},
                red_model_client=object(),  # type: ignore[arg-type]
                repository=ExperimentRepository.from_url("sqlite+pysqlite:///:memory:"),
                run_id="drifted-admission",
            )
        )
