import pytest

from llm_redteam.model_inventory import (
    OpenWebUIOllamaInventory,
    validate_local_only_model_selection,
)
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.reference_artifact_provenance import (
    LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
    MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
    build_reference_execution_provenance,
)
from llm_redteam.reference_artifact_qualification import (
    OllamaArtifactContractSet,
    qualify_admitted_ollama_artifacts,
)
from llm_redteam.reference_evaluation import ReferenceEvaluationStage


def _fixture():
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(
        {
            "data": [
                {
                    "id": "red",
                    "owned_by": "ollama",
                    "ollama": {
                        "digest": "a" * 64,
                        "size": 100,
                        "details": {},
                        "capabilities": ["completion", "thinking"],
                    },
                },
                {
                    "id": "blue",
                    "owned_by": "ollama",
                    "ollama": {
                        "digest": "b" * 64,
                        "size": 200,
                        "details": {},
                        "capabilities": ["completion"],
                    },
                },
            ]
        }
    )
    models = ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "red",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "red",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
            },
        }
    )
    admission = validate_local_only_model_selection(
        models=models,
        inventory=inventory,
        blue_model_id="blue",
        blue_endpoint="http://127.0.0.1:11434",
    )
    contracts = OllamaArtifactContractSet(
        contracts=(
            OllamaArtifactContract(model_id="red", expected_manifest_digest="a" * 64),
            OllamaArtifactContract(model_id="blue", expected_manifest_digest="b" * 64),
        )
    )
    qualification = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=contracts,
        tags_snapshot={
            "models": [
                {"name": "red", "digest": "a" * 64, "size": 100, "details": {}},
                {"name": "blue", "digest": "b" * 64, "size": 200, "details": {}},
            ]
        },
    )
    return admission, qualification


def test_smoke_requires_only_local_admission_provenance() -> None:
    admission, _ = _fixture()

    descriptors = build_reference_execution_provenance(
        stage=ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
        admission=admission,
    )

    assert tuple(item.kind for item in descriptors) == (LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,)


def test_policy_qualification_fails_without_exact_artifact_proof() -> None:
    admission, _ = _fixture()

    with pytest.raises(ValueError, match="requires exact local model artifact qualification"):
        build_reference_execution_provenance(
            stage=ReferenceEvaluationStage.POLICY_QUALIFICATION,
            admission=admission,
        )


def test_policy_qualification_emits_both_provenance_descriptors() -> None:
    admission, qualification = _fixture()

    descriptors = build_reference_execution_provenance(
        stage=ReferenceEvaluationStage.POLICY_QUALIFICATION,
        admission=admission,
        artifact_qualification=qualification,
    )

    assert tuple(item.kind for item in descriptors) == (
        LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
        MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
    )


def test_artifact_proof_from_different_admission_is_rejected() -> None:
    admission, qualification = _fixture()
    tampered = qualification.model_copy(
        update={"local_admission_proof_sha256": "f" * 64}
    )

    with pytest.raises(ValueError, match="not bound to this local admission proof"):
        build_reference_execution_provenance(
            stage=ReferenceEvaluationStage.POLICY_QUALIFICATION,
            admission=admission,
            artifact_qualification=tampered,
        )
