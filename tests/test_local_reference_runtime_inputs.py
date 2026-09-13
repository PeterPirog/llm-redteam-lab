import json
from pathlib import Path

import pytest

from llm_redteam.local_reference_admission import build_local_reference_admission_bundle
from llm_redteam.local_reference_runtime_inputs import (
    load_local_reference_admission_bundle,
    resolve_local_reference_runtime_artifacts,
)
from llm_redteam.model_artifact import ModelArtifactIdentity, ModelArtifactObservation
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.offline_ollama_qualification import (
    OfflineOllamaQualificationReport,
    VerifiedOllamaArtifact,
)


def _identity(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=4096,
        local_artifact=True,
        format="gguf",
        family="synthetic",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def _report(*, blue_char: str = "c") -> OfflineOllamaQualificationReport:
    inventory_sha256 = "f" * 64
    artifacts = []
    for model, char in (
        ("planner:latest", "a"),
        ("mutator:latest", "b"),
        ("blue:latest", blue_char),
    ):
        artifacts.append(
            VerifiedOllamaArtifact(
                model_id=model,
                roles=("operator-metadata",),
                contract_sha256=char * 64,
                observation=ModelArtifactObservation(
                    identity=_identity(model, char),
                    source_kind="ollama:/api/tags",
                    source_response_sha256=inventory_sha256,
                ),
            )
        )
    return OfflineOllamaQualificationReport(
        source="runtime-inputs-test",
        inventory_sha256=inventory_sha256,
        contracts_sha256="e" * 64,
        artifacts=tuple(sorted(artifacts, key=lambda item: item.model_id)),
    )


def _models(*, planner_temperature: float = 0.2) -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": planner_temperature,
                    "max_output_tokens": 128,
                    "fallback": [],
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://localhost:11434/v1/chat/completions",
                    "temperature": 0.0,
                    "max_output_tokens": 96,
                    "fallback": [],
                },
            },
            "blue": {"source": "campaign"},
        }
    )


def _bundle(models: ModelsConfig, report: OfflineOllamaQualificationReport):
    return build_local_reference_admission_bundle(
        models=models,
        report=report,
        blue_model="blue:latest",
    )


def _write_bundle(path: Path, bundle) -> None:
    payload = bundle.model_dump(mode="json")
    payload["bundle_sha256"] = bundle.bundle_sha256
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_persisted_bundle_reloads_with_independently_pinned_hash(tmp_path: Path) -> None:
    models = _models()
    report = _report()
    bundle = _bundle(models, report)
    path = tmp_path / "reference-admission.json"
    _write_bundle(path, bundle)

    loaded = load_local_reference_admission_bundle(
        path,
        expected_bundle_sha256=bundle.bundle_sha256,
    )

    assert loaded == bundle
    assert loaded.bundle_sha256 == bundle.bundle_sha256


def test_modified_bundle_is_rejected_when_stored_hash_is_stale(tmp_path: Path) -> None:
    models = _models()
    report = _report()
    bundle = _bundle(models, report)
    path = tmp_path / "reference-admission.json"
    _write_bundle(path, bundle)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["blue"]["model"] = "other-blue:latest"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="bundle_sha256 does not match content"):
        load_local_reference_admission_bundle(path)


def test_rewritten_bundle_with_new_self_hash_fails_against_pinned_hash(tmp_path: Path) -> None:
    models = _models()
    first_report = _report(blue_char="c")
    second_report = _report(blue_char="d")
    first = _bundle(models, first_report)
    second = _bundle(models, second_report)
    path = tmp_path / "reference-admission.json"
    _write_bundle(path, second)

    with pytest.raises(ValueError, match="does not match pinned bundle hash"):
        load_local_reference_admission_bundle(
            path,
            expected_bundle_sha256=first.bundle_sha256,
        )


def test_runtime_resolver_exposes_exact_provider_neutral_artifacts() -> None:
    models = _models()
    report = _report()
    bundle = _bundle(models, report)

    resolved = resolve_local_reference_runtime_artifacts(
        models=models,
        report=report,
        bundle=bundle,
    )

    assert resolved.bundle_sha256 == bundle.bundle_sha256
    assert resolved.qualification_report_sha256 == report.report_sha256
    assert resolved.red_planner.model_id == "planner:latest"
    assert resolved.red_planner.artifact_digest == "sha256:" + "a" * 64
    assert resolved.red_mutator.model_id == "mutator:latest"
    assert resolved.red_mutator.artifact_digest == "sha256:" + "b" * 64
    assert resolved.blue.model_id == "blue:latest"
    assert resolved.blue.artifact_digest == "sha256:" + "c" * 64
    assert set(resolved.red_artifact_map()) == {
        ("ollama", "planner:latest"),
        ("ollama", "mutator:latest"),
    }
    assert set(resolved.all_artifact_map()) == {
        ("ollama", "planner:latest"),
        ("ollama", "mutator:latest"),
        ("ollama", "blue:latest"),
    }


def test_runtime_resolver_rejects_models_config_drift() -> None:
    original_models = _models(planner_temperature=0.2)
    report = _report()
    bundle = _bundle(original_models, report)

    with pytest.raises(ValueError, match="do not reproduce the persisted"):
        resolve_local_reference_runtime_artifacts(
            models=_models(planner_temperature=0.3),
            report=report,
            bundle=bundle,
        )


def test_runtime_resolver_rejects_report_artifact_drift() -> None:
    models = _models()
    first_report = _report(blue_char="c")
    bundle = _bundle(models, first_report)

    with pytest.raises(ValueError, match="qualification report does not match"):
        resolve_local_reference_runtime_artifacts(
            models=models,
            report=_report(blue_char="d"),
            bundle=bundle,
        )


def test_runtime_resolver_rejects_bundle_with_wrong_inventory_identity() -> None:
    models = _models()
    report = _report()
    bundle = _bundle(models, report)
    tampered = bundle.model_copy(update={"inventory_sha256": "0" * 64})

    with pytest.raises(ValueError, match="inventory hash does not match"):
        resolve_local_reference_runtime_artifacts(
            models=models,
            report=report,
            bundle=tampered,
        )
