import json
from pathlib import Path

import pytest

from llm_redteam.local_reference_admission import (
    LocalReferenceParticipant,
    build_local_reference_admission_bundle,
    load_offline_ollama_qualification_report,
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


def _verified(
    model: str,
    char: str,
    inventory_sha256: str,
    *,
    roles: tuple[str, ...],
) -> VerifiedOllamaArtifact:
    identity = _identity(model, char)
    return VerifiedOllamaArtifact(
        model_id=model,
        roles=roles,
        contract_sha256=char * 64,
        observation=ModelArtifactObservation(
            identity=identity,
            source_kind="ollama:/api/tags",
            source_response_sha256=inventory_sha256,
        ),
    )


def _report(*, blue_char: str = "c") -> OfflineOllamaQualificationReport:
    inventory_sha256 = "f" * 64
    return OfflineOllamaQualificationReport(
        source="synthetic-local-inventory",
        inventory_sha256=inventory_sha256,
        contracts_sha256="e" * 64,
        artifacts=tuple(
            sorted(
                (
                    _verified(
                        "planner:latest",
                        "a",
                        inventory_sha256,
                        roles=("not_authorization_metadata",),
                    ),
                    _verified(
                        "mutator:latest",
                        "b",
                        inventory_sha256,
                        roles=("another_operator_hint",),
                    ),
                    _verified(
                        "blue:latest",
                        blue_char,
                        inventory_sha256,
                        roles=("recommended_model_blue",),
                    ),
                ),
                key=lambda item: item.model_id,
            )
        ),
    )


def _models(
    *,
    planner_temperature: float = 0.2,
    planner_endpoint: str = "http://localhost:11434/v1/chat/completions",
    planner_fallback: tuple[str, ...] = (),
) -> ModelsConfig:
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
                    "endpoint": planner_endpoint,
                    "temperature": planner_temperature,
                    "max_output_tokens": 128,
                    "fallback": list(planner_fallback),
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                    "temperature": 0.0,
                    "max_output_tokens": 96,
                    "fallback": [],
                },
            },
            "blue": {"source": "campaign"},
        }
    )


def _write_report(path: Path, report: OfflineOllamaQualificationReport) -> None:
    payload = report.model_dump(mode="json")
    payload["artifact_set_sha256"] = report.artifact_set_sha256
    payload["report_sha256"] = report.report_sha256
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_persisted_offline_report_reloads_only_when_hashes_match(tmp_path: Path) -> None:
    path = tmp_path / "qualification-report.json"
    report = _report()
    _write_report(path, report)

    loaded = load_offline_ollama_qualification_report(
        path,
        expected_report_sha256=report.report_sha256,
    )

    assert loaded == report
    assert loaded.report_sha256 == report.report_sha256
    assert loaded.artifact_set_sha256 == report.artifact_set_sha256


def test_persisted_report_rejects_wrong_independently_pinned_hash(tmp_path: Path) -> None:
    path = tmp_path / "qualification-report.json"
    report = _report()
    _write_report(path, report)

    with pytest.raises(ValueError, match="does not match pinned report hash"):
        load_offline_ollama_qualification_report(
            path,
            expected_report_sha256="0" * 64,
        )


def test_modified_persisted_report_is_rejected_before_admission(tmp_path: Path) -> None:
    path = tmp_path / "qualification-report.json"
    report = _report()
    _write_report(path, report)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["artifacts"][0]["observation"]["identity"]["artifact_digest"] = (
        "sha256:" + "d" * 64
    )
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="artifact_set_sha256"):
        load_offline_ollama_qualification_report(path)


def test_persisted_report_rejects_observation_inventory_hash_drift(tmp_path: Path) -> None:
    path = tmp_path / "qualification-report.json"
    report = _report()
    payload = report.model_dump(mode="json")
    payload["artifacts"][0]["observation"]["source_response_sha256"] = "0" * 64
    modified = OfflineOllamaQualificationReport.model_validate(payload)
    _write_report(path, modified)

    with pytest.raises(ValueError, match="observation does not match inventory hash"):
        load_offline_ollama_qualification_report(path)


def test_missing_persisted_hashes_are_not_treated_as_trusted_report(tmp_path: Path) -> None:
    path = tmp_path / "qualification-report.json"
    path.write_text(json.dumps(_report().model_dump(mode="json")), encoding="utf-8")

    with pytest.raises(ValueError, match="must include artifact_set_sha256 and report_sha256"):
        load_offline_ollama_qualification_report(path)


def test_bundle_maps_models_config_to_exact_artifacts_not_role_labels() -> None:
    report = _report()
    bundle = build_local_reference_admission_bundle(
        models=_models(),
        report=report,
        blue_model="blue:latest",
    )

    assert tuple(item.participant for item in bundle.red_roles) == (
        LocalReferenceParticipant.RED_PLANNER,
        LocalReferenceParticipant.RED_MUTATOR,
    )
    by_participant = {item.participant: item for item in bundle.red_roles}
    assert by_participant[LocalReferenceParticipant.RED_PLANNER].model == "planner:latest"
    assert by_participant[LocalReferenceParticipant.RED_MUTATOR].model == "mutator:latest"
    assert by_participant[LocalReferenceParticipant.RED_PLANNER].artifact_digest == (
        "sha256:" + "a" * 64
    )
    assert by_participant[LocalReferenceParticipant.RED_MUTATOR].artifact_digest == (
        "sha256:" + "b" * 64
    )
    assert bundle.blue.model == "blue:latest"
    assert bundle.blue.artifact_digest == "sha256:" + "c" * 64
    assert bundle.qualification_report_sha256 == report.report_sha256
    assert bundle.artifact_set_sha256 == report.artifact_set_sha256
    assert len(bundle.models_config_sha256) == 64
    assert len(bundle.bundle_sha256) == 64


def test_blue_artifact_drift_changes_bundle_identity_under_same_tag() -> None:
    first = build_local_reference_admission_bundle(
        models=_models(),
        report=_report(blue_char="c"),
        blue_model="blue:latest",
    )
    second = build_local_reference_admission_bundle(
        models=_models(),
        report=_report(blue_char="d"),
        blue_model="blue:latest",
    )

    assert first.blue.model == second.blue.model == "blue:latest"
    assert first.blue.artifact_digest != second.blue.artifact_digest
    assert first.bundle_sha256 != second.bundle_sha256


def test_red_runtime_configuration_drift_changes_bundle_identity() -> None:
    first = build_local_reference_admission_bundle(
        models=_models(planner_temperature=0.2),
        report=_report(),
        blue_model="blue:latest",
    )
    second = build_local_reference_admission_bundle(
        models=_models(planner_temperature=0.3),
        report=_report(),
        blue_model="blue:latest",
    )

    assert first.models_config_sha256 != second.models_config_sha256
    assert first.bundle_sha256 != second.bundle_sha256


def test_non_loopback_red_endpoint_is_rejected_even_with_local_artifact() -> None:
    with pytest.raises(ValueError, match="endpoint must use a loopback host"):
        build_local_reference_admission_bundle(
            models=_models(
                planner_endpoint="https://example.invalid/v1/chat/completions"
            ),
            report=_report(),
            blue_model="blue:latest",
        )


def test_red_fallback_is_rejected_for_exact_local_reference_admission() -> None:
    with pytest.raises(ValueError, match="must not declare fallback models"):
        build_local_reference_admission_bundle(
            models=_models(planner_fallback=("some-other-model",)),
            report=_report(),
            blue_model="blue:latest",
        )


def test_missing_selected_blue_artifact_fails_closed() -> None:
    with pytest.raises(ValueError, match="verified local artifact missing for selected Blue"):
        build_local_reference_admission_bundle(
            models=_models(),
            report=_report(),
            blue_model="missing-blue:latest",
        )
