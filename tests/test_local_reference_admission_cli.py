import json
from pathlib import Path

from typer.testing import CliRunner

from llm_redteam.cli import app
from llm_redteam.model_artifact import ModelArtifactIdentity, ModelArtifactObservation
from llm_redteam.offline_ollama_qualification import (
    OfflineOllamaQualificationReport,
    VerifiedOllamaArtifact,
)

runner = CliRunner()


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


def _report() -> OfflineOllamaQualificationReport:
    inventory_sha256 = "f" * 64
    artifacts = []
    for model, char, roles in (
        ("planner:latest", "a", ("red_planner",)),
        ("mutator:latest", "b", ("red_mutator",)),
        ("blue:latest", "c", ("recommended_model_blue",)),
    ):
        artifacts.append(
            VerifiedOllamaArtifact(
                model_id=model,
                roles=roles,
                contract_sha256=char * 64,
                observation=ModelArtifactObservation(
                    identity=_identity(model, char),
                    source_kind="ollama:/api/tags",
                    source_response_sha256=inventory_sha256,
                ),
            )
        )
    return OfflineOllamaQualificationReport(
        source="synthetic-cli-report",
        inventory_sha256=inventory_sha256,
        contracts_sha256="e" * 64,
        artifacts=tuple(sorted(artifacts, key=lambda item: item.model_id)),
    )


def _write_report(path: Path) -> OfflineOllamaQualificationReport:
    report = _report()
    payload = report.model_dump(mode="json")
    payload["artifact_set_sha256"] = report.artifact_set_sha256
    payload["report_sha256"] = report.report_sha256
    path.write_text(json.dumps(payload), encoding="utf-8")
    return report


def _write_models(path: Path, *, planner_endpoint: str) -> None:
    path.write_text(
        """version: 1
policy:
  local_first: true
  allow_cloud_fallback: false
roles:
  red_planner:
    provider: ollama
    model: planner:latest
    class: local
    capabilities: [text, reasoning]
    endpoint: {planner_endpoint}
    temperature: 0.2
    max_output_tokens: 128
    fallback: []
  red_mutator:
    provider: ollama
    model: mutator:latest
    class: local
    capabilities: [text]
    endpoint: http://localhost:11434/v1/chat/completions
    temperature: 0.0
    max_output_tokens: 96
    fallback: []
blue:
  source: campaign
""".format(planner_endpoint=planner_endpoint),
        encoding="utf-8",
    )


def test_prepare_local_reference_emits_hash_bound_json_to_stdout(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    report_path = tmp_path / "qualification-report.json"
    _write_models(
        models,
        planner_endpoint="http://localhost:11434/v1/chat/completions",
    )
    report = _write_report(report_path)

    result = runner.invoke(
        app,
        [
            "prepare-local-reference",
            "--models",
            str(models),
            "--qualification-report",
            str(report_path),
            "--blue-model",
            "blue:latest",
            "--expected-report-sha256",
            report.report_sha256,
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["qualification_report_sha256"] == report.report_sha256
    assert payload["blue"]["model"] == "blue:latest"
    assert payload["blue"]["local_artifact"] is True
    assert [item["participant"] for item in payload["red_roles"]] == [
        "red_planner",
        "red_mutator",
    ]
    assert len(payload["bundle_sha256"]) == 64


def test_prepare_local_reference_writes_bundle_and_summary(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    report_path = tmp_path / "qualification-report.json"
    output = tmp_path / "reference-admission.json"
    _write_models(
        models,
        planner_endpoint="http://127.0.0.1:11434/v1/chat/completions",
    )
    _write_report(report_path)

    result = runner.invoke(
        app,
        [
            "prepare-local-reference",
            "--models",
            str(models),
            "--qualification-report",
            str(report_path),
            "--blue-model",
            "blue:latest",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["bundle_sha256"] in result.stdout
    assert "PREPARED" in result.stdout
    assert payload["blue"]["artifact_digest"] == "sha256:" + "c" * 64


def test_wrong_pinned_report_hash_fails_without_partial_bundle(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    report_path = tmp_path / "qualification-report.json"
    output = tmp_path / "reference-admission.json"
    _write_models(
        models,
        planner_endpoint="http://localhost:11434/v1/chat/completions",
    )
    _write_report(report_path)

    result = runner.invoke(
        app,
        [
            "prepare-local-reference",
            "--models",
            str(models),
            "--qualification-report",
            str(report_path),
            "--blue-model",
            "blue:latest",
            "--expected-report-sha256",
            "0" * 64,
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert "does not match pinned report hash" in result.output
    assert not output.exists()


def test_remote_red_endpoint_fails_without_partial_bundle(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    report_path = tmp_path / "qualification-report.json"
    output = tmp_path / "reference-admission.json"
    _write_models(
        models,
        planner_endpoint="https://example.invalid/v1/chat/completions",
    )
    _write_report(report_path)

    result = runner.invoke(
        app,
        [
            "prepare-local-reference",
            "--models",
            str(models),
            "--qualification-report",
            str(report_path),
            "--blue-model",
            "blue:latest",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert "endpoint must use a loopback host" in result.output
    assert not output.exists()
