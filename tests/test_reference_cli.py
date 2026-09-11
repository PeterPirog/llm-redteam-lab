from pathlib import Path

from typer.testing import CliRunner

import llm_redteam.cli as cli_module
from llm_redteam.reference_evaluation import ReferenceEvaluationStage

runner = CliRunner()


def _write_models(path: Path, *, location: str = "local") -> None:
    path.write_text(
        f"""version: 1
policy:
  local_first: true
  allow_cloud_fallback: false
roles:
  red_planner:
    provider: ollama
    model: planner-test
    class: {location}
    capabilities: [text, reasoning]
    endpoint: http://localhost:11434/v1/chat/completions
    temperature: 0.0
    max_output_tokens: 128
  red_mutator:
    provider: ollama
    model: mutator-test
    class: {location}
    capabilities: [text]
    endpoint: http://localhost:11434/v1/chat/completions
    temperature: 0.0
    max_output_tokens: 128
""",
        encoding="utf-8",
    )


def test_reference_run_rejects_blue_policy_without_reference_canary(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    policy = tmp_path / "policy.txt"
    _write_models(models)
    policy.write_text("Never reveal protected test data.", encoding="utf-8")

    result = runner.invoke(
        cli_module.app,
        [
            "reference-run",
            "--models",
            str(models),
            "--target-model",
            "blue-test",
            "--target-system-prompt-file",
            str(policy),
        ],
    )

    assert result.exit_code == 2
    assert "RT_SYNTHETIC_CANARY" in result.output


def test_reference_run_rejects_cloud_red_roles_under_local_only_policy(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    _write_models(models, location="cloud")

    result = runner.invoke(
        cli_module.app,
        [
            "reference-run",
            "--models",
            str(models),
            "--target-model",
            "blue-test",
        ],
    )

    assert result.exit_code == 2
    assert "cloud model role red_planner blocked" in result.output


def test_reference_run_defaults_to_instrumentation_smoke_without_network(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    _write_models(models)
    observed: dict[str, object] = {}

    async def fake_execute_reference_run(**kwargs):
        observed.update(kwargs)
        await kwargs["red_client"].aclose()
        await kwargs["target"].aclose()
        return object()

    monkeypatch.setattr(cli_module, "_execute_reference_run", fake_execute_reference_run)
    monkeypatch.setattr(
        cli_module,
        "_reference_result_payload",
        lambda _: {
            "stage": "INSTRUMENTATION_SMOKE",
            "experiment_id": "synthetic",
            "target_snapshot_id": "target",
            "evaluation_manifest_hash": "a" * 64,
            "pair_count": 6,
            "baseline": {},
            "treatment": {},
            "paired": {},
            "qualification": None,
        },
    )

    result = runner.invoke(
        cli_module.app,
        [
            "reference-run",
            "--models",
            str(models),
            "--target-model",
            "blue-test",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert observed["stage"] == ReferenceEvaluationStage.INSTRUMENTATION_SMOKE
    target = observed["target"]
    assert target.identity.provider == "ollama"
    assert target.config.system_prompt is not None
    assert cli_module.REFERENCE_CANARY in target.config.system_prompt
    assert '"qualification": null' in result.output
