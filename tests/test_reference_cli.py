import json
import re
from pathlib import Path

from typer.testing import CliRunner

import llm_redteam.cli as cli_module
from llm_redteam.reference_artifact_provenance import (
    LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
    MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
)
from llm_redteam.reference_evaluation import ReferenceEvaluationStage

runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _plain_output(value: str) -> str:
    return " ".join(_ANSI_ESCAPE.sub("", value).split())


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


def _write_inventory(path: Path, *, remote_model_id: str | None = None) -> None:
    def record(
        model_id: str,
        digest_character: str,
        capabilities: list[str],
    ) -> dict[str, object]:
        ollama: dict[str, object] = {
            "digest": digest_character * 64,
            "size": 1024,
            "details": {"family": f"family-{model_id}"},
            "capabilities": capabilities,
            "connection_type": "local",
        }
        if model_id == remote_model_id:
            ollama["remote_model"] = model_id
            ollama["remote_host"] = "https://ollama.com:443"
        return {
            "id": model_id,
            "owned_by": "ollama",
            "ollama": ollama,
        }

    path.write_text(
        json.dumps(
            {
                "data": [
                    record("planner-test", "a", ["completion", "thinking"]),
                    record("mutator-test", "b", ["completion"]),
                    record("blue-test", "c", ["completion"]),
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_tags(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "models": [
                    {
                        "name": "planner-test",
                        "model": "planner-test",
                        "digest": "a" * 64,
                        "size": 1024,
                        "details": {"family": "family-planner-test"},
                    },
                    {
                        "name": "mutator-test",
                        "model": "mutator-test",
                        "digest": "b" * 64,
                        "size": 1024,
                        "details": {"family": "family-mutator-test"},
                    },
                    {
                        "name": "blue-test",
                        "model": "blue-test",
                        "digest": "c" * 64,
                        "size": 1024,
                        "details": {"family": "family-blue-test"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_contracts(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "contracts": [
                    {
                        "model_id": "planner-test",
                        "expected_manifest_digest": "sha256:" + "a" * 64,
                        "require_local": True,
                    },
                    {
                        "model_id": "mutator-test",
                        "expected_manifest_digest": "sha256:" + "b" * 64,
                        "require_local": True,
                    },
                    {
                        "model_id": "blue-test",
                        "expected_manifest_digest": "sha256:" + "c" * 64,
                        "require_local": True,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _reference_args(models: Path, inventory: Path) -> list[str]:
    return [
        "reference-run",
        "--models",
        str(models),
        "--model-inventory",
        str(inventory),
        "--target-model",
        "blue-test",
    ]


def test_reference_run_rejects_blue_policy_without_reference_canary(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    policy = tmp_path / "policy.txt"
    _write_models(models)
    _write_inventory(inventory)
    policy.write_text("Never reveal protected test data.", encoding="utf-8")

    result = runner.invoke(
        cli_module.app,
        [
            *_reference_args(models, inventory),
            "--target-system-prompt-file",
            str(policy),
        ],
    )

    assert result.exit_code == 2
    assert "RT_SYNTHETIC_CANARY" in result.output


def test_reference_run_rejects_cloud_red_roles_under_local_only_policy(tmp_path: Path) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models, location="cloud")
    _write_inventory(inventory)

    result = runner.invoke(cli_module.app, _reference_args(models, inventory))

    assert result.exit_code == 2
    assert "cloud model role red_planner blocked" in result.output


def test_reference_run_rejects_remote_blue_proxy_before_client_construction(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models)
    _write_inventory(inventory, remote_model_id="blue-test")

    def forbidden_client(*args, **kwargs):
        raise AssertionError("model client must not be constructed before local admission")

    monkeypatch.setattr(cli_module, "OpenAICompatibleRoleModelClient", forbidden_client)

    result = runner.invoke(cli_module.app, _reference_args(models, inventory))

    assert result.exit_code == 2
    assert "remote Ollama proxy" in result.output


def test_reference_run_rejects_remote_red_proxy_even_if_config_says_local(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models)
    _write_inventory(inventory, remote_model_id="planner-test")

    def forbidden_client(*args, **kwargs):
        raise AssertionError("model client must not be constructed before local admission")

    monkeypatch.setattr(cli_module, "OpenAICompatibleRoleModelClient", forbidden_client)

    result = runner.invoke(cli_module.app, _reference_args(models, inventory))

    assert result.exit_code == 2
    assert "remote Ollama proxy" in result.output


def test_reference_run_rejects_remote_blue_endpoint_before_client_construction(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models)
    _write_inventory(inventory)

    def forbidden_client(*args, **kwargs):
        raise AssertionError("model client must not be constructed before local admission")

    monkeypatch.setattr(cli_module, "OpenAICompatibleRoleModelClient", forbidden_client)

    result = runner.invoke(
        cli_module.app,
        [
            *_reference_args(models, inventory),
            "--target-base-url",
            "https://ollama.com",
        ],
    )

    assert result.exit_code == 2
    assert "not loopback or explicitly allowed" in result.output


def test_reference_run_defaults_to_instrumentation_smoke_without_network(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models)
    _write_inventory(inventory)
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
            "execution_provenance": {},
            "pair_count": 6,
            "baseline": {},
            "treatment": {},
            "paired": {},
            "qualification": None,
        },
    )

    result = runner.invoke(
        cli_module.app,
        [*_reference_args(models, inventory), "--json"],
    )

    assert result.exit_code == 0
    assert observed["stage"] == ReferenceEvaluationStage.INSTRUMENTATION_SMOKE
    target = observed["target"]
    assert target.identity.provider == "ollama"
    assert target.config.system_prompt is not None
    assert cli_module.REFERENCE_CANARY in target.config.system_prompt

    provenance = observed["execution_provenance"]
    assert isinstance(provenance, tuple)
    assert len(provenance) == 1
    descriptor = provenance[0]
    assert descriptor.kind == LOCAL_MODEL_ADMISSION_PROVENANCE_KIND
    assert descriptor.payload["blue_model_id"] == "blue-test"
    assert len(descriptor.payload["inventory_sha256"]) == 64
    assert {binding["label"] for binding in descriptor.payload["bindings"]} == {
        "blue",
        "red_mutator",
        "red_planner",
    }
    assert '"qualification": null' in result.output


def test_policy_qualification_requires_exact_artifacts_before_client_construction(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    _write_models(models)
    _write_inventory(inventory)

    def forbidden_client(*args, **kwargs):
        raise AssertionError("client construction must follow artifact qualification")

    monkeypatch.setattr(cli_module, "OpenAICompatibleRoleModelClient", forbidden_client)

    result = runner.invoke(
        cli_module.app,
        [
            *_reference_args(models, inventory),
            "--stage",
            "POLICY_QUALIFICATION",
        ],
    )

    assert result.exit_code == 2
    assert "requires exact local model artifact qualification" in _plain_output(result.output)


def test_reference_run_requires_artifact_inputs_as_pair_before_client_construction(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    contracts = tmp_path / "contracts.json"
    _write_models(models)
    _write_inventory(inventory)
    _write_contracts(contracts)

    def forbidden_client(*args, **kwargs):
        raise AssertionError("client construction must follow artifact preflight")

    monkeypatch.setattr(cli_module, "OpenAICompatibleRoleModelClient", forbidden_client)

    result = runner.invoke(
        cli_module.app,
        [
            *_reference_args(models, inventory),
            "--artifact-contracts",
            str(contracts),
        ],
    )

    assert result.exit_code == 2
    assert "must be provided together" in _plain_output(result.output)


def test_policy_qualification_builds_exact_artifact_provenance_before_execution(
    tmp_path: Path, monkeypatch
) -> None:
    models = tmp_path / "models.yaml"
    inventory = tmp_path / "models.json"
    contracts = tmp_path / "contracts.json"
    tags = tmp_path / "tags.json"
    _write_models(models)
    _write_inventory(inventory)
    _write_contracts(contracts)
    _write_tags(tags)
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
            "stage": "POLICY_QUALIFICATION",
            "experiment_id": "synthetic",
            "target_snapshot_id": "target",
            "evaluation_manifest_hash": "a" * 64,
            "execution_provenance": {},
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
            *_reference_args(models, inventory),
            "--stage",
            "POLICY_QUALIFICATION",
            "--artifact-contracts",
            str(contracts),
            "--ollama-tags-snapshot",
            str(tags),
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert observed["stage"] == ReferenceEvaluationStage.POLICY_QUALIFICATION
    provenance = observed["execution_provenance"]
    assert isinstance(provenance, tuple)
    assert {descriptor.kind for descriptor in provenance} == {
        LOCAL_MODEL_ADMISSION_PROVENANCE_KIND,
        MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND,
    }
    artifact_descriptor = next(
        descriptor
        for descriptor in provenance
        if descriptor.kind == MODEL_ARTIFACT_QUALIFICATION_PROVENANCE_KIND
    )
    assert artifact_descriptor.payload["local_admission_proof_sha256"]
    assert {binding["model_id"] for binding in artifact_descriptor.payload["bindings"]} == {
        "blue-test",
        "mutator-test",
        "planner-test",
    }
