import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import llm_redteam.cli as cli_module
from llm_redteam.cli import app
from llm_redteam.hal_smoke_operator import (
    HalSmokeOperatorInputs,
    build_live_hal_smoke_runtime,
    prepare_hal_smoke_operator,
)
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.ollama_model_staging import OllamaModelStagingSupervisor
from llm_redteam.storage.repository import ExperimentRepository

runner = CliRunner()

_PLANNER = "gpt-oss:latest"
_MUTATOR = "mistral:7b-instruct"
_BLUE = "ornith-1.5:9b"
_MANIFEST_PATH = "registry.ollama.ai/library/ornith-1.5/9b"


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _operator_inputs(tmp_path: Path) -> HalSmokeOperatorInputs:
    source = tmp_path / "ollama-source"
    manifests = source / "manifests"
    blobs = source / "blobs"
    manifests.mkdir(parents=True)
    blobs.mkdir(parents=True)

    config_blob = b"synthetic-config"
    layer_blob = b"synthetic-layer"
    config_digest = _sha256(config_blob)
    layer_digest = _sha256(layer_blob)
    (blobs / f"sha256-{config_digest}").write_bytes(config_blob)
    (blobs / f"sha256-{layer_digest}").write_bytes(layer_blob)

    manifest_payload = {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.ollama.image.model",
            "digest": f"sha256:{config_digest}",
            "size": len(config_blob),
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": f"sha256:{layer_digest}",
                "size": len(layer_blob),
            }
        ],
    }
    manifest_bytes = json.dumps(
        manifest_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest_file = manifests / Path(*_MANIFEST_PATH.split("/"))
    manifest_file.parent.mkdir(parents=True)
    manifest_file.write_bytes(manifest_bytes)
    blue_digest = _sha256(manifest_bytes)

    digests = {
        _PLANNER: "a" * 64,
        _MUTATOR: "b" * 64,
        _BLUE: blue_digest,
    }
    sizes = {_PLANNER: 1001, _MUTATOR: 1002, _BLUE: 1003}
    capabilities = {
        _PLANNER: ["completion", "thinking"],
        _MUTATOR: ["completion"],
        _BLUE: ["completion"],
    }
    families = {
        _PLANNER: "gptoss",
        _MUTATOR: "mistral",
        _BLUE: "qwen35",
    }

    inventory = _write_json(
        tmp_path / "models.json",
        {
            "data": [
                {
                    "id": model_id,
                    "owned_by": "ollama",
                    "ollama": {
                        "digest": digest,
                        "size": sizes[model_id],
                        "details": {
                            "family": families[model_id],
                            "parameter_size": "synthetic",
                            "quantization_level": "Q4",
                            "context_length": 131072,
                        },
                        "capabilities": capabilities[model_id],
                    },
                }
                for model_id, digest in digests.items()
            ]
        },
    )
    tags = _write_json(
        tmp_path / "tags.json",
        {
            "models": [
                {
                    "name": model_id,
                    "digest": f"sha256:{digest}",
                    "size": sizes[model_id],
                    "details": {
                        "format": "gguf",
                        "family": families[model_id],
                        "parameter_size": "synthetic",
                        "quantization_level": "Q4",
                    },
                }
                for model_id, digest in digests.items()
            ]
        },
    )
    contracts = _write_json(
        tmp_path / "contracts.json",
        {
            "version": 1,
            "contracts": [
                {
                    "model_id": model_id,
                    "expected_manifest_digest": f"sha256:{digest}",
                    "require_local": True,
                }
                for model_id, digest in digests.items()
            ],
        },
    )

    blue_contract = OllamaArtifactContract(
        model_id=_BLUE,
        expected_manifest_digest=f"sha256:{blue_digest}",
        require_local=True,
    )
    prestage = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "prestage",
    ).stage(
        contract=blue_contract,
        manifest_relative_path=_MANIFEST_PATH,
    )
    pins = _write_json(
        tmp_path / "pins.json",
        {
            "version": 1,
            "staged_blue_store_identity": prestage.identity.model_dump(mode="json"),
            "opencode_application_version": "1.2.3-test",
            "opencode_image_ref": "synthetic/opencode@sha256:" + "c" * 64,
            "opencode_image_id": "sha256:" + "d" * 64,
            "ollama_peer_image_ref": "synthetic/ollama-probe@sha256:" + "e" * 64,
            "ollama_peer_image_id": "sha256:" + "f" * 64,
        },
    )

    template = tmp_path / "workspace-template"
    template.mkdir()
    (template / "README.md").write_text("synthetic smoke workspace\n", encoding="utf-8")

    return HalSmokeOperatorInputs(
        models_config=Path("config/models.hal-smoke.example.yaml"),
        model_inventory=inventory,
        artifact_contracts=contracts,
        ollama_tags_snapshot=tags,
        runtime_pins=pins,
        source_ollama_models_root=source,
        staging_root=tmp_path / "operator-stage",
        blue_manifest_relative_path=_MANIFEST_PATH,
        workspace_template_root=template,
        workspace_sandbox_root=tmp_path / "sandboxes",
        budget_config=Path("config/budgets.yaml"),
        blue_model_id=_BLUE,
    )


class NoCallDockerRunner:
    def __init__(self) -> None:
        self.calls = []

    def run(self, argv, *, timeout_seconds):
        self.calls.append((argv, timeout_seconds))
        raise AssertionError("Docker must not run while wiring operator runtime")


def test_operator_prepare_builds_exact_stage_without_docker_or_inference(
    tmp_path: Path,
) -> None:
    inputs = _operator_inputs(tmp_path)

    prepared = prepare_hal_smoke_operator(inputs)

    assert prepared.composition.static_plan.blue_model_id == _BLUE
    assert (
        prepared.staged_store.identity.identity_sha256
        == prepared.composition.model_peer.staged_store_identity_sha256
    )
    assert prepared.workspace_supervisor.profile.template_sha256
    assert prepared.blue_artifact_contract.model_id == _BLUE


def test_runtime_wiring_requires_opencode_secret_before_docker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepared = prepare_hal_smoke_operator(_operator_inputs(tmp_path))
    fake_docker = NoCallDockerRunner()
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")

    monkeypatch.delenv("OPENCODE_SERVER_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="OPENCODE_SERVER_PASSWORD"):
        build_live_hal_smoke_runtime(
            prepared=prepared,
            repository=repository,
            network_name="llmrt-hal-smoke-test",
            docker_runner=fake_docker,
        )
    assert fake_docker.calls == []

    monkeypatch.setenv("OPENCODE_SERVER_PASSWORD", "synthetic-test-secret")
    runtime = build_live_hal_smoke_runtime(
        prepared=prepared,
        repository=repository,
        network_name="llmrt-hal-smoke-test",
        docker_runner=fake_docker,
    )
    assert fake_docker.calls == []
    asyncio.run(runtime.aclose())


def test_hal_smoke_run_cli_passes_only_explicit_operator_inputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured = {}

    async def fake_run_live_hal_smoke(**kwargs):
        captured.update(kwargs)
        campaign = SimpleNamespace(
            campaign_id="campaign-cli-smoke",
            status=SimpleNamespace(value="completed"),
            target_snapshot_id="1" * 64,
            measurement_hash="2" * 64,
            executions=(
                SimpleNamespace(outcome=SimpleNamespace(value="model_compromise")),
            ),
        )
        run = SimpleNamespace(
            campaign=campaign,
            execution_provenance_hashes=(("local_model_admission_v1", "3" * 64),),
            blue_infrastructure=SimpleNamespace(proof_sha256="4" * 64),
            blue_release=SimpleNamespace(
                teardown_proof_sha256="5" * 64,
                cleanup_complete=True,
            ),
        )
        return SimpleNamespace(
            run=run,
            composition_sha256="6" * 64,
            staged_store_identity_sha256="7" * 64,
        )

    monkeypatch.setattr(cli_module, "run_live_hal_smoke", fake_run_live_hal_smoke)

    args = [
        "hal-smoke-run",
        "--model-inventory",
        str(tmp_path / "models.json"),
        "--artifact-contracts",
        str(tmp_path / "contracts.json"),
        "--ollama-tags-snapshot",
        str(tmp_path / "tags.json"),
        "--runtime-pins",
        str(tmp_path / "pins.json"),
        "--source-ollama-models-root",
        str(tmp_path / "ollama"),
        "--staging-root",
        str(tmp_path / "staging"),
        "--blue-manifest-path",
        _MANIFEST_PATH,
        "--workspace-template-root",
        str(tmp_path / "template"),
        "--workspace-sandbox-root",
        str(tmp_path / "sandboxes"),
        "--campaign-id",
        "campaign-cli-smoke",
        "--json",
    ]
    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["campaign_id"] == "campaign-cli-smoke"
    assert payload["cleanup_complete"] is True
    assert payload["outcomes"] == ["model_compromise"]
    assert captured["campaign_id"] == "campaign-cli-smoke"
    inputs = captured["inputs"]
    assert inputs.blue_manifest_relative_path == _MANIFEST_PATH
    assert inputs.source_ollama_models_root == tmp_path / "ollama"
